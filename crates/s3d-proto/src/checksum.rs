use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};

use base64::Engine as _;
use bytes::Bytes;
use crc32fast::Hasher as Crc32Hasher;
use md5::{Digest as _, Md5};
use s3d_types::{
    BodyStreamError, ChecksumAlgorithm, ChecksumState, ChecksumType, S3Error, S3ErrorCode,
    StoreResult, VerifiedDigests,
};
use sha1::Sha1;
use sha2::Sha256;

pub enum ActiveHasher {
    Crc32(Crc32Hasher),
    Crc32c(u32),
    Crc64Nvme(crc64fast_nvme::Digest),
    Sha1(Sha1),
    Sha256(Sha256),
}

impl ActiveHasher {
    pub fn new(alg: ChecksumAlgorithm) -> Self {
        match alg {
            ChecksumAlgorithm::Crc32 => Self::Crc32(Crc32Hasher::new()),
            ChecksumAlgorithm::Crc32c => Self::Crc32c(0),
            ChecksumAlgorithm::Crc64Nvme => Self::Crc64Nvme(crc64fast_nvme::Digest::new()),
            ChecksumAlgorithm::Sha1 => Self::Sha1(Sha1::new()),
            ChecksumAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(data),
            Self::Crc32c(c) => *c = crc32c::crc32c_append(*c, data),
            Self::Crc64Nvme(d) => d.write(data),
            Self::Sha1(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
        }
    }

    pub fn finalize_b64(self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD;
        match self {
            Self::Crc32(h) => b64.encode(h.finalize().to_be_bytes()),
            Self::Crc32c(c) => b64.encode(c.to_be_bytes()),
            Self::Crc64Nvme(d) => b64.encode(d.sum64().to_be_bytes()),
            Self::Sha1(h) => b64.encode(h.finalize()),
            Self::Sha256(h) => b64.encode(h.finalize()),
        }
    }
}

/// Validate and parse `Content-MD5` header (base64 of 16 bytes, `InvalidDigest` on bad format).
pub fn parse_content_md5_header(raw: &str) -> StoreResult<[u8; 16]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidDigest, "The Content-MD5 you specified was invalid."))?;
    bytes
        .try_into()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidDigest, "The Content-MD5 you specified was invalid."))
}

/// Validate base64 format & expected byte length of `x-amz-checksum-<alg>`.
pub fn validate_checksum_b64_format(alg: ChecksumAlgorithm, b64_val: &str) -> StoreResult<()> {
    let expected_len = match alg {
        ChecksumAlgorithm::Crc32 | ChecksumAlgorithm::Crc32c => 4,
        ChecksumAlgorithm::Crc64Nvme => 8,
        ChecksumAlgorithm::Sha1 => 20,
        ChecksumAlgorithm::Sha256 => 32,
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64_val.trim())
        .map_err(|_| {
            S3Error::new(
                S3ErrorCode::BadDigest,
                format!("Value for {} header is invalid.", alg.header_name()),
            )
        })?;
    if decoded.len() != expected_len {
        return Err(S3Error::new(
            S3ErrorCode::BadDigest,
            format!("Value for {} header is invalid.", alg.header_name()),
        ));
    }
    Ok(())
}

/// Threshold (`256 KiB` in production; `1 KiB` under Miri for fast UB/leak checking) above which
/// RFC 1321 `Md5` (`ETag`) hashing is pipelined onto a bounded background worker (`<= 1 MiB` queued)
/// so single-stream multi-GiB `PutObject` / `UploadPart` overlaps serial 64-round MD5 with
/// `CRC64NVME`, `CRC32C`, TCP reads, and `pwrite`.
const MD5_WORKER_THRESHOLD_BYTES: u64 = if cfg!(miri) { 1024 } else { 256 * 1024 };

struct Md5Worker {
    tx: Option<SyncSender<Bytes>>,
    handle: Option<JoinHandle<Md5>>,
}

impl Drop for Md5Worker {
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

enum Md5Accumulator {
    Inline(Md5),
    Worker(Md5Worker),
    Taken,
}

impl Md5Accumulator {
    fn new() -> Self {
        Self::Inline(Md5::new())
    }

    fn feed_bytes(&mut self, total_bytes: u64, chunk: &Bytes) {
        match self {
            Self::Inline(h) => {
                if total_bytes <= MD5_WORKER_THRESHOLD_BYTES {
                    h.update(chunk);
                } else {
                    let Self::Inline(mut md5) = std::mem::replace(self, Self::Taken) else {
                        unreachable!();
                    };
                    let (tx, rx) = mpsc::sync_channel::<Bytes>(4);
                    let first = chunk.clone();
                    let mut worker_md5 = md5.clone();
                    match thread::Builder::new().name("s3d-md5".into()).spawn(move || {
                        worker_md5.update(&first);
                        while let Ok(buf) = rx.recv() {
                            worker_md5.update(&buf);
                        }
                        worker_md5
                    }) {
                        Ok(handle) => {
                            *self = Self::Worker(Md5Worker {
                                tx: Some(tx),
                                handle: Some(handle),
                            });
                        }
                        Err(_) => {
                            md5.update(chunk);
                            *self = Self::Inline(md5);
                        }
                    }
                }
            }
            Self::Worker(Md5Worker { tx: Some(tx), .. }) => {
                let _ = tx.send(chunk.clone());
            }
            Self::Worker(Md5Worker { tx: None, .. }) | Self::Taken => unreachable!(),
        }
    }

    fn feed_slice(&mut self, total_bytes: u64, chunk: &[u8]) {
        if let Self::Inline(h) = self
            && total_bytes <= MD5_WORKER_THRESHOLD_BYTES
        {
            h.update(chunk);
            return;
        }
        self.feed_bytes(total_bytes, &Bytes::copy_from_slice(chunk));
    }

    fn finalize(self) -> [u8; 16] {
        match self {
            Self::Inline(h) => h.finalize().into(),
            Self::Worker(mut w) => {
                drop(w.tx.take());
                w.handle
                    .take()
                    .expect("md5 worker handle missing")
                    .join()
                    .expect("s3d-md5 background worker panicked")
                    .finalize()
                    .into()
            }
            Self::Taken => unreachable!(),
        }
    }
}

/// Streaming digest accumulator verifying `Content-MD5`, `x-amz-content-sha256`, and `x-amz-checksum-*`.
pub struct StreamingDigestVerifier {
    total_bytes: u64,
    expected_len: Option<u64>,
    md5: Md5Accumulator,
    expected_md5: Option<[u8; 16]>,
    sha256: Option<(Sha256, [u8; 32])>,
    checksum_alg: ChecksumAlgorithm,
    checksum_hasher: ActiveHasher,
    expected_checksum_b64: Option<String>,
    client_requested_checksum: bool,
}

impl StreamingDigestVerifier {
    pub fn new(
        expected_len: Option<u64>,
        expected_md5: Option<[u8; 16]>,
        expected_sha256: Option<[u8; 32]>,
        checksum_spec: Option<(ChecksumAlgorithm, Option<String>)>,
    ) -> Self {
        let (alg, expected_b64, client_req) = match checksum_spec {
            Some((a, exp)) => (a, exp, true),
            None => (ChecksumAlgorithm::Crc64Nvme, None, false),
        };
        Self {
            total_bytes: 0,
            expected_len,
            md5: Md5Accumulator::new(),
            expected_md5,
            sha256: expected_sha256.map(|exp| (Sha256::new(), exp)),
            checksum_alg: alg,
            checksum_hasher: ActiveHasher::new(alg),
            expected_checksum_b64: expected_b64,
            client_requested_checksum: client_req,
        }
    }

    pub fn set_trailer_expected_checksum(&mut self, b64_val: String) {
        self.expected_checksum_b64 = Some(b64_val);
        self.client_requested_checksum = true;
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.total_bytes += chunk.len() as u64;
        self.md5.feed_slice(self.total_bytes, chunk);
        if let Some((h, _)) = &mut self.sha256 {
            h.update(chunk);
        }
        self.checksum_hasher.update(chunk);
    }

    /// Zero-copy `Bytes` fast path avoiding slice cloning when offloading large streams to `Md5Accumulator`.
    pub fn update_bytes(&mut self, chunk: &Bytes) {
        self.total_bytes += chunk.len() as u64;
        self.md5.feed_bytes(self.total_bytes, chunk);
        if let Some((h, _)) = &mut self.sha256 {
            h.update(chunk);
        }
        self.checksum_hasher.update(chunk);
    }

    pub fn finish(self) -> Result<VerifiedDigests, BodyStreamError> {
        if let Some(exp_len) = self.expected_len
            && self.total_bytes != exp_len {
                return Err(BodyStreamError::IncompleteBody);
            }
        if let Some((sha, exp_sha)) = self.sha256 {
            let actual_sha: [u8; 32] = sha.finalize().into();
            if actual_sha != exp_sha {
                return Err(BodyStreamError::Sha256Mismatch);
            }
        }
        let actual_md5: [u8; 16] = self.md5.finalize();
        if let Some(exp_md5) = self.expected_md5
            && actual_md5 != exp_md5 {
                return Err(BodyStreamError::BadDigest);
            }
        let actual_csum_b64 = self.checksum_hasher.finalize_b64();
        if let Some(exp_b64) = &self.expected_checksum_b64
            && exp_b64.trim() != actual_csum_b64 {
                return Err(BodyStreamError::BadDigest);
            }
        Ok(VerifiedDigests {
            total_bytes: self.total_bytes,
            md5: actual_md5,
            checksum: ChecksumState {
                algorithm: self.checksum_alg,
                checksum_type: ChecksumType::FullObject,
                value_b64: actual_csum_b64,
                client_requested: self.client_requested_checksum,
            },
        })
    }
}

// ---- GF(2) Reflected CRC Combine Formula (PR-25: O(w log N) without re-reading part data!) ----

fn gf2_matrix_times_32(mat: &[u32; 32], mut vec: u32) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while vec != 0 {
        if (vec & 1) != 0 {
            sum ^= mat[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

fn gf2_matrix_square_32(src: &[u32; 32]) -> [u32; 32] {
    let mut out = [0u32; 32];
    for i in 0..32 {
        out[i] = gf2_matrix_times_32(src, src[i]);
    }
    out
}

fn combine_reflected_crc32_poly(poly: u32, mut crc1: u32, crc2: u32, mut len2: u64) -> u32 {
    if len2 == 0 {
        return crc1;
    }
    let mut odd = [0u32; 32];
    odd[0] = poly;
    for (i, slot) in odd.iter_mut().enumerate().skip(1) {
        *slot = 1u32 << (i - 1);
    }
    let mut even = gf2_matrix_square_32(&odd);
    odd = gf2_matrix_square_32(&even); // 4-bit shift
    even = gf2_matrix_square_32(&odd); // 8-bit (1-byte) shift!

    // Now `even` shifts by 1 byte; square repeatedly to apply `len2` zero bytes
    let mut op = even;
    while len2 != 0 {
        if (len2 & 1) != 0 {
            crc1 = gf2_matrix_times_32(&op, crc1);
        }
        len2 >>= 1;
        if len2 != 0 {
            op = gf2_matrix_square_32(&op);
        }
    }
    crc1 ^ crc2
}

pub fn combine_crc32(crc1: u32, crc2: u32, len2: u64) -> u32 {
    combine_reflected_crc32_poly(0xEDB8_8320, crc1, crc2, len2)
}

pub fn combine_crc32c(crc1: u32, crc2: u32, len2: u64) -> u32 {
    combine_reflected_crc32_poly(0x82F6_3B78, crc1, crc2, len2)
}

fn gf2_matrix_times_64(mat: &[u64; 64], mut vec: u64) -> u64 {
    let mut sum = 0u64;
    let mut i = 0;
    while vec != 0 {
        if (vec & 1) != 0 {
            sum ^= mat[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

fn gf2_matrix_square_64(src: &[u64; 64]) -> [u64; 64] {
    let mut out = [0u64; 64];
    for i in 0..64 {
        out[i] = gf2_matrix_times_64(src, src[i]);
    }
    out
}

pub fn combine_crc64_nvme(mut crc1: u64, crc2: u64, mut len2: u64) -> u64 {
    if len2 == 0 {
        return crc1;
    }
    let poly: u64 = 0x9A6C_9329_AC4B_C9B5;
    let mut odd = [0u64; 64];
    odd[0] = poly;
    for (i, slot) in odd.iter_mut().enumerate().skip(1) {
        *slot = 1u64 << (i - 1);
    }
    let mut even = gf2_matrix_square_64(&odd);
    odd = gf2_matrix_square_64(&even);
    even = gf2_matrix_square_64(&odd); // 1-byte shift

    let mut op = even;
    while len2 != 0 {
        if (len2 & 1) != 0 {
            crc1 = gf2_matrix_times_64(&op, crc1);
        }
        len2 >>= 1;
        if len2 != 0 {
            op = gf2_matrix_square_64(&op);
        }
    }
    crc1 ^ crc2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf2_crc_combine_matches_full_stream_pr25() {
        let part1 = b"Hello multipart world! ";
        let part2 = &[0x5Au8; 13_579];
        let mut combined = Vec::from(&part1[..]);
        combined.extend_from_slice(part2);

        // CRC32
        let mut h1 = Crc32Hasher::new();
        h1.update(part1);
        let mut h2 = Crc32Hasher::new();
        h2.update(part2);
        let mut hall = Crc32Hasher::new();
        hall.update(&combined);
        assert_eq!(
            combine_crc32(h1.finalize(), h2.finalize(), part2.len() as u64),
            hall.finalize()
        );

        // CRC32C
        assert_eq!(
            combine_crc32c(
                crc32c::crc32c(part1),
                crc32c::crc32c(part2),
                part2.len() as u64
            ),
            crc32c::crc32c(&combined)
        );

        // CRC64NVME
        let crc64 = |b: &[u8]| {
            let mut d = crc64fast_nvme::Digest::new();
            d.write(b);
            d.sum64()
        };
        assert_eq!(
            combine_crc64_nvme(crc64(part1), crc64(part2), part2.len() as u64),
            crc64(&combined)
        );
    }

    #[test]
    fn pipelined_md5_worker_matches_inline_and_handles_early_drop() {
        let total_len = if cfg!(miri) { 4096 } else { 1024 * 1024 };
        let step_a = if cfg!(miri) { 512 } else { 64 * 1024 };
        let step_b = if cfg!(miri) { 700 } else { 100_000 };
        let step_c = if cfg!(miri) { 1024 } else { 128 * 1024 };

        let mut full = Vec::with_capacity(total_len);
        for i in 0..total_len {
            full.push((i as u8).wrapping_mul(31).wrapping_add(7));
        }
        let expected_md5: [u8; 16] = Md5::digest(&full).into();

        // 1. Feed above worker threshold via `update_bytes`
        let mut v_bytes =
            StreamingDigestVerifier::new(Some(full.len() as u64), Some(expected_md5), None, None);
        for chunk in full.chunks(step_a) {
            v_bytes.update_bytes(&Bytes::copy_from_slice(chunk));
        }
        let d1 = v_bytes.finish().unwrap();
        assert_eq!(d1.md5, expected_md5);
        assert_eq!(d1.total_bytes, full.len() as u64);

        // 2. Feed above worker threshold via `update` slice path
        let mut v_slice =
            StreamingDigestVerifier::new(Some(full.len() as u64), Some(expected_md5), None, None);
        for chunk in full.chunks(step_b) {
            v_slice.update(chunk);
        }
        let d2 = v_slice.finish().unwrap();
        assert_eq!(d2.md5, expected_md5);
        assert_eq!(d2.checksum.value_b64, d1.checksum.value_b64);

        // 3. Early drop after spawning worker (simulates aborted stream) reaps thread cleanly
        let mut v_abort = StreamingDigestVerifier::new(None, None, None, None);
        for chunk in full.chunks(step_c).take(4) {
            v_abort.update_bytes(&Bytes::copy_from_slice(chunk));
        }
        drop(v_abort);
    }
}
