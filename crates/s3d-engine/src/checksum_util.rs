use base64::Engine as _;
use crc32fast::Hasher as Crc32Hasher;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use s3d_types::{ChecksumAlgorithm, S3Error, S3ErrorCode, StoreResult};

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

pub fn compute_composite_checksum_b64(
    alg: ChecksumAlgorithm,
    part_b64s: &[String],
) -> StoreResult<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut raw_concat = Vec::with_capacity(part_b64s.len() * 32);
    for p in part_b64s {
        let decoded = b64
            .decode(p.trim())
            .map_err(|_| S3Error::new(S3ErrorCode::BadDigest, "Invalid part checksum encoding"))?;
        raw_concat.extend_from_slice(&decoded);
    }
    let mut hasher = ActiveHasher::new(alg);
    hasher.update(&raw_concat);
    Ok(format!("{}-{}", hasher.finalize_b64(), part_b64s.len()))
}

pub fn decode_u32_be_b64(b64_str: &str) -> StoreResult<u32> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64_str.trim())
        .map_err(|_| S3Error::new(S3ErrorCode::BadDigest, "Invalid CRC32 base64"))?;
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| S3Error::new(S3ErrorCode::BadDigest, "Invalid CRC32 byte length"))?;
    Ok(u32::from_be_bytes(arr))
}

pub fn encode_u32_be_b64(val: u32) -> String {
    base64::engine::general_purpose::STANDARD.encode(val.to_be_bytes())
}

pub fn encode_u64_be_b64(val: u64) -> String {
    base64::engine::general_purpose::STANDARD.encode(val.to_be_bytes())
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
    for i in 1..32 {
        odd[i] = 1u32 << (i - 1);
    }
    let mut even = gf2_matrix_square_32(&odd);
    odd = gf2_matrix_square_32(&even);
    even = gf2_matrix_square_32(&odd); // 1-byte shift

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
    for i in 1..64 {
        odd[i] = 1u64 << (i - 1);
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
