//! Streaming `aws-chunked` decoder (`PR-12`, `PR-27`) + raw body adapter implementing `VerifiedBodyStream`.

use bytes::{Buf, BytesMut};
use s3d_types::{BodyStreamError, ChecksumAlgorithm};

use crate::checksum::StreamingDigestVerifier;
use crate::sigv4::{compute_chunk_signature, compute_trailer_signature, constant_time_eq_str};

pub const MIN_NON_FINAL_AWS_CHUNK: usize = 8 * 1024; // 8 KiB (`PR-12`)

enum ChunkDecodeState {
    ReadHeader,
    ReadPayload { remaining: usize, chunk_buf: BytesMut },
    ReadPayloadCrLf,
    ReadTrailers { lines: Vec<String> },
    Done,
}

/// Incremental `aws-chunked` state machine supporting:
/// - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
/// - `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
/// - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`
pub struct AwsChunkedDecoder {
    signed: Option<SignedChunkCtx>,
    expected_trailer_name: Option<String>,
    expected_decoded_len: u64,
    decoded_so_far: u64,
    prev_chunk_len: Option<usize>,
    raw_buf: BytesMut,
    state: ChunkDecodeState,
    parsed_trailer_checksum_b64: Option<String>,
}

struct SignedChunkCtx {
    signing_key: [u8; 32],
    amz_date: String,
    scope: String,
    prev_sig: String,
    pending_sig: String,
}

impl AwsChunkedDecoder {
    pub fn new_signed(
        signing_key: [u8; 32],
        amz_date: String,
        scope: String,
        seed_signature: String,
        expected_decoded_len: u64,
        expected_trailer_name: Option<String>,
    ) -> Self {
        Self {
            signed: Some(SignedChunkCtx {
                signing_key,
                amz_date,
                scope,
                prev_sig: seed_signature,
                pending_sig: String::new(),
            }),
            expected_trailer_name,
            expected_decoded_len,
            decoded_so_far: 0,
            prev_chunk_len: None,
            raw_buf: BytesMut::with_capacity(64 * 1024),
            state: ChunkDecodeState::ReadHeader,
            parsed_trailer_checksum_b64: None,
        }
    }

    pub fn new_unsigned_trailer(expected_decoded_len: u64, trailer_name: String) -> Self {
        Self {
            signed: None,
            expected_trailer_name: Some(trailer_name),
            expected_decoded_len,
            decoded_so_far: 0,
            prev_chunk_len: None,
            raw_buf: BytesMut::with_capacity(64 * 1024),
            state: ChunkDecodeState::ReadHeader,
            parsed_trailer_checksum_b64: None,
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, ChunkDecodeState::Done)
    }

    pub fn trailer_checksum_b64(&self) -> Option<&str> {
        self.parsed_trailer_checksum_b64.as_deref()
    }

    pub fn push_wire_bytes(
        &mut self,
        wire: &[u8],
        verifier: &mut StreamingDigestVerifier,
        out_decoded: &mut BytesMut,
    ) -> Result<(), BodyStreamError> {
        self.raw_buf.extend_from_slice(wire);
        loop {
            match &mut self.state {
                ChunkDecodeState::ReadHeader => {
                    let Some(crlf_pos) = find_crlf(&self.raw_buf) else {
                        if self.raw_buf.len() > 4096 {
                            return Err(BodyStreamError::InvalidChunkedEncoding(
                                "aws-chunked header line too long".into(),
                            ));
                        }
                        break;
                    };
                    let line_bytes = self.raw_buf.split_to(crlf_pos);
                    self.raw_buf.advance(2); // consume \r\n
                    let line = std::str::from_utf8(&line_bytes).map_err(|_| {
                        BodyStreamError::InvalidChunkedEncoding("non-UTF8 chunk header".into())
                    })?;

                    let (hex_part, ext_part) = match line.split_once(';') {
                        Some((h, ext)) => (h.trim(), Some(ext.trim())),
                        None => (line.trim(), None),
                    };
                    let chunk_len = usize::from_str_radix(hex_part, 16).map_err(|_| {
                        BodyStreamError::InvalidChunkedEncoding("invalid chunk hex size".into())
                    })?;

                    // [PR-12] Non-final chunks must be >= 8 KiB!
                    if chunk_len > 0 {
                        if let Some(prev) = self.prev_chunk_len
                            && prev < MIN_NON_FINAL_AWS_CHUNK {
                                return Err(BodyStreamError::InvalidChunkedEncoding(
                                    "non-final aws-chunked block smaller than 8 KiB".into(),
                                ));
                            }
                        self.prev_chunk_len = Some(chunk_len);
                    }

                    if let Some(sctx) = &mut self.signed {
                        let sig = ext_part
                            .and_then(|e| e.strip_prefix("chunk-signature="))
                            .ok_or_else(|| {
                                BodyStreamError::InvalidChunkedEncoding(
                                    "missing chunk-signature".into(),
                                )
                            })?;
                        sctx.pending_sig = sig.trim().to_ascii_lowercase();
                    }

                    if chunk_len == 0 {
                        if self.decoded_so_far != self.expected_decoded_len {
                            return Err(BodyStreamError::IncompleteBody);
                        }
                        if let Some(sctx) = &mut self.signed {
                            let calc = compute_chunk_signature(
                                &sctx.signing_key,
                                &sctx.amz_date,
                                &sctx.scope,
                                &sctx.prev_sig,
                                b"",
                            );
                            if !constant_time_eq_str(&calc, &sctx.pending_sig) {
                                return Err(BodyStreamError::InvalidChunkedEncoding(
                                    "final chunk signature mismatch".into(),
                                ));
                            }
                            sctx.prev_sig = calc;
                        }
                        self.state = ChunkDecodeState::ReadTrailers { lines: Vec::new() };
                    } else {
                        if self.decoded_so_far + (chunk_len as u64) > self.expected_decoded_len {
                            return Err(BodyStreamError::InvalidChunkedEncoding(
                                "decoded bytes exceed x-amz-decoded-content-length".into(),
                            ));
                        }
                        let cap = if self.signed.is_some() { chunk_len } else { 0 };
                        self.state = ChunkDecodeState::ReadPayload {
                            remaining: chunk_len,
                            chunk_buf: BytesMut::with_capacity(cap),
                        };
                    }
                }
                ChunkDecodeState::ReadPayload {
                    remaining,
                    chunk_buf,
                } => {
                    if self.raw_buf.is_empty() {
                        break;
                    }
                    let take = (*remaining).min(self.raw_buf.len());
                    let piece = self.raw_buf.split_to(take);
                    *remaining -= take;
                    self.decoded_so_far += take as u64;

                    if let Some(sctx) = &mut self.signed {
                        // Buffer chunk until chunk-signature is verified before releasing downstream!
                        chunk_buf.extend_from_slice(&piece);
                        if *remaining == 0 {
                            let full_chunk = chunk_buf.split().freeze();
                            let calc = compute_chunk_signature(
                                &sctx.signing_key,
                                &sctx.amz_date,
                                &sctx.scope,
                                &sctx.prev_sig,
                                &full_chunk,
                            );
                            if !constant_time_eq_str(&calc, &sctx.pending_sig) {
                                return Err(BodyStreamError::InvalidChunkedEncoding(
                                    "chunk signature mismatch".into(),
                                ));
                            }
                            sctx.prev_sig = calc;
                            verifier.update(&full_chunk);
                            out_decoded.extend_from_slice(&full_chunk);
                            self.state = ChunkDecodeState::ReadPayloadCrLf;
                        }
                    } else {
                        verifier.update(&piece);
                        out_decoded.extend_from_slice(&piece);
                        if *remaining == 0 {
                            self.state = ChunkDecodeState::ReadPayloadCrLf;
                        }
                    }
                }
                ChunkDecodeState::ReadPayloadCrLf => {
                    if self.raw_buf.len() < 2 {
                        break;
                    }
                    if &self.raw_buf[0..2] != b"\r\n" {
                        return Err(BodyStreamError::InvalidChunkedEncoding(
                            "missing CRLF after chunk payload".into(),
                        ));
                    }
                    self.raw_buf.advance(2);
                    self.state = ChunkDecodeState::ReadHeader;
                }
                ChunkDecodeState::ReadTrailers { lines } => {
                    let Some(crlf_pos) = find_crlf(&self.raw_buf) else {
                        break;
                    };
                    let line_bytes = self.raw_buf.split_to(crlf_pos);
                    self.raw_buf.advance(2);
                    if line_bytes.is_empty() {
                        // End of trailers!
                        let taken = std::mem::take(lines);
                        self.state = ChunkDecodeState::Done;
                        self.finish_trailers(taken, verifier)?;
                        break;
                    }
                    let line = std::str::from_utf8(&line_bytes).map_err(|_| {
                        BodyStreamError::InvalidChunkedEncoding("non-UTF8 trailer".into())
                    })?;
                    lines.push(line.to_string());
                }
                ChunkDecodeState::Done => break,
            }
        }
        Ok(())
    }

    pub fn verify_eof(&self) -> Result<(), BodyStreamError> {
        if !self.is_done() {
            return Err(BodyStreamError::IncompleteBody);
        }
        Ok(())
    }

    fn finish_trailers(
        &mut self,
        lines: Vec<String>,
        verifier: &mut StreamingDigestVerifier,
    ) -> Result<(), BodyStreamError> {
        let Some(exp_name) = &self.expected_trailer_name else {
            if !lines.is_empty() {
                return Err(BodyStreamError::InvalidChunkedEncoding(
                    "unexpected trailers in non-trailer stream".into(),
                ));
            }
            return Ok(());
        };

        let mut csum_val: Option<String> = None;
        let mut trailer_sig: Option<String> = None;

        for line in &lines {
            let Some((k, v)) = line.split_once(':') else {
                return Err(BodyStreamError::InvalidChunkedEncoding(
                    "malformed trailer line".into(),
                ));
            };
            let k_low = k.trim().to_ascii_lowercase();
            let v_trim = v.trim().to_string();
            if k_low == "x-amz-trailer-signature" {
                trailer_sig = Some(v_trim);
            } else if &k_low == exp_name {
                if csum_val.is_some() {
                    // [PR-12] Only one trailer checksum block allowed
                    return Err(BodyStreamError::InvalidChunkedEncoding(
                        "duplicate trailer checksum".into(),
                    ));
                }
                csum_val = Some(v_trim);
            } else {
                return Err(BodyStreamError::InvalidChunkedEncoding(
                    "undeclared trailer header".into(),
                ));
            }
        }

        let val = csum_val.ok_or_else(|| {
            BodyStreamError::InvalidChunkedEncoding("missing expected checksum trailer".into())
        })?;

        if let Some(sctx) = &self.signed {
            let sig = trailer_sig.ok_or_else(|| {
                BodyStreamError::InvalidChunkedEncoding("missing x-amz-trailer-signature".into())
            })?;
            let canonical_trailer = format!("{exp_name}:{val}\n");
            let calc = compute_trailer_signature(
                &sctx.signing_key,
                &sctx.amz_date,
                &sctx.scope,
                &sctx.prev_sig,
                &canonical_trailer,
            );
            if !constant_time_eq_str(&calc, &sig.to_ascii_lowercase()) {
                return Err(BodyStreamError::InvalidChunkedEncoding(
                    "trailer signature mismatch".into(),
                ));
            }
        }

        let alg = match exp_name.as_str() {
            "x-amz-checksum-crc32" => ChecksumAlgorithm::Crc32,
            "x-amz-checksum-crc32c" => ChecksumAlgorithm::Crc32c,
            "x-amz-checksum-crc64nvme" => ChecksumAlgorithm::Crc64Nvme,
            "x-amz-checksum-sha1" => ChecksumAlgorithm::Sha1,
            "x-amz-checksum-sha256" => ChecksumAlgorithm::Sha256,
            _ => {
                return Err(BodyStreamError::InvalidChunkedEncoding(
                    "unsupported trailer checksum".into(),
                ))
            }
        };
        crate::checksum::validate_checksum_b64_format(alg, &val)
            .map_err(|_| BodyStreamError::InvalidChunkedEncoding("invalid trailer base64".into()))?;

        verifier.set_trailer_expected_checksum(val.clone());
        self.parsed_trailer_checksum_b64 = Some(val);
        Ok(())
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Sanitize `Content-Encoding` before persisting (`FR-5`: strip `aws-chunked`; if empty, return `None`).
pub fn strip_aws_chunked_encoding(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    let kept: Vec<&str> = raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("aws-chunked"))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join(", "))
    }
}
