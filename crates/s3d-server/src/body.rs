use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use s3d_proto::{AwsChunkedDecoder, PayloadAuthMode, StreamingDigestVerifier};
use s3d_types::{
    AsyncByteReader, BodyStreamError, ChecksumAlgorithm, S3Error, S3ErrorCode, StoreResult,
    VerifiedBodyStream, VerifiedDigests,
};

/// Streaming request body wrapper implementing `VerifiedBodyStream` (`PR-12`, `PR-13`, `PR-27`).
/// Never polls `Incoming` until `poll_next_chunk` is invoked by the engine!
pub struct HyperVerifiedBodyStream {
    incoming: Incoming,
    incoming_eof: bool,
    chunked_decoder: Option<AwsChunkedDecoder>,
    decoded_buf: BytesMut,
    verifier: Option<StreamingDigestVerifier>,
    max_bytes_limit: u64,
    emitted_bytes: u64,
}

impl HyperVerifiedBodyStream {
    pub fn new(
        incoming: Incoming,
        payload_mode: PayloadAuthMode,
        content_len_header: Option<u64>,
        expected_md5: Option<[u8; 16]>,
        header_checksum: Option<(ChecksumAlgorithm, Option<String>)>,
        max_bytes_limit: u64,
    ) -> StoreResult<Self> {
        let (chunked_decoder, verifier) = match payload_mode {
            PayloadAuthMode::Unsigned => (
                None,
                StreamingDigestVerifier::new(
                    content_len_header,
                    expected_md5,
                    None,
                    header_checksum,
                ),
            ),
            PayloadAuthMode::SignedHash(sha) => (
                None,
                StreamingDigestVerifier::new(
                    content_len_header,
                    expected_md5,
                    Some(sha),
                    header_checksum,
                ),
            ),
            PayloadAuthMode::StreamingSignedChunked {
                seed_signature,
                amz_date,
                scope,
                signing_key,
                decoded_len,
                trailer_header,
            } => {
                if decoded_len > max_bytes_limit {
                    return Err(S3Error::new(
                        S3ErrorCode::EntityTooLarge,
                        "Your proposed upload exceeds the maximum allowed size",
                    ));
                }
                let csum_spec = match (&trailer_header, header_checksum) {
                    (Some(th), _) => Some((alg_from_trailer_hdr(th)?, None)),
                    (None, hc) => hc,
                };
                let dec = AwsChunkedDecoder::new_signed(
                    signing_key,
                    amz_date,
                    scope,
                    seed_signature,
                    decoded_len,
                    trailer_header,
                );
                let ver =
                    StreamingDigestVerifier::new(Some(decoded_len), expected_md5, None, csum_spec);
                (Some(dec), ver)
            }
            PayloadAuthMode::StreamingUnsignedTrailer {
                decoded_len,
                trailer_header,
            } => {
                if decoded_len > max_bytes_limit {
                    return Err(S3Error::new(
                        S3ErrorCode::EntityTooLarge,
                        "Your proposed upload exceeds the maximum allowed size",
                    ));
                }
                let alg = alg_from_trailer_hdr(&trailer_header)?;
                let dec = AwsChunkedDecoder::new_unsigned_trailer(decoded_len, trailer_header);
                let ver = StreamingDigestVerifier::new(
                    Some(decoded_len),
                    expected_md5,
                    None,
                    Some((alg, None)),
                );
                (Some(dec), ver)
            }
        };

        if let Some(cl) = content_len_header {
            if chunked_decoder.is_none() && cl > max_bytes_limit {
                return Err(S3Error::new(
                    S3ErrorCode::EntityTooLarge,
                    "Your proposed upload exceeds the maximum allowed size",
                ));
            }
        }

        Ok(Self {
            incoming,
            incoming_eof: false,
            chunked_decoder,
            decoded_buf: BytesMut::new(),
            verifier: Some(verifier),
            max_bytes_limit,
            emitted_bytes: 0,
        })
    }

    /// Collect the entire verified body into memory up to `max_bytes` (for XML control requests).
    pub async fn collect_bounded(mut self) -> StoreResult<(Bytes, VerifiedDigests)> {
        let mut out = BytesMut::new();
        while let Some(chunk) = std::future::poll_fn(|cx| self.poll_next_chunk(cx))
            .await
            .map_err(map_body_err)?
        {
            out.extend_from_slice(&chunk);
        }
        let digests = self.finish().map_err(map_body_err)?;
        Ok((out.freeze(), digests))
    }
}

fn alg_from_trailer_hdr(name: &str) -> StoreResult<ChecksumAlgorithm> {
    match name {
        "x-amz-checksum-crc32" => Ok(ChecksumAlgorithm::Crc32),
        "x-amz-checksum-crc32c" => Ok(ChecksumAlgorithm::Crc32c),
        "x-amz-checksum-crc64nvme" => Ok(ChecksumAlgorithm::Crc64Nvme),
        "x-amz-checksum-sha1" => Ok(ChecksumAlgorithm::Sha1),
        "x-amz-checksum-sha256" => Ok(ChecksumAlgorithm::Sha256),
        _ => Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Unsupported checksum trailer header",
        )),
    }
}

pub fn map_body_err(err: BodyStreamError) -> S3Error {
    match err {
        BodyStreamError::Sha256Mismatch => S3Error::new(
            S3ErrorCode::XAmzContentSHA256Mismatch,
            "The provided 'x-amz-content-sha256' header does not match what was computed.",
        ),
        BodyStreamError::BadDigest => S3Error::new(
            S3ErrorCode::BadDigest,
            "The digest you specified did not match the calculated digest.",
        ),
        BodyStreamError::InvalidChunkedEncoding(msg) => {
            S3Error::new(S3ErrorCode::InvalidRequest, msg)
        }
        BodyStreamError::EntityTooLarge => S3Error::new(
            S3ErrorCode::EntityTooLarge,
            "Your proposed upload exceeds the maximum allowed size",
        ),
        BodyStreamError::EntityTooSmall => S3Error::new(
            S3ErrorCode::EntityTooSmall,
            "Your proposed upload is smaller than the minimum allowed size",
        ),
        BodyStreamError::IncompleteBody | BodyStreamError::ClientDisconnected(_) => S3Error::new(
            S3ErrorCode::IncompleteBody,
            "You did not provide the number of bytes specified by the Content-Length HTTP header.",
        ),
    }
}

impl VerifiedBodyStream for HyperVerifiedBodyStream {
    fn poll_next_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, BodyStreamError>> {
        loop {
            if !self.decoded_buf.is_empty() {
                let chunk = self.decoded_buf.split().freeze();
                self.emitted_bytes += chunk.len() as u64;
                if self.emitted_bytes > self.max_bytes_limit {
                    return Poll::Ready(Err(BodyStreamError::EntityTooLarge));
                }
                return Poll::Ready(Ok(Some(chunk)));
            }

            if self.incoming_eof {
                return Poll::Ready(Ok(None));
            }

            match Pin::new(&mut self.incoming).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.incoming_eof = true;
                    if let Some(dec) = &self.chunked_decoder {
                        dec.verify_eof()?;
                    }
                    return Poll::Ready(Ok(None));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(BodyStreamError::ClientDisconnected(e.to_string())));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if data.is_empty() {
                        continue;
                    }
                    let ver = self
                        .verifier
                        .as_mut()
                        .expect("poll_next_chunk called after finish");

                    if let Some(dec) = &mut self.chunked_decoder {
                        dec.push_wire_bytes(&data, ver, &mut self.decoded_buf)?;
                    } else {
                        self.emitted_bytes += data.len() as u64;
                        if self.emitted_bytes > self.max_bytes_limit {
                            return Poll::Ready(Err(BodyStreamError::EntityTooLarge));
                        }
                        ver.update(&data);
                        return Poll::Ready(Ok(Some(data)));
                    }
                }
            }
        }
    }

    fn finish(&mut self) -> Result<VerifiedDigests, BodyStreamError> {
        if let Some(dec) = &self.chunked_decoder {
            dec.verify_eof()?;
        }
        let ver = self
            .verifier
            .take()
            .expect("finish called multiple times on HyperVerifiedBodyStream");
        ver.finish()
    }
}

/// Streaming HTTP response body (`Fixed` XML/empty or `Stream` over `AsyncByteReader`).
pub enum S3ResponseBody<R> {
    Fixed(Option<Bytes>),
    Stream(R),
}

impl<R> S3ResponseBody<R> {
    pub fn empty() -> Self {
        Self::Fixed(None)
    }

    pub fn from_bytes(b: impl Into<Bytes>) -> Self {
        let bytes = b.into();
        if bytes.is_empty() {
            Self::Fixed(None)
        } else {
            Self::Fixed(Some(bytes))
        }
    }
}

impl<R: AsyncByteReader> Body for S3ResponseBody<R> {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut *self {
            Self::Fixed(opt) => Poll::Ready(opt.take().map(|b| Ok(Frame::data(b)))),
            Self::Stream(reader) => match Pin::new(reader).poll_read_chunk(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Some(chunk))) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
                Poll::Ready(Ok(None)) => Poll::Ready(None),
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(std::io::Error::other(e.to_string())))),
            },
        }
    }
}

pub async fn drain_empty_or_ignore(mut incoming: Incoming) {
    // Drain tiny trailing EOF if any without blocking connection reuse when body is 0 bytes
    if incoming.size_hint().exact() == Some(0) {
        let _ = incoming.frame().await;
    }
}

/// Collect raw unverified HTTP `Incoming` frames up to `max_bytes` (used by HTML Form `PostObject`).
pub async fn collect_raw_incoming_bounded(
    mut incoming: Incoming,
    max_bytes: u64,
) -> StoreResult<Bytes> {
    let mut out = BytesMut::new();
    while let Some(frame_res) = incoming.frame().await {
        let frame = frame_res.map_err(|_| {
            S3Error::new(
                S3ErrorCode::IncompleteBody,
                "Client disconnected while sending POST body.",
            )
        })?;
        if let Ok(data) = frame.into_data() {
            if out.len() as u64 + data.len() as u64 > max_bytes {
                return Err(S3Error::new(
                    S3ErrorCode::EntityTooLarge,
                    "Your proposed upload exceeds the maximum allowed size",
                ));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out.freeze())
}

/// `VerifiedBodyStream` over an already-buffered `Bytes` slice (used by `PostObject`).
pub struct PreVerifiedBytesStream {
    data: Option<Bytes>,
    verifier: Option<StreamingDigestVerifier>,
}

impl PreVerifiedBytesStream {
    pub fn new(
        data: Bytes,
        expected_checksum: Option<(ChecksumAlgorithm, String)>,
    ) -> Self {
        let len = data.len() as u64;
        let verifier = StreamingDigestVerifier::new(
            Some(len),
            None,
            None,
            expected_checksum.map(|(alg, val)| (alg, Some(val))),
        );
        Self {
            data: Some(data),
            verifier: Some(verifier),
        }
    }
}

impl VerifiedBodyStream for PreVerifiedBytesStream {
    fn poll_next_chunk(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, BodyStreamError>> {
        if let Some(chunk) = self.data.take() {
            if !chunk.is_empty() {
                self.verifier
                    .as_mut()
                    .expect("poll_next_chunk called after finish")
                    .update(&chunk);
                return Poll::Ready(Ok(Some(chunk)));
            }
        }
        Poll::Ready(Ok(None))
    }

    fn finish(&mut self) -> Result<VerifiedDigests, BodyStreamError> {
        self.verifier
            .take()
            .expect("finish called multiple times on PreVerifiedBytesStream")
            .finish()
    }
}
