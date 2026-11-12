use std::collections::HashMap;
use std::sync::RwLock;

use hmac::{Hmac, Mac};
use http::{HeaderMap, Method};
use s3d_types::{AccountRecord, OwnerInfo, S3Error, S3ErrorCode, StoreResult};
use sha2::{Digest, Sha256};

use crate::uri::{aws_uri_encode, ParsedUri};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_CLOCK_SKEW_MS: i64 = 15 * 60 * 1000; // 15 minutes (`PR-9`)
pub const MIN_PRESIGN_EXPIRES_SEC: i64 = 1;
pub const MAX_PRESIGN_EXPIRES_SEC: i64 = 604_800; // 7 days (`PR-10`)
pub const EMPTY_SHA256_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone)]
pub enum PayloadAuthMode {
    Unsigned,
    SignedHash([u8; 32]),
    StreamingSignedChunked {
        seed_signature: String,
        amz_date: String,
        scope: String,
        signing_key: [u8; 32],
        decoded_len: u64,
        trailer_header: Option<String>,
    },
    StreamingUnsignedTrailer {
        decoded_len: u64,
        trailer_header: String,
    },
}

#[derive(Debug, Clone)]
pub struct AuthOutcome {
    pub caller: Option<OwnerInfo>,
    pub is_authenticated: bool,
    pub is_presigned: bool,
    pub payload_mode: PayloadAuthMode,
}

/// Thread-safe credential directory + derived signing-key cache (`PR-7`).
pub struct SigV4Verifier {
    region: String,
    by_access_key: HashMap<String, AccountRecord>,
    /// Cache `(access_key, date_yyyymmdd)` -> 32-byte derived signing key (`PR-7`).
    key_cache: RwLock<HashMap<(String, String), [u8; 32]>>,
}

impl SigV4Verifier {
    pub fn new(region: impl Into<String>, accounts: Vec<AccountRecord>) -> Self {
        let mut by_access_key = HashMap::with_capacity(accounts.len());
        for acc in accounts {
            by_access_key.insert(acc.access_key.clone(), acc);
        }
        Self {
            region: region.into(),
            by_access_key,
            key_cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    fn derive_signing_key(&self, account: &AccountRecord, date_yyyymmdd: &str) -> [u8; 32] {
        let cache_key = (account.access_key.clone(), date_yyyymmdd.to_string());
        if let Some(&cached) = self.key_cache.read().unwrap().get(&cache_key) {
            return cached;
        }
        let k_secret = format!("AWS4{}", account.secret_key.expose());
        let k_date = hmac_sha256(k_secret.as_bytes(), date_yyyymmdd.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"s3");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");

        let mut cache = self.key_cache.write().unwrap();
        if cache.len() > 4096 {
            cache.clear();
        }
        cache.insert(cache_key, k_signing);
        k_signing
    }

    /// Authenticate incoming request (Header SigV4, Presigned URL, or Anonymous) (`PR-6` ~ `PR-12`).
    pub fn verify_request(
        &self,
        method: &Method,
        uri: &ParsedUri,
        headers: &HeaderMap,
        now_ms: i64,
    ) -> StoreResult<AuthOutcome> {
        if let Some(auth_val) = headers.get("authorization") {
            let auth_str = auth_val.to_str().map_err(|_| {
                S3Error::new(
                    S3ErrorCode::AuthorizationHeaderMalformed,
                    "The authorization header that you provided is not valid.",
                )
            })?;
            return self.verify_header_auth(method, uri, headers, auth_str, now_ms);
        }

        // Check query string for Presigned URL (`X-Amz-Algorithm`)
        if uri
            .query
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-Amz-Algorithm"))
        {
            return self.verify_presigned(method, uri, headers, now_ms);
        }

        // Check SigV2 query (`AWSAccessKeyId`) -> Not supported (400 InvalidRequest)
        if uri.query.iter().any(|(k, _)| k == "AWSAccessKeyId") {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Please use AWS4-HMAC-SHA256.",
            ));
        }

        // Anonymous request
        Ok(AuthOutcome {
            caller: None,
            is_authenticated: false,
            is_presigned: false,
            payload_mode: PayloadAuthMode::Unsigned,
        })
    }

    fn verify_header_auth(
        &self,
        method: &Method,
        uri: &ParsedUri,
        headers: &HeaderMap,
        auth_str: &str,
        now_ms: i64,
    ) -> StoreResult<AuthOutcome> {
        let auth_str = auth_str.trim();
        if auth_str.is_empty() {
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Access Denied",
            ));
        }
        if auth_str.starts_with("AWS ") || auth_str.starts_with("AWS4-ECDSA-P256-SHA256") {
            // Section 4.2: SigV2 / SigV4a -> 400 InvalidRequest
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.",
            ));
        }
        let Some(rest) = auth_str.strip_prefix("AWS4-HMAC-SHA256 ") else {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                "The authorization header that you provided is not valid.",
            ));
        };

        let mut credential_val = None;
        let mut signed_headers_val = None;
        let mut signature_val = None;

        for part in rest.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some((k, v)) = part.split_once('=') else {
                return Err(S3Error::new(
                    S3ErrorCode::AuthorizationHeaderMalformed,
                    "The authorization header that you provided is not valid.",
                ));
            };
            match k.trim() {
                "Credential" => credential_val = Some(v.trim()),
                "SignedHeaders" => signed_headers_val = Some(v.trim()),
                "Signature" => signature_val = Some(v.trim()),
                _ => {
                    return Err(S3Error::new(
                        S3ErrorCode::AuthorizationHeaderMalformed,
                        "The authorization header that you provided is not valid.",
                    ));
                }
            }
        }

        let (Some(cred), Some(sh_raw), Some(sig_hex)) =
            (credential_val, signed_headers_val, signature_val)
        else {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                "The authorization header that you provided is not valid.",
            ));
        };

        let (ak, date_yyyymmdd, scope) = self.parse_and_check_credential(cred)?;

        // Parse request timestamp (`x-amz-date` preferred over `Date`)
        let (amz_date_iso, req_ts_ms) = extract_request_timestamp(headers)?;
        if (req_ts_ms - now_ms).abs() > MAX_CLOCK_SKEW_MS {
            return Err(S3Error::new(
                S3ErrorCode::RequestTimeTooSkewed,
                "The difference between the request time and the current time is too large.",
            ));
        }
        if !amz_date_iso.starts_with(&date_yyyymmdd) {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                "Credential date does not match request date.",
            ));
        }

        let account = self.by_access_key.get(&ak).ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::InvalidAccessKeyId,
                "The AWS Access Key Id you provided does not exist in our records.",
            )
        })?;

        let signed_headers: Vec<String> = sh_raw
            .split(';')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if !signed_headers.iter().any(|h| h == "host") {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                "SignedHeaders must include host.",
            ));
        }

        // Payload hash header (`x-amz-content-sha256`)
        let payload_sha_hdr = match headers.get("x-amz-content-sha256") {
            Some(v) => v.to_str().map_err(|_| {
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid x-amz-content-sha256 header",
                )
            })?,
            None => "UNSIGNED-PAYLOAD",
        };

        let canonical_headers = build_canonical_headers(headers, &signed_headers)?;
        let canonical_query = build_canonical_query(&uri.query, false);
        let signed_headers_joined = signed_headers.join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            uri.canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers_joined,
            payload_sha_hdr
        );

        let cr_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date_iso, scope, cr_hash
        );

        let signing_key = self.derive_signing_key(account, &date_yyyymmdd);
        let expected_sig = hmac_sha256(&signing_key, string_to_sign.as_bytes());
        let provided_sig = decode_sig_hex(sig_hex)?;

        if !constant_time_eq_32(&expected_sig, &provided_sig) {
            return Err(S3Error::new(
                S3ErrorCode::SignatureDoesNotMatch,
                "The request signature we calculated does not match the signature you provided.",
            ));
        }

        let payload_mode = parse_payload_mode(
            payload_sha_hdr,
            headers,
            sig_hex,
            &amz_date_iso,
            &scope,
            signing_key,
        )?;

        Ok(AuthOutcome {
            caller: Some(account.owner.clone()),
            is_authenticated: true,
            is_presigned: false,
            payload_mode,
        })
    }

    fn verify_presigned(
        &self,
        method: &Method,
        uri: &ParsedUri,
        headers: &HeaderMap,
        now_ms: i64,
    ) -> StoreResult<AuthOutcome> {
        let get_q = |name: &str| -> Option<&str> {
            uri.query
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };

        let alg = get_q("X-Amz-Algorithm").unwrap_or("");
        if alg != "AWS4-HMAC-SHA256" {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Please use AWS4-HMAC-SHA256.",
            ));
        }

        let (Some(cred), Some(amz_date), Some(expires_str), Some(sh_raw), Some(sig_hex)) = (
            get_q("X-Amz-Credential"),
            get_q("X-Amz-Date"),
            get_q("X-Amz-Expires"),
            get_q("X-Amz-SignedHeaders"),
            get_q("X-Amz-Signature"),
        ) else {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                "Incomplete presigned URL parameters.",
            ));
        };

        // [PR-10] Presigned X-Amz-Expires in 1..=604800; out of range or expired -> 403 AccessDenied
        let expires_sec: i64 = expires_str
            .parse()
            .map_err(|_| S3Error::new(S3ErrorCode::AccessDenied, "Invalid X-Amz-Expires"))?;
        if !(MIN_PRESIGN_EXPIRES_SEC..=MAX_PRESIGN_EXPIRES_SEC).contains(&expires_sec) {
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "X-Amz-Expires must be between 1 and 604800 seconds",
            ));
        }

        let sign_ts_ms = parse_iso8601_compact_ms(amz_date).map_err(|_| {
            S3Error::new(S3ErrorCode::AccessDenied, "Invalid X-Amz-Date in presigned URL")
        })?;
        if sign_ts_ms - now_ms > MAX_CLOCK_SKEW_MS {
            return Err(S3Error::new(
                S3ErrorCode::RequestTimeTooSkewed,
                "Request time is too skewed.",
            ));
        }
        if now_ms > sign_ts_ms + expires_sec * 1000 {
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Request has expired",
            ));
        }

        let (ak, date_yyyymmdd, scope) = self.parse_and_check_credential(cred)?;
        let account = self.by_access_key.get(&ak).ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::InvalidAccessKeyId,
                "The AWS Access Key Id you provided does not exist in our records.",
            )
        })?;

        let signed_headers: Vec<String> = sh_raw
            .split(';')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let canonical_headers = build_canonical_headers(headers, &signed_headers)?;
        let canonical_query = build_canonical_query(&uri.query, true);
        let signed_headers_joined = signed_headers.join(";");

        let payload_sha = headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("UNSIGNED-PAYLOAD");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            uri.canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers_joined,
            payload_sha
        );
        let cr_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amz_date, scope, cr_hash);

        let signing_key = self.derive_signing_key(account, &date_yyyymmdd);
        let expected_sig = hmac_sha256(&signing_key, string_to_sign.as_bytes());
        let provided_sig = decode_sig_hex(sig_hex)?;

        if !constant_time_eq_32(&expected_sig, &provided_sig) {
            return Err(S3Error::new(
                S3ErrorCode::SignatureDoesNotMatch,
                "The request signature we calculated does not match the signature you provided.",
            ));
        }

        let payload_mode = if payload_sha == "UNSIGNED-PAYLOAD" {
            PayloadAuthMode::Unsigned
        } else {
            parse_payload_mode(payload_sha, headers, sig_hex, amz_date, &scope, signing_key)?
        };

        Ok(AuthOutcome {
            caller: Some(account.owner.clone()),
            is_authenticated: true,
            is_presigned: true,
            payload_mode,
        })
    }

    fn parse_and_check_credential(&self, cred: &str) -> StoreResult<(String, String, String)> {
        let parts: Vec<&str> = cred.split('/').collect();
        if parts.len() != 5 || parts[4] != "aws4_request" {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                "Invalid Credential scope format.",
            ));
        }
        let (ak, date, region, service) = (parts[0], parts[1], parts[2], parts[3]);
        if ak.is_empty() || date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                "Invalid Credential date or access key.",
            ));
        }
        // [PR-4] Credential region mismatch -> 400 AuthorizationHeaderMalformed
        if region != self.region || service != "s3" {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                format!(
                    "The authorization header is malformed; the region '{region}' is wrong; expecting '{}'.",
                    self.region
                ),
            ));
        }
        let scope = format!("{date}/{region}/{service}/aws4_request");
        Ok((ak.to_string(), date.to_string(), scope))
    }
}

fn parse_payload_mode(
    payload_sha_hdr: &str,
    headers: &HeaderMap,
    seed_sig: &str,
    amz_date: &str,
    scope: &str,
    signing_key: [u8; 32],
) -> StoreResult<PayloadAuthMode> {
    match payload_sha_hdr {
        "UNSIGNED-PAYLOAD" => Ok(PayloadAuthMode::Unsigned),
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" => {
            let decoded_len = require_decoded_content_len(headers)?;
            Ok(PayloadAuthMode::StreamingSignedChunked {
                seed_signature: seed_sig.to_ascii_lowercase(),
                amz_date: amz_date.to_string(),
                scope: scope.to_string(),
                signing_key,
                decoded_len,
                trailer_header: None,
            })
        }
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => {
            let decoded_len = require_decoded_content_len(headers)?;
            let trailer = require_allowed_trailer(headers)?;
            Ok(PayloadAuthMode::StreamingUnsignedTrailer {
                decoded_len,
                trailer_header: trailer,
            })
        }
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => {
            let decoded_len = require_decoded_content_len(headers)?;
            let trailer = require_allowed_trailer(headers)?;
            Ok(PayloadAuthMode::StreamingSignedChunked {
                seed_signature: seed_sig.to_ascii_lowercase(),
                amz_date: amz_date.to_string(),
                scope: scope.to_string(),
                signing_key,
                decoded_len,
                trailer_header: Some(trailer),
            })
        }
        hex_str => {
            let bytes = hex::decode(hex_str).map_err(|_| {
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, valid streaming value, or hex SHA256.",
                )
            })?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "x-amz-content-sha256 must be 64 hex characters.",
                )
            })?;
            Ok(PayloadAuthMode::SignedHash(arr))
        }
    }
}

fn require_decoded_content_len(headers: &HeaderMap) -> StoreResult<u64> {
    let raw = headers
        .get("x-amz-decoded-content-length")
        .ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::MissingContentLength,
                "Missing x-amz-decoded-content-length for aws-chunked upload.",
            )
        })?
        .to_str()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid decoded content length"))?;
    raw.trim()
        .parse::<u64>()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid decoded content length"))
}

fn require_allowed_trailer(headers: &HeaderMap) -> StoreResult<String> {
    let raw = headers
        .get("x-amz-trailer")
        .ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Missing x-amz-trailer header for trailer streaming upload.",
            )
        })?
        .to_str()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidRequest, "Invalid x-amz-trailer"))?
        .trim()
        .to_ascii_lowercase();
    // [PR-27] Only the 5 supported trailer checksum headers are allowed
    match raw.as_str() {
        "x-amz-checksum-crc32"
        | "x-amz-checksum-crc32c"
        | "x-amz-checksum-crc64nvme"
        | "x-amz-checksum-sha1"
        | "x-amz-checksum-sha256" => Ok(raw),
        _ => Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "The value specified in the x-amz-trailer header is not supported",
        )),
    }
}

pub fn compute_chunk_signature(
    signing_key: &[u8; 32],
    amz_date: &str,
    scope: &str,
    prev_sig: &str,
    chunk_data: &[u8],
) -> String {
    let chunk_hash = hex::encode(Sha256::digest(chunk_data));
    let sts = format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prev_sig}\n{EMPTY_SHA256_HEX}\n{chunk_hash}"
    );
    hex::encode(hmac_sha256(signing_key, sts.as_bytes()))
}

pub fn compute_trailer_signature(
    signing_key: &[u8; 32],
    amz_date: &str,
    scope: &str,
    prev_sig: &str,
    canonical_trailer_line: &str,
) -> String {
    let trailer_hash = hex::encode(Sha256::digest(canonical_trailer_line.as_bytes()));
    let sts = format!("AWS4-HMAC-SHA256-TRAILER\n{amz_date}\n{scope}\n{prev_sig}\n{trailer_hash}");
    hex::encode(hmac_sha256(signing_key, sts.as_bytes()))
}

pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn decode_sig_hex(sig_hex: &str) -> StoreResult<[u8; 32]> {
    let bytes = hex::decode(sig_hex).map_err(|_| {
        S3Error::new(
            S3ErrorCode::SignatureDoesNotMatch,
            "Malformed signature hex.",
        )
    })?;
    bytes.try_into().map_err(|_| {
        S3Error::new(
            S3ErrorCode::SignatureDoesNotMatch,
            "Signature length must be 32 bytes.",
        )
    })
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn build_canonical_query(query: &[(String, String)], exclude_sig: bool) -> String {
    let mut encoded: Vec<(String, String)> = query
        .iter()
        .filter(|(k, _)| !(exclude_sig && k == "X-Amz-Signature"))
        .map(|(k, v)| (aws_uri_encode(k, true), aws_uri_encode(v, true)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Decode an HTTP `HeaderValue` as UTF-8, falling back to ISO-8859-1 (Latin-1) per HTTP/1.1 `obs-text`
/// so `botocore` / `urllib3` non-ASCII `x-amz-meta-*` headers match Python's `CanonicalRequest` UTF-8 hash.
pub fn decode_header_value_str(v: &http::HeaderValue) -> String {
    match std::str::from_utf8(v.as_bytes()) {
        Ok(s) => s.to_string(),
        Err(_) => v.as_bytes().iter().map(|&b| b as char).collect(),
    }
}

fn build_canonical_headers(headers: &HeaderMap, signed_headers: &[String]) -> StoreResult<String> {
    let mut sorted = signed_headers.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut out = String::new();
    for hname in sorted {
        let mut vals = Vec::new();
        for v in headers.get_all(hname.as_str()) {
            let s = decode_header_value_str(v);
            vals.push(collapse_header_ws(&s));
        }
        if vals.is_empty() {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                format!("Signed header '{hname}' missing from request"),
            ));
        }
        out.push_str(&hname);
        out.push(':');
        out.push_str(&vals.join(","));
        out.push('\n');
    }
    Ok(out)
}

fn collapse_header_ws(s: &str) -> String {
    let trimmed = s.trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_space = false;
    for ch in trimmed.chars() {
        if ch == ' ' || ch == '\t' {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

fn extract_request_timestamp(headers: &HeaderMap) -> StoreResult<(String, i64)> {
    if let Some(amz) = headers.get("x-amz-date") {
        let s = amz.to_str().map_err(|_| {
            S3Error::new(S3ErrorCode::AccessDenied, "Invalid x-amz-date header")
        })?;
        let ms = parse_iso8601_compact_ms(s)
            .map_err(|_| S3Error::new(S3ErrorCode::AccessDenied, "Invalid x-amz-date format"))?;
        return Ok((s.trim().to_string(), ms));
    }
    if let Some(date_hdr) = headers.get("date") {
        let s = date_hdr
            .to_str()
            .map_err(|_| S3Error::new(S3ErrorCode::AccessDenied, "Invalid Date header"))?;
        let sys_time = httpdate::parse_http_date(s.trim())
            .map_err(|_| S3Error::new(S3ErrorCode::AccessDenied, "Invalid HTTP Date format"))?;
        let ms = sys_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| S3Error::new(S3ErrorCode::AccessDenied, "Date before epoch"))?
            .as_millis() as i64;
        return Ok((format_iso8601_compact(ms), ms));
    }
    Err(S3Error::new(
        S3ErrorCode::AccessDenied,
        "AWS authentication requires a valid Date or x-amz-date header",
    ))
}

/// Parse `YYYYMMDDTHHMMSSZ` into Unix epoch milliseconds.
pub fn parse_iso8601_compact_ms(s: &str) -> Result<i64, ()> {
    let b = s.trim().as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return Err(());
    }
    let parse_num = |slice: &[u8]| -> Result<i64, ()> {
        std::str::from_utf8(slice)
            .map_err(|_| ())?
            .parse::<i64>()
            .map_err(|_| ())
    };
    let year = parse_num(&b[0..4])?;
    let month = parse_num(&b[4..6])?;
    let day = parse_num(&b[6..8])?;
    let hour = parse_num(&b[9..11])?;
    let min = parse_num(&b[11..13])?;
    let sec = parse_num(&b[13..15])?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return Err(());
    }

    let days = days_from_civil(year, month as u32, day as u32);
    Ok(((days * 86_400 + hour * 3600 + min * 60 + sec) * 1000) as i64)
}

pub fn format_iso8601_compact(epoch_ms: i64) -> String {
    let total_secs = epoch_ms.div_euclid(1000);
    let days = total_secs.div_euclid(86_400);
    let rem = total_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

pub fn format_iso8601_millis(epoch_ms: i64) -> String {
    let total_secs = epoch_ms.div_euclid(1000);
    let millis = epoch_ms.rem_euclid(1000);
    let days = total_secs.div_euclid(86_400);
    let rem = total_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

// Howard Hinnant civil calendar algorithms (exact, leap-year accurate)
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + (d as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m as u32, d as u32)
}
