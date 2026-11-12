use std::collections::BTreeMap;
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine as _;
use md5::{Digest as _, Md5};
use serde::{Deserialize, Serialize};

use crate::acl::AclGrant;
use crate::crypto::ct_eq_16;
use crate::error::{S3Error, S3ErrorCode, StoreResult};

// ============================================================================
// Civil <-> Unix Timestamp Helpers (Howard Hinnant's proleptic Gregorian)
// ============================================================================

pub const US_PER_SEC: i64 = 1_000_000;
pub const US_PER_MS: i64 = 1_000;
pub const US_PER_DAY: i64 = 86_400 * US_PER_SEC;

pub fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let y = i64::from(year) - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = u64::from(month);
    let d = u64::from(day);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

pub fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

pub fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

pub fn days_in_month(year: i32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap_year(year) { 29 } else { 28 }),
        _ => None,
    }
}

/// Parse an ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)`) into Unix microseconds.
pub fn parse_iso8601_utc_us(raw: &str) -> Option<i64> {
    let s = raw.trim();
    if s.len() < 20 {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' || (bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ') {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }

    let year: i32 = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let max_day = days_in_month(year, month)?;
    if !(1..=9999).contains(&year) || day == 0 || day > max_day {
        return None;
    }

    let hour: u32 = s[11..13].parse().ok()?;
    let min: u32 = s[14..16].parse().ok()?;
    let sec: u32 = s[17..19].parse().ok()?;
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }

    let mut rest = &s[19..];
    let mut subsec_us: i64 = 0;
    if let Some(after_dot) = rest.strip_prefix('.') {
        let frac_len = after_dot
            .bytes()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if frac_len == 0 || frac_len > 9 {
            return None;
        }
        let frac_str = &after_dot[..frac_len];
        let mut digits = [b'0'; 6];
        for (i, b) in frac_str.bytes().take(6).enumerate() {
            digits[i] = b;
        }
        let us_str = std::str::from_utf8(&digits).ok()?;
        subsec_us = us_str.parse().ok()?;
        rest = &after_dot[frac_len..];
    }

    let tz_offset_secs: i64 = if rest == "Z" || rest == "z" {
        0
    } else {
        let off = rest.strip_prefix('+').or_else(|| rest.strip_prefix('-'))?;
        let sign: i64 = if rest.starts_with('-') { -1 } else { 1 };
        let (oh, om) = if off.len() == 5 && off.as_bytes()[2] == b':' {
            (off[0..2].parse::<u32>().ok()?, off[3..5].parse::<u32>().ok()?)
        } else if off.len() == 4 {
            (off[0..2].parse::<u32>().ok()?, off[2..4].parse::<u32>().ok()?)
        } else {
            return None;
        };
        if oh > 23 || om > 59 {
            return None;
        }
        sign * (i64::from(oh) * 3600 + i64::from(om) * 60)
    };

    let days = days_from_civil(year, month, day);
    let day_secs = i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec);
    let total_secs = days.checked_mul(86_400)?.checked_add(day_secs)?.checked_sub(tz_offset_secs)?;
    total_secs.checked_mul(US_PER_SEC)?.checked_add(subsec_us)
}

/// Parse HTTP header `x-amz-object-lock-retain-until-date` (accepts ISO-8601 or HTTP-date).
pub fn parse_retain_until_header_us(raw: &str) -> Option<i64> {
    if let Some(us) = parse_iso8601_utc_us(raw) {
        return Some(us);
    }
    let st = httpdate::parse_http_date(raw.trim()).ok()?;
    let dur = st.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(dur.as_micros()).ok()
}

/// Format Unix microseconds as ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.ffffffZ`).
pub fn format_iso8601_utc_us(us: i64) -> String {
    let days = us.div_euclid(US_PER_DAY);
    let rem_us = us.rem_euclid(US_PER_DAY);
    let rem_secs = rem_us / US_PER_SEC;
    let subsec_us = rem_us % US_PER_SEC;
    let hour = rem_secs / 3600;
    let min = (rem_secs % 3600) / 60;
    let sec = rem_secs % 60;
    let (year, month, day) = civil_from_days(days);
    if subsec_us == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{subsec_us:06}Z")
    }
}

pub fn is_exact_utc_midnight_us(us: i64) -> bool {
    us.rem_euclid(US_PER_DAY) == 0
}

pub fn add_calendar_years_us(base_us: i64, years: u32) -> i64 {
    let days = base_us.div_euclid(US_PER_DAY);
    let rem_us = base_us.rem_euclid(US_PER_DAY);
    let (y, m, d) = civil_from_days(days);
    let ny = y.saturating_add(years as i32).min(9999);
    let max_d = days_in_month(ny, m).unwrap_or(28);
    let nd = d.min(max_d);
    days_from_civil(ny, m, nd) * US_PER_DAY + rem_us
}

// ============================================================================
// Domain 1: Object Lock (`PR-36` ~ `PR-38`)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectLockMode {
    Governance,
    Compliance,
}

impl ObjectLockMode {
    pub const fn as_aws_str(self) -> &'static str {
        match self {
            Self::Governance => "GOVERNANCE",
            Self::Compliance => "COMPLIANCE",
        }
    }

    pub fn from_aws_str_exact(s: &str) -> Option<Self> {
        match s {
            "GOVERNANCE" => Some(Self::Governance),
            "COMPLIANCE" => Some(Self::Compliance),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultRetentionPeriod {
    Days(u32),
    Years(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultRetention {
    pub mode: ObjectLockMode,
    pub period: DefaultRetentionPeriod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ObjectLockConfiguration {
    pub default_retention: Option<DefaultRetention>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRetention {
    pub mode: ObjectLockMode,
    pub retain_until_us: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegalHoldStatus {
    On,
    Off,
}

impl LegalHoldStatus {
    pub const fn as_aws_str(self) -> &'static str {
        match self {
            Self::On => "ON",
            Self::Off => "OFF",
        }
    }

    pub fn from_aws_str_exact(s: &str) -> Option<Self> {
        match s {
            "ON" => Some(Self::On),
            "OFF" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Unvalidated Object Lock upload headers extracted at HTTP/POST layer so Bucket Policy runs first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawUploadObjectLockHeaders {
    pub mode: Option<String>,
    pub retain_until_date: Option<String>,
    pub legal_hold: Option<String>,
}

impl RawUploadObjectLockHeaders {
    pub fn has_any(&self) -> bool {
        self.mode.is_some() || self.retain_until_date.is_some() || self.legal_hold.is_some()
    }
}

/// Validate upload Object Lock headers and apply bucket `DefaultRetention` if no explicit retention was given.
pub fn resolve_upload_object_lock(
    bucket_lock_enabled: bool,
    bucket_cfg: Option<&ObjectLockConfiguration>,
    raw: &RawUploadObjectLockHeaders,
    now_ms: i64,
) -> StoreResult<(Option<ObjectRetention>, Option<LegalHoldStatus>)> {
    if raw.has_any() && !bucket_lock_enabled {
        return Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Bucket is missing Object Lock Configuration",
        ));
    }

    let now_us = now_ms.saturating_mul(US_PER_MS);

    let explicit_retention = match (&raw.mode, &raw.retain_until_date) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied",
            ));
        }
        (Some(m_str), Some(d_str)) => {
            let mode = ObjectLockMode::from_aws_str_exact(m_str.trim()).ok_or_else(|| {
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Unknown object lock mode specified.",
                )
            })?;
            let retain_until_us = parse_retain_until_header_us(d_str).ok_or_else(|| {
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "The retain until date must be provided in ISO 8601 format",
                )
            })?;
            if retain_until_us <= now_us {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "The retain until date must be in the future!",
                ));
            }
            Some(ObjectRetention {
                mode,
                retain_until_us,
            })
        }
    };

    let legal_hold = match &raw.legal_hold {
        None => None,
        Some(lh_str) => Some(
            LegalHoldStatus::from_aws_str_exact(lh_str.trim()).ok_or_else(|| {
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid x-amz-object-lock-legal-hold status",
                )
            })?,
        ),
    };

    let final_retention = if explicit_retention.is_some() {
        explicit_retention
    } else if bucket_lock_enabled {
        bucket_cfg
            .and_then(|c| c.default_retention)
            .map(|def| {
                let retain_until_us = match def.period {
                    DefaultRetentionPeriod::Days(d) => {
                        now_us.saturating_add(i64::from(d) * US_PER_DAY)
                    }
                    DefaultRetentionPeriod::Years(y) => add_calendar_years_us(now_us, y),
                };
                ObjectRetention {
                    mode: def.mode,
                    retain_until_us,
                }
            })
    } else {
        None
    };

    Ok((final_retention, legal_hold))
}

/// Enforce WORM transition rules for `PutObjectRetention`.
pub fn check_worm_put_retention(
    existing: Option<ObjectRetention>,
    new_ret: ObjectRetention,
    bypass_governance: bool,
    can_bypass: bool,
    now_ms: i64,
) -> StoreResult<()> {
    let now_us = now_ms.saturating_mul(US_PER_MS);
    if new_ret.retain_until_us <= now_us {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The retain until date must be in the future!",
        ));
    }
    if bypass_governance && !can_bypass {
        return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied"));
    }
    if let Some(ex) = existing
        && ex.retain_until_us > now_us
    {
        match ex.mode {
            ObjectLockMode::Compliance => {
                if new_ret.mode != ObjectLockMode::Compliance
                    || new_ret.retain_until_us < ex.retain_until_us
                {
                    return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied"));
                }
            }
            ObjectLockMode::Governance => {
                if !bypass_governance
                    && (new_ret.mode != ObjectLockMode::Governance
                        || new_ret.retain_until_us < ex.retain_until_us)
                {
                    return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied"));
                }
            }
        }
    }
    Ok(())
}

/// Enforce WORM protection when permanently deleting a specific non-delete-marker object version.
pub fn check_worm_version_delete(
    retention: Option<ObjectRetention>,
    legal_hold: Option<LegalHoldStatus>,
    bypass_governance: bool,
    can_bypass: bool,
    now_ms: i64,
) -> StoreResult<()> {
    if legal_hold == Some(LegalHoldStatus::On) {
        return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied"));
    }
    let now_us = now_ms.saturating_mul(US_PER_MS);
    if let Some(ret) = retention
        && ret.retain_until_us > now_us
    {
        match ret.mode {
            ObjectLockMode::Compliance => {
                return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied"));
            }
            ObjectLockMode::Governance => {
                if !bypass_governance || !can_bypass {
                    return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access Denied"));
                }
            }
        }
    }
    Ok(())
}

// ============================================================================
// Domain 2: Server-Side Encryption (`SSE-S3` & `SSE-C`, `PR-41` ~ `PR-42`)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketEncryptionConfig {
    pub sse_algorithm: String,
    pub bucket_key_enabled: Option<bool>,
}

/// Unvalidated SSE headers from HTTP request / POST form (validated AFTER bucket policy check!).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawSseHeaders {
    pub sse_algorithm: Option<String>,
    pub sse_kms_key_id: Option<String>,
    pub sse_customer_algorithm: Option<String>,
    pub sse_customer_key_b64: Option<String>,
    pub sse_customer_key_md5_b64: Option<String>,
}

impl RawSseHeaders {
    pub fn has_customer_headers(&self) -> bool {
        self.sse_customer_algorithm.is_some()
            || self.sse_customer_key_b64.is_some()
            || self.sse_customer_key_md5_b64.is_some()
    }
}

/// Unvalidated `x-amz-copy-source-server-side-encryption-customer-*` headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawCopySourceSseHeaders {
    pub sse_customer_algorithm: Option<String>,
    pub sse_customer_key_b64: Option<String>,
    pub sse_customer_key_md5_b64: Option<String>,
}

impl RawCopySourceSseHeaders {
    pub fn has_any(&self) -> bool {
        self.sse_customer_algorithm.is_some()
            || self.sse_customer_key_b64.is_some()
            || self.sse_customer_key_md5_b64.is_some()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ValidatedSseWrite {
    None,
    SseS3,
    SseC {
        key: [u8; 32],
        key_md5: [u8; 16],
        key_md5_b64: String,
    },
}

impl std::fmt::Debug for ValidatedSseWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::SseS3 => f.write_str("SseS3"),
            Self::SseC { key_md5_b64, .. } => f
                .debug_struct("SseC")
                .field("key", &"[REDACTED]")
                .field("key_md5_b64", key_md5_b64)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ValidatedSseRead {
    None,
    SseC {
        key: [u8; 32],
        key_md5: [u8; 16],
        key_md5_b64: String,
    },
}

impl std::fmt::Debug for ValidatedSseRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::SseC { key_md5_b64, .. } => f
                .debug_struct("SseC")
                .field("key", &"[REDACTED]")
                .field("key_md5_b64", key_md5_b64)
                .finish(),
        }
    }
}

/// At-rest encryption metadata persisted in WAL & Checkpoint.
/// Raw SSE-C customer keys are NEVER stored here (`ST-5`, Spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SseStoredMeta {
    #[default]
    None,
    SseS3 {
        iv: [u8; 16],
    },
    SseC {
        key_md5: [u8; 16],
        iv: [u8; 16],
    },
}

impl SseStoredMeta {
    pub fn to_response_headers(self) -> SseResponseHeaders {
        match self {
            Self::None => SseResponseHeaders::None,
            Self::SseS3 { .. } => SseResponseHeaders::SseS3,
            Self::SseC { key_md5, .. } => SseResponseHeaders::SseC {
                key_md5_b64: base64::engine::general_purpose::STANDARD.encode(key_md5),
            },
        }
    }
}

/// SSE response headers to attach to HTTP responses.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SseResponseHeaders {
    #[default]
    None,
    SseS3,
    SseC {
        key_md5_b64: String,
    },
}

fn parse_and_verify_sse_c_triplet(
    algo: Option<&str>,
    key_b64: Option<&str>,
    md5_b64: Option<&str>,
) -> StoreResult<([u8; 32], [u8; 16], String)> {
    let Some(algo_str) = algo else {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Requests specifying Server Side Encryption with Customer provided keys must provide a valid encryption algorithm.",
        ));
    };
    if algo_str.trim() != "AES256" {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The encryption method specified is not supported",
        ));
    }
    let Some(k_str) = key_b64 else {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Requests specifying Server Side Encryption with Customer provided keys must provide an appropriate secret key.",
        ));
    };
    let Some(m_str) = md5_b64 else {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Requests specifying Server Side Encryption with Customer provided keys must provide the client calculated MD5 of the secret key.",
        ));
    };

    let raw_key = base64::engine::general_purpose::STANDARD
        .decode(k_str.trim())
        .map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Secret key was invalid base64.",
            )
        })?;
    if raw_key.len() != 32 {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The secret key was invalid - too short or too long.",
        ));
    }
    let raw_md5 = base64::engine::general_purpose::STANDARD
        .decode(m_str.trim())
        .map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "The secret key MD5 was invalid base64.",
            )
        })?;
    if raw_md5.len() != 16 {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The secret key MD5 was invalid length.",
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&raw_key);
    let mut provided_md5 = [0u8; 16];
    provided_md5.copy_from_slice(&raw_md5);

    let computed = Md5::digest(key);
    let mut computed_md5 = [0u8; 16];
    computed_md5.copy_from_slice(&computed);

    if !ct_eq_16(&provided_md5, &computed_md5) {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The calculated MD5 hash of the key did not match the hash that was provided.",
        ));
    }

    let canonical_b64 = base64::engine::general_purpose::STANDARD.encode(computed_md5);
    Ok((key, computed_md5, canonical_b64))
}

/// Validate SSE headers for object/multipart write (`PutObject`, `CopyObject`, `CreateMultipartUpload`, `PostObject`).
pub fn validate_sse_write(
    raw: &RawSseHeaders,
    bucket_default_sse_s3: bool,
) -> StoreResult<ValidatedSseWrite> {
    if raw.sse_kms_key_id.is_some() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "SSE-KMS is not supported.",
        ));
    }
    if (raw.sse_algorithm.is_some()) && raw.has_customer_headers() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Server Side Encryption with Customer provided key is incompatible with the encryption method specified",
        ));
    }
    if let Some(alg) = &raw.sse_algorithm {
        if alg.trim() != "AES256" {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "The encryption method specified is not supported",
            ));
        }
        return Ok(ValidatedSseWrite::SseS3);
    }
    if raw.has_customer_headers() {
        let (key, key_md5, key_md5_b64) = parse_and_verify_sse_c_triplet(
            raw.sse_customer_algorithm.as_deref(),
            raw.sse_customer_key_b64.as_deref(),
            raw.sse_customer_key_md5_b64.as_deref(),
        )?;
        return Ok(ValidatedSseWrite::SseC {
            key,
            key_md5,
            key_md5_b64,
        });
    }
    if bucket_default_sse_s3 {
        Ok(ValidatedSseWrite::SseS3)
    } else {
        Ok(ValidatedSseWrite::None)
    }
}

/// Validate SSE headers on `GetObject`, `HeadObject`, `GetObjectAttributes`, `UploadPart`, `UploadPartCopy` (dest), or `CompleteMultipartUpload`.
pub fn validate_sse_read_or_part(raw: &RawSseHeaders) -> StoreResult<ValidatedSseRead> {
    if raw.sse_algorithm.is_some() || raw.sse_kms_key_id.is_some() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "x-amz-server-side-encryption header is not supported for this operation.",
        ));
    }
    if raw.has_customer_headers() {
        let (key, key_md5, key_md5_b64) = parse_and_verify_sse_c_triplet(
            raw.sse_customer_algorithm.as_deref(),
            raw.sse_customer_key_b64.as_deref(),
            raw.sse_customer_key_md5_b64.as_deref(),
        )?;
        return Ok(ValidatedSseRead::SseC {
            key,
            key_md5,
            key_md5_b64,
        });
    }
    Ok(ValidatedSseRead::None)
}

/// Validate `x-amz-copy-source-server-side-encryption-customer-*` headers.
pub fn validate_copy_source_sse(raw: &RawCopySourceSseHeaders) -> StoreResult<ValidatedSseRead> {
    if raw.has_any() {
        let (key, key_md5, key_md5_b64) = parse_and_verify_sse_c_triplet(
            raw.sse_customer_algorithm.as_deref(),
            raw.sse_customer_key_b64.as_deref(),
            raw.sse_customer_key_md5_b64.as_deref(),
        )?;
        return Ok(ValidatedSseRead::SseC {
            key,
            key_md5,
            key_md5_b64,
        });
    }
    Ok(ValidatedSseRead::None)
}

/// `(aes256_key, object_iv)` parameters for AES-256-CTR encryption/decryption.
pub type SseCipherParams = ([u8; 32], [u8; 16]);

/// Match a read/copy-source SSE request against stored object encryption metadata.
/// Returns `(Option<SseCipherParams>, SseResponseHeaders)`.
pub fn match_sse_for_stored_object(
    stored: &SseStoredMeta,
    read_req: &ValidatedSseRead,
    sse_s3_master_key: &[u8; 32],
) -> StoreResult<(Option<SseCipherParams>, SseResponseHeaders)> {
    match (stored, read_req) {
        (SseStoredMeta::None, ValidatedSseRead::None) => Ok((None, SseResponseHeaders::None)),
        (SseStoredMeta::None, ValidatedSseRead::SseC { .. }) => Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "The SSE-C key for encryption was provided, but the object is not encrypted with SSE-C.",
        )),
        (SseStoredMeta::SseS3 { iv }, ValidatedSseRead::None) => {
            Ok((Some((*sse_s3_master_key, *iv)), SseResponseHeaders::SseS3))
        }
        (SseStoredMeta::SseS3 { .. }, ValidatedSseRead::SseC { .. }) => Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "The object was stored using SSE-S3, not SSE-C.",
        )),
        (SseStoredMeta::SseC { .. }, ValidatedSseRead::None) => Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object.",
        )),
        (
            SseStoredMeta::SseC { key_md5, iv },
            ValidatedSseRead::SseC {
                key,
                key_md5: req_md5,
                key_md5_b64,
            },
        ) => {
            if !ct_eq_16(key_md5, req_md5) {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "The provided encryption key does not match the encryption key used to store the object.",
                ));
            }
            Ok((
                Some((*key, *iv)),
                SseResponseHeaders::SseC {
                    key_md5_b64: key_md5_b64.clone(),
                },
            ))
        }
    }
}

// ============================================================================
// Domain 3: Lifecycle (`PR-39` ~ `PR-40`)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleRuleStatus {
    Enabled,
    Disabled,
}

impl LifecycleRuleStatus {
    pub const fn as_aws_str(self) -> &'static str {
        match self {
            Self::Enabled => "Enabled",
            Self::Disabled => "Disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleFilter {
    /// `<Filter/>` or `<Filter></Filter>` (matches all objects in bucket)
    Empty,
    Prefix(String),
    Tag {
        key: String,
        value: String,
    },
    ObjectSizeGreaterThan(u64),
    ObjectSizeLessThan(u64),
    And {
        prefix: Option<String>,
        tags: Vec<(String, String)>,
        object_size_greater_than: Option<u64>,
        object_size_less_than: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleRuleScope {
    /// Legacy S3 Lifecycle v1 `<Prefix>...</Prefix>` directly under `<Rule>`
    LegacyPrefix(String),
    /// S3 Lifecycle v2 `<Filter>...</Filter>`
    Filter(LifecycleFilter),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LifecycleExpiration {
    pub days: Option<u32>,
    pub date_us: Option<i64>,
    pub expired_object_delete_marker: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoncurrentVersionExpiration {
    pub noncurrent_days: u32,
    pub newer_noncurrent_versions: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortIncompleteMultipartUpload {
    pub days_after_initiation: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleRule {
    pub id: String,
    pub status: LifecycleRuleStatus,
    pub scope: LifecycleRuleScope,
    pub expiration: Option<LifecycleExpiration>,
    pub noncurrent_version_expiration: Option<NoncurrentVersionExpiration>,
    pub abort_incomplete_multipart_upload: Option<AbortIncompleteMultipartUpload>,
}

impl LifecycleRule {
    pub fn matches_object(
        &self,
        key: &str,
        size: u64,
        tags: &BTreeMap<String, String>,
    ) -> bool {
        match &self.scope {
            LifecycleRuleScope::LegacyPrefix(pfx) => key.starts_with(pfx.as_str()),
            LifecycleRuleScope::Filter(flt) => match flt {
                LifecycleFilter::Empty => true,
                LifecycleFilter::Prefix(pfx) => key.starts_with(pfx.as_str()),
                LifecycleFilter::Tag { key: tk, value: tv } => {
                    tags.get(tk).is_some_and(|v| v == tv)
                }
                LifecycleFilter::ObjectSizeGreaterThan(min_sz) => size > *min_sz,
                LifecycleFilter::ObjectSizeLessThan(max_sz) => size < *max_sz,
                LifecycleFilter::And {
                    prefix,
                    tags: req_tags,
                    object_size_greater_than,
                    object_size_less_than,
                } => {
                    if let Some(pfx) = prefix
                        && !key.starts_with(pfx.as_str())
                    {
                        return false;
                    }
                    if let Some(min_sz) = object_size_greater_than
                        && size <= *min_sz
                    {
                        return false;
                    }
                    if let Some(max_sz) = object_size_less_than
                        && size >= *max_sz
                    {
                        return false;
                    }
                    req_tags
                        .iter()
                        .all(|(tk, tv)| tags.get(tk).is_some_and(|v| v == tv))
                }
            },
        }
    }

    /// Used for Delete Markers and Multipart Uploads (which do not have object tags or size).
    pub fn matches_key_without_tags_or_size(&self, key: &str) -> bool {
        match &self.scope {
            LifecycleRuleScope::LegacyPrefix(pfx) => key.starts_with(pfx.as_str()),
            LifecycleRuleScope::Filter(flt) => match flt {
                LifecycleFilter::Empty => true,
                LifecycleFilter::Prefix(pfx) => key.starts_with(pfx.as_str()),
                LifecycleFilter::Tag { .. }
                | LifecycleFilter::ObjectSizeGreaterThan(_)
                | LifecycleFilter::ObjectSizeLessThan(_) => false,
                LifecycleFilter::And {
                    prefix,
                    tags,
                    object_size_greater_than,
                    object_size_less_than,
                } => {
                    if !tags.is_empty()
                        || object_size_greater_than.is_some()
                        || object_size_less_than.is_some()
                    {
                        return false;
                    }
                    prefix.as_ref().is_none_or(|pfx| key.starts_with(pfx.as_str()))
                }
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LifecycleConfiguration {
    pub rules: Vec<LifecycleRule>,
}

/// Compute AWS S3 `x-amz-expiration` response header (`expiry-date="...", rule-id="..."`)
/// for a current non-delete-marker object version.
/// Always uses real 86400s UTC calendar days rounded up to next UTC midnight (`PR-40`).
pub fn compute_x_amz_expiration(
    cfg: Option<&LifecycleConfiguration>,
    key: &str,
    size: u64,
    tags: &BTreeMap<String, String>,
    last_modified_ms: i64,
) -> Option<String> {
    let cfg = cfg?;
    let created_sec = last_modified_ms.div_euclid(1000);
    let mut best: Option<(i64, &str)> = None;

    for rule in &cfg.rules {
        if rule.status != LifecycleRuleStatus::Enabled {
            continue;
        }
        let Some(exp) = &rule.expiration else {
            continue;
        };
        if !rule.matches_object(key, size, tags) {
            continue;
        }
        let candidate_sec = if let Some(days) = exp.days {
            (created_sec.div_euclid(86_400) + i64::from(days) + 1) * 86_400
        } else if let Some(date_us) = exp.date_us {
            date_us.div_euclid(US_PER_SEC)
        } else {
            continue;
        };

        if best.is_none_or(|(b_sec, _)| candidate_sec < b_sec) {
            best = Some((candidate_sec, rule.id.as_str()));
        }
    }

    let (expiry_sec, rule_id) = best?;
    let expiry_u64 = u64::try_from(expiry_sec.max(0)).unwrap_or(0);
    let http_date = httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(expiry_u64));
    let escaped_rule_id = rule_id.replace('\\', "\\\\").replace('"', "\\\"");
    Some(format!(
        "expiry-date=\"{http_date}\", rule-id=\"{escaped_rule_id}\""
    ))
}

// ============================================================================
// Domain 4: Bucket Logging (`?logging`)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionDateSource {
    EventTime,
    DeliveryTime,
}

impl PartitionDateSource {
    pub const fn as_aws_str(self) -> &'static str {
        match self {
            Self::EventTime => "EventTime",
            Self::DeliveryTime => "DeliveryTime",
        }
    }

    pub fn from_aws_str_exact(s: &str) -> Option<Self> {
        match s {
            "EventTime" => Some(Self::EventTime),
            "DeliveryTime" => Some(Self::DeliveryTime),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetObjectKeyFormat {
    SimplePrefix,
    PartitionedPrefix(PartitionDateSource),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingEnabled {
    pub target_bucket: String,
    pub target_prefix: String,
    pub target_grants: Vec<AclGrant>,
    pub target_object_key_format: Option<TargetObjectKeyFormat>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BucketLoggingStatus {
    pub logging_enabled: Option<LoggingEnabled>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_roundtrip_year_2140_and_microseconds() {
        let us = parse_iso8601_utc_us("2140-05-19T14:23:45.123456Z").unwrap();
        assert_eq!(format_iso8601_utc_us(us), "2140-05-19T14:23:45.123456Z");

        let midnight = parse_iso8601_utc_us("2030-01-01T00:00:00.000Z").unwrap();
        assert!(is_exact_utc_midnight_us(midnight));
        assert_eq!(format_iso8601_utc_us(midnight), "2030-01-01T00:00:00Z");

        let non_midnight = parse_iso8601_utc_us("1970-08-22T19:08:21Z").unwrap();
        assert!(!is_exact_utc_midnight_us(non_midnight));
    }
}
