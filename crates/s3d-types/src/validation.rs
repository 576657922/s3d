use crate::error::{S3Error, S3ErrorCode, StoreResult};

pub const MAX_KEY_BYTES: usize = 1024;
pub const MAX_USER_METADATA_BYTES: usize = 2048;
pub const MAX_SINGLE_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB
pub const MAX_PART_SIZE_BYTES: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB
pub const MIN_PART_SIZE_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB
pub const MAX_PART_NUMBER: u32 = 10_000;
pub const MAX_PARTS_COUNT: u32 = 10_000;
pub const DEFAULT_MAX_OBJECT_SIZE: u64 = 50_000_000_000_000; // ~48.8 TiB / 50 TB
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = DEFAULT_MAX_OBJECT_SIZE;
pub const MAX_MULTIPART_OBJECT_BYTES: u64 = DEFAULT_MAX_OBJECT_SIZE;

const RESERVED_BUCKET_PREFIXES: &[&str] = &["xn--", "sthree-", "amzn-s3-demo-"];
const RESERVED_BUCKET_SUFFIXES: &[&str] = &[
    "-s3alias",
    "--ol-s3",
    ".mrap",
    "--x-s3",
    "--table-s3",
    "-an",
];

/// Validate general-purpose S3 bucket naming rules (Section 7, FR-48).
pub fn validate_bucket_name(name: &str) -> StoreResult<()> {
    let len = name.len();
    if !(3..=63).contains(&len) {
        return Err(S3Error::new(
            S3ErrorCode::InvalidBucketName,
            "Bucket name must be between 3 and 63 characters long.",
        )
        .with_bucket(name));
    }

    let bytes = name.as_bytes();
    let is_lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();

    if !is_lower_alnum(bytes[0]) || !is_lower_alnum(bytes[len - 1]) {
        return Err(S3Error::new(
            S3ErrorCode::InvalidBucketName,
            "Bucket name must begin and end with a lowercase letter or number.",
        )
        .with_bucket(name));
    }

    let mut prev_dot = false;
    for &b in bytes {
        if !(is_lower_alnum(b) || b == b'.' || b == b'-') {
            return Err(S3Error::new(
                S3ErrorCode::InvalidBucketName,
                "Bucket name contains invalid characters.",
            )
            .with_bucket(name));
        }
        if b == b'.' {
            if prev_dot {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidBucketName,
                    "Bucket name must not contain two adjacent periods.",
                )
                .with_bucket(name));
            }
            prev_dot = true;
        } else {
            prev_dot = false;
        }
    }

    // Must not be formatted as an IPv4 address (e.g., 192.168.5.4)
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(S3Error::new(
            S3ErrorCode::InvalidBucketName,
            "Bucket name must not be formatted as an IP address.",
        )
        .with_bucket(name));
    }

    for prefix in RESERVED_BUCKET_PREFIXES {
        if name.starts_with(prefix) {
            return Err(S3Error::new(
                S3ErrorCode::InvalidBucketName,
                format!("Bucket name must not start with reserved prefix '{prefix}'."),
            )
            .with_bucket(name));
        }
    }

    for suffix in RESERVED_BUCKET_SUFFIXES {
        if name.ends_with(suffix) {
            return Err(S3Error::new(
                S3ErrorCode::InvalidBucketName,
                format!("Bucket name must not end with reserved suffix '{suffix}'."),
            )
            .with_bucket(name));
        }
    }

    Ok(())
}

/// Validate object key length (Section 7: <= 1024 UTF-8 bytes, non-empty).
pub fn validate_object_key(bucket: &str, key: &str) -> StoreResult<()> {
    if key.is_empty() {
        return Err(
            S3Error::new(S3ErrorCode::InvalidArgument, "Object key cannot be empty.")
                .with_bucket(bucket),
        );
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(S3Error::new(
            S3ErrorCode::KeyTooLongError,
            "Your key is too long.",
        )
        .with_key(bucket, key));
    }
    Ok(())
}

/// Validate user metadata `x-amz-meta-*` key-value UTF-8 byte sum <= 2048 (FR-3).
/// Keys passed here should already have `x-amz-meta-` stripped and be lowercased.
pub fn validate_user_metadata(meta: &[(String, String)]) -> StoreResult<()> {
    let total: usize = meta.iter().map(|(k, v)| k.len() + v.len()).sum();
    if total > MAX_USER_METADATA_BYTES {
        return Err(S3Error::new(
            S3ErrorCode::MetadataTooLarge,
            "Your metadata headers exceed the maximum allowed metadata size.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_name_rules() {
        assert!(validate_bucket_name("my-valid.bucket-01").is_ok());
        assert!(validate_bucket_name("abc").is_ok());
        assert!(validate_bucket_name("ab").is_err());
        assert!(validate_bucket_name(&"a".repeat(64)).is_err());
        assert!(validate_bucket_name("MyBucket").is_err());
        assert!(validate_bucket_name("-abc").is_err());
        assert!(validate_bucket_name("abc-").is_err());
        assert!(validate_bucket_name("a..b").is_err());
        assert!(validate_bucket_name("192.168.1.1").is_err());
        assert!(validate_bucket_name("xn--punycode").is_err());
        assert!(validate_bucket_name("sthree-test").is_err());
        assert!(validate_bucket_name("amzn-s3-demo-test").is_err());
        assert!(validate_bucket_name("my-bucket-s3alias").is_err());
        assert!(validate_bucket_name("my-bucket--x-s3").is_err());
        assert!(validate_bucket_name("my-bucket-an").is_err());
    }

    #[test]
    fn key_and_metadata_limits() {
        assert!(validate_object_key("b", &"k".repeat(1024)).is_ok());
        assert_eq!(
            validate_object_key("b", &"k".repeat(1025)).unwrap_err().code,
            S3ErrorCode::KeyTooLongError
        );
        assert!(validate_user_metadata(&[("a".repeat(1000), "b".repeat(1048))]).is_ok());
        assert_eq!(
            validate_user_metadata(&[("a".repeat(1000), "b".repeat(1049))])
                .unwrap_err()
                .code,
            S3ErrorCode::MetadataTooLarge
        );
    }
}
