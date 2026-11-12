use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{S3Error, S3ErrorCode, StoreResult};

pub const MAX_BUCKET_TAGS: usize = 50;
pub const MAX_OBJECT_TAGS: usize = 10;
pub const MAX_TAG_KEY_CHARS: usize = 128;
pub const MAX_TAG_VALUE_CHARS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TaggingDirective {
    #[default]
    Copy,
    Replace,
}

impl TaggingDirective {
    pub fn from_aws_str(raw: &str) -> StoreResult<Self> {
        match raw.trim() {
            "COPY" => Ok(Self::Copy),
            "REPLACE" => Ok(Self::Replace),
            _ => Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Unknown tagging directive specified.",
            )),
        }
    }
}

fn is_valid_tag_char(c: char) -> bool {
    c.is_alphanumeric()
        || c.is_whitespace()
        || matches!(c, '+' | '-' | '=' | '.' | '_' | ':' | '/' | '@')
}

/// Validate a tag set (bucket max 50, object max 10, key 1..=128, val 0..=256, unique keys)
/// and return an ordered `BTreeMap<String, String>`.
pub fn validate_tags(
    raw: &[(String, String)],
    max_tags: usize,
) -> StoreResult<BTreeMap<String, String>> {
    if raw.len() > max_tags {
        return Err(S3Error::new(
            S3ErrorCode::InvalidTag,
            "Object tags cannot be greater than allowed limit",
        ));
    }
    let mut out = BTreeMap::new();
    for (k, v) in raw {
        let k_len = k.chars().count();
        let v_len = v.chars().count();
        if k_len == 0 || k_len > MAX_TAG_KEY_CHARS {
            return Err(S3Error::new(
                S3ErrorCode::InvalidTag,
                "The TagKey you have provided is invalid",
            ));
        }
        if v_len > MAX_TAG_VALUE_CHARS {
            return Err(S3Error::new(
                S3ErrorCode::InvalidTag,
                "The TagValue you have provided is invalid",
            ));
        }
        if k.starts_with("aws:") {
            return Err(S3Error::new(
                S3ErrorCode::InvalidTag,
                "System tags prefixed with 'aws:' cannot be added or modified by a user",
            ));
        }
        if !k.chars().all(is_valid_tag_char) || !v.chars().all(is_valid_tag_char) {
            return Err(S3Error::new(
                S3ErrorCode::InvalidTag,
                "The TagKey or TagValue contains invalid characters",
            ));
        }
        if out.insert(k.clone(), v.clone()).is_some() {
            return Err(S3Error::new(
                S3ErrorCode::InvalidTag,
                "Cannot provide multiple Tags with the same key",
            ));
        }
    }
    Ok(out)
}
