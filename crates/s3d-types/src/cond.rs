use crate::error::{S3Error, S3ErrorCode, StoreResult};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preconditions {
    pub if_match: Option<Vec<String>>,
    pub if_none_match: Option<Vec<String>>,
    pub if_modified_since_sec: Option<i64>,
    pub if_unmodified_since_sec: Option<i64>,
}

impl Preconditions {
    pub fn is_empty(&self) -> bool {
        self.if_match.is_none()
            && self.if_none_match.is_none()
            && self.if_modified_since_sec.is_none()
            && self.if_unmodified_since_sec.is_none()
    }
}

fn normalize_etag(tag: &str) -> &str {
    let t = tag.trim();
    let t = t.strip_prefix("W/").unwrap_or(t).trim();
    t.trim_matches('"')
}

fn etag_list_matches(list: &[String], current_etag: &str) -> bool {
    let cur = normalize_etag(current_etag);
    list.iter()
        .any(|item| item.trim() == "*" || normalize_etag(item) == cur)
}

/// Evaluate conditional read headers (`GET` / `HEAD`) per FR-12 & FR-13.
/// Returns `Ok(())` to proceed with 200/206, or `Err(PreconditionFailed | NotModified)`.
pub fn evaluate_read_preconditions(
    cond: &Preconditions,
    current_etag: &str,
    last_modified_ms: i64,
    last_modified_http: &str,
) -> StoreResult<()> {
    let obj_sec = last_modified_ms.div_euclid(1000);

    // Step 1 & 2: If-Match overrides If-Unmodified-Since when If-Match succeeds (FR-13).
    if let Some(if_match) = &cond.if_match {
        if !etag_list_matches(if_match, current_etag) {
            return Err(S3Error::new(
                S3ErrorCode::PreconditionFailed,
                "At least one of the pre-conditions you specified did not hold",
            ));
        }
    } else if let Some(unmod_sec) = cond.if_unmodified_since_sec
        && obj_sec > unmod_sec {
            return Err(S3Error::new(
                S3ErrorCode::PreconditionFailed,
                "At least one of the pre-conditions you specified did not hold",
            ));
        }

    // Step 3 & 4: If-None-Match takes precedence over If-Modified-Since (FR-13).
    if let Some(if_none_match) = &cond.if_none_match {
        if etag_list_matches(if_none_match, current_etag) {
            return Err(S3Error::new(S3ErrorCode::NotModified, "Not Modified")
                .with_header("ETag", current_etag.to_string())
                .with_header("Last-Modified", last_modified_http.to_string()));
        }
    } else if let Some(mod_sec) = cond.if_modified_since_sec
        && obj_sec <= mod_sec {
            return Err(S3Error::new(S3ErrorCode::NotModified, "Not Modified")
                .with_header("ETag", current_etag.to_string())
                .with_header("Last-Modified", last_modified_http.to_string()));
        }

    Ok(())
}

/// Evaluate copy-source preconditions (`x-amz-copy-source-if-*`) per FR-22 (all failures -> 412).
pub fn evaluate_copy_source_preconditions(
    cond: &Preconditions,
    current_etag: &str,
    last_modified_ms: i64,
) -> StoreResult<()> {
    match evaluate_read_preconditions(cond, current_etag, last_modified_ms, "") {
        Ok(()) => Ok(()),
        Err(_) => Err(S3Error::new(
            S3ErrorCode::PreconditionFailed,
            "At least one of the pre-conditions you specified did not hold",
        )),
    }
}

/// Current head state of a key at the commit point.
#[derive(Debug, Clone, Copy)]
pub enum HeadState<'a> {
    Absent,
    DeleteMarker,
    Present { etag: &'a str },
}

/// Evaluate conditional write (`PutObject` / `CompleteMultipartUpload`) at commit point (FR-15, FR-17).
pub fn evaluate_write_preconditions(
    cond: &Preconditions,
    bucket: &str,
    key: &str,
    head: HeadState<'_>,
) -> StoreResult<()> {
    if cond.if_match.is_some() && cond.if_none_match.is_some() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Cannot specify both If-Match and If-None-Match conditional headers.",
        )
        .with_key(bucket, key));
    }

    if let Some(if_none_match) = &cond.if_none_match
        && let HeadState::Present { etag } = head
            && etag_list_matches(if_none_match, etag) {
                return Err(S3Error::new(
                    S3ErrorCode::PreconditionFailed,
                    "At least one of the pre-conditions you specified did not hold",
                )
                .with_key(bucket, key));
            }

    if let Some(if_match) = &cond.if_match {
        match head {
            HeadState::Absent | HeadState::DeleteMarker => {
                return Err(S3Error::new(
                    S3ErrorCode::NoSuchKey,
                    "The specified key does not exist.",
                )
                .with_key(bucket, key));
            }
            HeadState::Present { etag } => {
                if !etag_list_matches(if_match, etag) {
                    return Err(S3Error::new(
                        S3ErrorCode::PreconditionFailed,
                        "At least one of the pre-conditions you specified did not hold",
                    )
                    .with_key(bucket, key));
                }
            }
        }
    }

    Ok(())
}

/// Evaluate conditional delete (`DeleteObject` / `DeleteObjects`) at commit point (FR-16).
pub fn evaluate_delete_preconditions(
    if_match: Option<&[String]>,
    bucket: &str,
    key: &str,
    head: HeadState<'_>,
) -> StoreResult<()> {
    let Some(if_match) = if_match else {
        return Ok(());
    };
    let is_star = if_match.len() == 1 && if_match[0].trim() == "*";
    match head {
        HeadState::Absent => Err(S3Error::new(
            S3ErrorCode::NoSuchKey,
            "The specified key does not exist.",
        )
        .with_key(bucket, key)),
        HeadState::DeleteMarker => {
            if is_star {
                // FR-16: When current version is a delete marker, If-Match: * -> 412
                Err(S3Error::new(
                    S3ErrorCode::PreconditionFailed,
                    "At least one of the pre-conditions you specified did not hold",
                )
                .with_key(bucket, key))
            } else {
                Err(S3Error::new(
                    S3ErrorCode::NoSuchKey,
                    "The specified key does not exist.",
                )
                .with_key(bucket, key))
            }
        }
        HeadState::Present { etag } => {
            if etag_list_matches(if_match, etag) {
                Ok(())
            } else {
                Err(S3Error::new(
                    S3ErrorCode::PreconditionFailed,
                    "At least one of the pre-conditions you specified did not hold",
                )
                .with_key(bucket, key))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr13_condition_combinations() {
        // If-Match true AND If-Unmodified-Since false -> 200 OK
        let cond = Preconditions {
            if_match: Some(vec!["\"abc\"".into()]),
            if_unmodified_since_sec: Some(100),
            ..Default::default()
        };
        assert!(evaluate_read_preconditions(&cond, "\"abc\"", 200_000, "Thu, 01 Jan 1970 00:03:20 GMT").is_ok());

        // If-None-Match false (ETag matched!) AND If-Modified-Since true -> 304 NotModified
        let cond2 = Preconditions {
            if_none_match: Some(vec!["\"abc\"".into()]),
            if_modified_since_sec: Some(100),
            ..Default::default()
        };
        assert_eq!(
            evaluate_read_preconditions(&cond2, "\"abc\"", 200_000, "Thu, 01 Jan 1970 00:03:20 GMT")
                .unwrap_err()
                .code,
            S3ErrorCode::NotModified
        );
    }
}
