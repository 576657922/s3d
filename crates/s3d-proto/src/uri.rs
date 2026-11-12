use s3d_types::{S3Error, S3ErrorCode, StoreResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3Target {
    ServiceRoot,
    Bucket { bucket: String },
    Object { bucket: String, key: String },
}

#[derive(Debug, Clone)]
pub struct ParsedUri {
    pub target: S3Target,
    /// Canonical URI path for SigV4 (`PR-6`): preserves `%2F` vs `/`, uppercases `%XX`, no dot normalization.
    pub canonical_uri: String,
    /// Raw query string (without leading `?`), preserved for SigV4 canonical query computation.
    pub raw_query: String,
    /// Decoded query key-value pairs in wire order.
    pub query: Vec<(String, String)>,
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// Percent-decode a slice once (`PR-3`: `+` stays literal `+` `0x2B`!).
pub fn percent_decode_once(raw: &str) -> StoreResult<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidURI,
                    "Couldn't parse the specified URI.",
                ));
            }
            let hi = hex_val(bytes[i + 1]).ok_or_else(|| {
                S3Error::new(S3ErrorCode::InvalidURI, "Couldn't parse the specified URI.")
            })?;
            let lo = hex_val(bytes[i + 2]).ok_or_else(|| {
                S3Error::new(S3ErrorCode::InvalidURI, "Couldn't parse the specified URI.")
            })?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| {
        S3Error::new(
            S3ErrorCode::InvalidURI,
            "Couldn't parse the specified URI.",
        )
    })
}

fn decode_uri_path_segment(raw: &str) -> StoreResult<String> {
    let s = percent_decode_once(raw)?;
    if s.chars().any(|c| ('\u{0080}'..='\u{009F}').contains(&c)) {
        return Err(S3Error::new(
            S3ErrorCode::InvalidURI,
            "Couldn't parse the specified URI.",
        ));
    }
    Ok(s)
}

/// Percent-decode query parameter (in query strings, S3 treats `%XX` via single decode; `+` in query params
/// is decoded as space per standard query parsing unless signed raw).
pub fn percent_decode_query_component(raw: &str) -> StoreResult<String> {
    let replaced = raw.replace('+', "%20");
    percent_decode_once(&replaced)
}

/// AWS SigV4 URI-encode bytes (`encode_slash = true` for query & copy-source, `false` for path).
pub fn aws_uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if is_unreserved(b) || (!encode_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Build SigV4 `CanonicalURI` for S3 (`PR-6`):
/// Do NOT normalize `.` / `..` / `//`, do NOT double-encode existing `%XX` (only uppercase hex),
/// and percent-encode any literal byte outside `unreserved` and `/`.
pub fn canonicalize_s3_uri_path(raw_path: &str) -> StoreResult<String> {
    if raw_path.is_empty() {
        return Ok("/".to_string());
    }
    let bytes = raw_path.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    if bytes[0] != b'/' {
        out.push('/');
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidURI,
                    "Couldn't parse the specified URI.",
                ));
            }
            let hi = hex_val(bytes[i + 1]).ok_or_else(|| {
                S3Error::new(S3ErrorCode::InvalidURI, "Couldn't parse the specified URI.")
            })?;
            let lo = hex_val(bytes[i + 2]).ok_or_else(|| {
                S3Error::new(S3ErrorCode::InvalidURI, "Couldn't parse the specified URI.")
            })?;
            let decoded = (hi << 4) | lo;
            if is_unreserved(decoded) {
                out.push(decoded as char);
            } else {
                out.push_str(&format!("%{decoded:02X}"));
            }
            i += 3;
        } else if is_unreserved(b) || b == b'/' {
            out.push(b as char);
            i += 1;
        } else {
            out.push_str(&format!("%{b:02X}"));
            i += 1;
        }
    }
    Ok(out)
}

/// Parse HTTP `Host` + request-target URI into `(S3Target, canonical_uri, query)` (`PR-1` ~ `PR-3`).
pub fn parse_s3_uri(
    host_header: Option<&str>,
    raw_uri: &str,
    base_domain: &str,
) -> StoreResult<ParsedUri> {
    let (raw_path, raw_query) = match raw_uri.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw_uri, ""),
    };

    let canonical_uri = canonicalize_s3_uri_path(raw_path)?;

    let mut query = Vec::new();
    if !raw_query.is_empty() {
        for pair in raw_query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (rk, rv) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            let k = percent_decode_query_component(rk)?;
            let v = percent_decode_query_component(rv)?;
            query.push((k, v));
        }
    }

    // Virtual-hosted style detection (`PR-2`)
    let vhost_bucket = if !base_domain.is_empty() {
        host_header
            .map(|h| h.split(':').next().unwrap_or(h).trim().to_ascii_lowercase())
            .and_then(|host| {
                let suffix = format!(".{}", base_domain.to_ascii_lowercase());
                host.strip_suffix(&suffix)
                    .filter(|b| !b.is_empty())
                    .map(|b| b.to_string())
            })
    } else {
        None
    };

    let target = if let Some(bucket) = vhost_bucket {
        let stripped = raw_path.strip_prefix('/').unwrap_or(raw_path);
        if stripped.is_empty() {
            S3Target::Bucket { bucket }
        } else {
            let key = decode_uri_path_segment(stripped)?;
            S3Target::Object { bucket, key }
        }
    } else {
        // Path-style (`PR-1`)
        let stripped = raw_path.strip_prefix('/').unwrap_or(raw_path);
        if stripped.is_empty() {
            S3Target::ServiceRoot
        } else {
            match stripped.split_once('/') {
                None => {
                    let bucket = decode_uri_path_segment(stripped)?;
                    S3Target::Bucket { bucket }
                }
                Some((raw_b, raw_k)) => {
                    let bucket = decode_uri_path_segment(raw_b)?;
                    if raw_k.is_empty() {
                        S3Target::Bucket { bucket }
                    } else {
                        let key = decode_uri_path_segment(raw_k)?;
                        S3Target::Object { bucket, key }
                    }
                }
            }
        }
    };

    Ok(ParsedUri {
        target,
        canonical_uri,
        raw_query: raw_query.to_string(),
        query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_decode_and_plus_literal_pr3() {
        let parsed = parse_s3_uri(
            Some("localhost:8000"),
            "/my-bkt/a//b/./..%2Fc+d%20e?list-type=2",
            "",
        )
        .unwrap();
        assert_eq!(
            parsed.target,
            S3Target::Object {
                bucket: "my-bkt".into(),
                key: "a//b/./../c+d e".into()
            }
        );
        assert_eq!(parsed.canonical_uri, "/my-bkt/a//b/./..%2Fc%2Bd%20e");
    }
}
