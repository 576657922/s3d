use serde::{Deserialize, Serialize};

use crate::error::{S3Error, S3ErrorCode, StoreResult};

pub const MAX_CORS_RULES: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsRule {
    pub id: Option<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CorsConfiguration {
    pub rules: Vec<CorsRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsResponseHeaders {
    pub allow_origin: String,
    pub allow_credentials: bool,
    pub allow_methods: String,
    pub allow_headers: Option<String>,
    pub expose_headers: Option<String>,
    pub max_age_seconds: Option<u32>,
}

impl CorsConfiguration {
    pub fn validate(&self) -> StoreResult<()> {
        if self.rules.is_empty() || self.rules.len() > MAX_CORS_RULES {
            return Err(S3Error::new(
                S3ErrorCode::MalformedXML,
                "CORSConfiguration must contain between 1 and 100 CORSRules",
            ));
        }
        for rule in &self.rules {
            if let Some(id) = &rule.id
                && id.chars().count() > 255 {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidRequest,
                        "Rule ID cannot exceed 255 characters",
                    ));
                }
            if rule.allowed_origins.is_empty() || rule.allowed_methods.is_empty() {
                return Err(S3Error::new(
                    S3ErrorCode::MalformedXML,
                    "CORSRule requires at least one AllowedOrigin and AllowedMethod",
                ));
            }
            for o in &rule.allowed_origins {
                if o.matches('*').count() > 1 {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidRequest,
                        "AllowedOrigin can not have more than one wildcard.",
                    ));
                }
            }
            for h in &rule.allowed_headers {
                if h.matches('*').count() > 1 {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidRequest,
                        "AllowedHeader can not have more than one wildcard.",
                    ));
                }
            }
            for m in &rule.allowed_methods {
                if !is_valid_cors_method(m) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidRequest,
                        format!("Found unsupported HTTP method in CORS config. Unsupported method is {m}"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Evaluate `OPTIONS` preflight request (`Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers`).
    pub fn match_preflight(
        &self,
        origin: &str,
        req_method: &str,
        req_headers: &[String],
    ) -> Option<CorsResponseHeaders> {
        let method_upper = req_method.trim().to_ascii_uppercase();
        for rule in &self.rules {
            let Some(matched_origin_pat) = rule
                .allowed_origins
                .iter()
                .find(|pat| match_single_wildcard(pat, origin, false))
            else {
                continue;
            };

            if !rule
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&method_upper))
            {
                continue;
            }

            // Every requested header must match at least one AllowedHeader (case-insensitive)
            let all_hdrs_ok = req_headers.iter().all(|rh| {
                let rh_trim = rh.trim();
                rh_trim.is_empty()
                    || rule
                        .allowed_headers
                        .iter()
                        .any(|ah| match_single_wildcard(ah, rh_trim, true))
            });
            if !all_hdrs_ok {
                continue;
            }

            let is_literal_star = matched_origin_pat == "*";
            let allow_origin = if is_literal_star {
                "*".to_string()
            } else {
                origin.to_string()
            };
            let allow_headers = if req_headers.is_empty() {
                None
            } else {
                Some(
                    req_headers
                        .iter()
                        .map(|h| h.trim().to_ascii_lowercase())
                        .filter(|h| !h.is_empty())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            };
            let expose_headers = if rule.expose_headers.is_empty() {
                None
            } else {
                Some(rule.expose_headers.join(", "))
            };
            return Some(CorsResponseHeaders {
                allow_origin,
                allow_credentials: !is_literal_star,
                allow_methods: rule.allowed_methods.join(", "),
                allow_headers,
                expose_headers,
                max_age_seconds: rule.max_age_seconds,
            });
        }
        None
    }

    /// Evaluate normal S3 request carrying an `Origin` header.
    /// Per AWS/RGW CORS behavior (`test_s3.py:6961-6970`), if `Access-Control-Request-Method` is
    /// present on a normal request, match against it; otherwise match against the HTTP method.
    pub fn match_origin_request(
        &self,
        origin: &str,
        effective_method: &str,
    ) -> Option<CorsResponseHeaders> {
        let method_upper = effective_method.trim().to_ascii_uppercase();
        for rule in &self.rules {
            let Some(matched_origin_pat) = rule
                .allowed_origins
                .iter()
                .find(|pat| match_single_wildcard(pat, origin, false))
            else {
                continue;
            };
            if !rule
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&method_upper))
            {
                continue;
            }
            let is_literal_star = matched_origin_pat == "*";
            let allow_origin = if is_literal_star {
                "*".to_string()
            } else {
                origin.to_string()
            };
            let expose_headers = if rule.expose_headers.is_empty() {
                None
            } else {
                Some(rule.expose_headers.join(", "))
            };
            return Some(CorsResponseHeaders {
                allow_origin,
                allow_credentials: !is_literal_star,
                allow_methods: rule.allowed_methods.join(", "),
                allow_headers: None,
                expose_headers,
                max_age_seconds: rule.max_age_seconds,
            });
        }
        None
    }
}

pub fn is_valid_cors_method(m: &str) -> bool {
    matches!(m, "GET" | "PUT" | "HEAD" | "POST" | "DELETE")
}

/// Match pattern containing at most one `*` (0+ chars).
pub fn match_single_wildcard(pattern: &str, candidate: &str, ignore_case: bool) -> bool {
    if pattern == "*" {
        return true;
    }
    let (p, c) = if ignore_case {
        (
            pattern.to_ascii_lowercase(),
            candidate.to_ascii_lowercase(),
        )
    } else {
        (pattern.to_string(), candidate.to_string())
    };
    if let Some((prefix, suffix)) = p.split_once('*') {
        c.len() >= prefix.len() + suffix.len() && c.starts_with(prefix) && c.ends_with(suffix)
    } else {
        c == p
    }
}
