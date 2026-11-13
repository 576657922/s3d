use std::collections::{BTreeMap, HashSet};

use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use s3d_types::*;
use serde_json::Value;
use sha1::Sha1;

use crate::checksum::{validate_checksum_b64_format, ActiveHasher};
use crate::sigv4::{
    constant_time_eq_str, days_from_civil, days_in_month, hmac_sha256, parse_iso8601_compact_ms,
    SigV4Verifier,
};
use crate::xml::parse_tagging_xml;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
pub struct ParsedPostObject {
    pub caller: Option<OwnerInfo>,
    pub is_authenticated: bool,
    pub key: String,
    pub file_bytes: Bytes,
    pub sys_meta: SystemMeta,
    pub user_meta: Vec<(String, String)>,
    pub acl: Option<AclSpec>,
    pub tags: Option<BTreeMap<String, String>>,
    pub expected_checksum: Option<(ChecksumAlgorithm, String)>,
    pub success_redirect: Option<String>,
    pub success_status: u16,
    pub x_amz_acl_raw: Option<String>,
    pub raw_sse: RawSseHeaders,
    pub raw_lock: RawUploadObjectLockHeaders,
}

#[derive(Debug, Clone)]
enum PostCondition {
    Exact {
        field_lower: String,
        expected: String,
    },
    StartsWith {
        field_lower: String,
        prefix: String,
    },
    ContentLengthRange {
        min: u64,
        max: u64,
    },
}

fn invalid_policy_doc(msg: &str) -> S3Error {
    S3Error::new(S3ErrorCode::InvalidPolicyDocument, msg)
}

fn invalid_arg(msg: &str) -> S3Error {
    S3Error::new(S3ErrorCode::InvalidArgument, msg)
}

/// Extract `boundary` from `Content-Type: multipart/form-data; boundary=...`.
pub fn parse_multipart_boundary(content_type: &str) -> StoreResult<Vec<u8>> {
    let mut parts = content_type.split(';');
    let Some(mime) = parts.next() else {
        return Err(invalid_arg("Missing Content-Type"));
    };
    if !mime.trim().eq_ignore_ascii_case("multipart/form-data") {
        return Err(invalid_arg(
            "POST Content-Type must be multipart/form-data",
        ));
    }
    for param in parts {
        let param = param.trim();
        if let Some((k, v)) = param.split_once('=')
            && k.trim().eq_ignore_ascii_case("boundary") {
                let unquoted = v.trim().trim_matches('"');
                if !unquoted.is_empty() && unquoted.len() <= 200 {
                    return Ok(unquoted.as_bytes().to_vec());
                }
            }
    }
    Err(invalid_arg(
        "The Content-Type is missing a multipart boundary",
    ))
}

fn find_subslice(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from + needle.len() > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|pos| from + pos)
}

fn parse_disposition_params(val: &str) -> (Option<String>, Option<String>) {
    let mut name = None;
    let mut filename = None;
    let mut parts = val.split(';');
    let Some(disp_type) = parts.next() else {
        return (None, None);
    };
    if !disp_type.trim().eq_ignore_ascii_case("form-data") {
        return (None, None);
    }
    for raw_p in parts {
        let p = raw_p.trim();
        let Some((k, rv)) = p.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let v_trim = rv.trim();
        let val_str = if v_trim.len() >= 2 && v_trim.starts_with('"') && v_trim.ends_with('"') {
            v_trim[1..v_trim.len() - 1].to_string()
        } else {
            v_trim.to_string()
        };
        if key.eq_ignore_ascii_case("name") {
            name = Some(val_str);
        } else if key.eq_ignore_ascii_case("filename") {
            filename = Some(val_str);
        }
    }
    (name, filename)
}

type ParsedMultipartForm = (Vec<(String, String)>, String, Option<String>, Bytes);

/// Parse `multipart/form-data` up to and including the `name="file"` part (all parts after `file` are ignored).
fn parse_multipart_form(
    body: &Bytes,
    boundary: &[u8],
) -> StoreResult<ParsedMultipartForm> {
    let mut dash_boundary = Vec::with_capacity(2 + boundary.len());
    dash_boundary.extend_from_slice(b"--");
    dash_boundary.extend_from_slice(boundary);

    let bytes = body.as_ref();
    let Some(first_pos) = find_subslice(bytes, &dash_boundary, 0) else {
        return Err(invalid_arg("Malformed multipart/form-data body"));
    };
    let mut cursor = first_pos + dash_boundary.len();

    let mut fields: Vec<(String, String)> = Vec::new();
    let mut file_result: Option<(String, Option<String>, Bytes)> = None;

    loop {
        if cursor + 2 <= bytes.len() && &bytes[cursor..cursor + 2] == b"--" {
            break;
        }
        if cursor + 2 <= bytes.len() && &bytes[cursor..cursor + 2] == b"\r\n" {
            cursor += 2;
        } else if cursor < bytes.len() && bytes[cursor] == b'\n' {
            cursor += 1;
        } else {
            return Err(invalid_arg("Malformed multipart boundary line ending"));
        }

        // Find end of part headers (`\r\n\r\n` or `\n\n`)
        let (hdr_end, body_start) = if let Some(p) = find_subslice(bytes, b"\r\n\r\n", cursor) {
            (p, p + 4)
        } else if let Some(p) = find_subslice(bytes, b"\n\n", cursor) {
            (p, p + 2)
        } else {
            return Err(invalid_arg("Malformed multipart part headers"));
        };

        let hdr_str = std::str::from_utf8(&bytes[cursor..hdr_end])
            .map_err(|_| invalid_arg("Multipart headers must be valid UTF-8"))?;

        let mut part_name: Option<String> = None;
        let mut part_filename: Option<String> = None;
        let mut part_content_type: Option<String> = None;
        for line in hdr_str.lines() {
            let line = line.trim_end_matches('\r');
            if let Some((hk, hv)) = line.split_once(':') {
                let hk = hk.trim();
                let hv = hv.trim();
                if hk.eq_ignore_ascii_case("content-disposition") {
                    let (n, fnm) = parse_disposition_params(hv);
                    part_name = n;
                    part_filename = fnm;
                } else if hk.eq_ignore_ascii_case("content-type") && !hv.is_empty() {
                    part_content_type = Some(hv.to_string());
                }
            }
        }

        let Some(name) = part_name else {
            return Err(invalid_arg("Multipart form part missing name"));
        };

        // Find next `--<boundary>` preceded by `\r\n` or `\n`
        let Some(next_b) = find_subslice(bytes, &dash_boundary, body_start) else {
            return Err(invalid_arg("Missing closing multipart boundary"));
        };
        let part_body_end = if next_b >= body_start + 2 && &bytes[next_b - 2..next_b] == b"\r\n" {
            next_b - 2
        } else if next_b > body_start && bytes[next_b - 1] == b'\n' {
            next_b - 1
        } else {
            return Err(invalid_arg("Malformed multipart boundary delimiter"));
        };

        cursor = next_b + dash_boundary.len();

        if name.eq_ignore_ascii_case("file") {
            let file_bytes = body.slice(body_start..part_body_end);
            let filename = part_filename.unwrap_or_default();
            file_result = Some((filename, part_content_type, file_bytes));
            break; // Ignore all form parts after `file` per AWS S3 POST spec
        } else {
            let val_str = std::str::from_utf8(&bytes[body_start..part_body_end])
                .map_err(|_| invalid_arg("Form field value must be UTF-8"))?
                .to_string();
            fields.push((name, val_str));
        }
    }

    let Some((filename, part_ct, file_bytes)) = file_result else {
        return Err(invalid_arg(
            "POST requires exactly one file upload per request.",
        ));
    };
    Ok((fields, filename, part_ct, file_bytes))
}

/// Parse ISO-8601 UTC policy expiration `YYYY-MM-DDTHH:MM:SS[.sss...]Z` into epoch ms.
fn parse_policy_expiration_ms(s: &str) -> StoreResult<i64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last().unwrap() != b'Z'
    {
        return Err(invalid_policy_doc("Invalid Policy: Invalid 'expiration' date."));
    }
    let parse_i64 = |slice: &[u8]| -> StoreResult<i64> {
        let st = std::str::from_utf8(slice)
            .map_err(|_| invalid_policy_doc("Invalid Policy: Invalid 'expiration' date."))?;
        if !st.bytes().all(|c| c.is_ascii_digit()) {
            return Err(invalid_policy_doc("Invalid Policy: Invalid 'expiration' date."));
        }
        st.parse::<i64>()
            .map_err(|_| invalid_policy_doc("Invalid Policy: Invalid 'expiration' date."))
    };

    let year = parse_i64(&b[0..4])?;
    let month = parse_i64(&b[5..7])? as u32;
    let day = parse_i64(&b[8..10])? as u32;
    let hour = parse_i64(&b[11..13])?;
    let min = parse_i64(&b[14..16])?;
    let sec = parse_i64(&b[17..19])?;

    let frac_ms = if b.len() == 20 {
        0i64
    } else {
        if b[19] != b'.' || b.len() == 21 {
            return Err(invalid_policy_doc("Invalid Policy: Invalid 'expiration' date."));
        }
        let frac_bytes = &b[20..b.len() - 1];
        if !frac_bytes.iter().all(|c| c.is_ascii_digit()) {
            return Err(invalid_policy_doc("Invalid Policy: Invalid 'expiration' date."));
        }
        let mut ms = 0i64;
        for i in 0..3 {
            ms *= 10;
            if i < frac_bytes.len() {
                ms += (frac_bytes[i] - b'0') as i64;
            }
        }
        ms
    };

    if !(1..=12).contains(&month) {
        return Err(invalid_policy_doc("Invalid Policy: Invalid 'expiration' date."));
    }
    let max_d = days_in_month(year, month);
    if !(1..=max_d).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return Err(invalid_policy_doc("Invalid Policy: Invalid 'expiration' date."));
    }

    let days = days_from_civil(year, month, day);
    Ok((days * 86_400 + hour * 3600 + min * 60 + sec) * 1000 + frac_ms)
}

fn parse_post_policy_json(policy_b64: &str) -> StoreResult<(i64, Vec<PostCondition>)> {
    let decoded = B64_STD
        .decode(policy_b64.trim())
        .map_err(|_| invalid_policy_doc("Invalid Base64 encoding of policy."))?;
    let json_val: Value = serde_json::from_slice(&decoded)
        .map_err(|_| invalid_policy_doc("Invalid JSON in policy document."))?;
    let Value::Object(obj) = json_val else {
        return Err(invalid_policy_doc("Policy document must be a JSON object."));
    };

    for k in obj.keys() {
        if k != "expiration" && k != "conditions" {
            return Err(invalid_policy_doc(
                "Invalid Policy: Unexpected top-level key in policy.",
            ));
        }
    }
    let Some(Value::String(exp_str)) = obj.get("expiration") else {
        return Err(invalid_policy_doc(
            "Invalid Policy: Policy missing 'expiration'.",
        ));
    };
    let Some(Value::Array(cond_arr)) = obj.get("conditions") else {
        return Err(invalid_policy_doc(
            "Invalid Policy: Policy missing 'conditions'.",
        ));
    };

    let exp_ms = parse_policy_expiration_ms(exp_str)?;
    let mut conds = Vec::with_capacity(cond_arr.len());

    for item in cond_arr {
        match item {
            Value::Object(m) => {
                if m.len() != 1 {
                    return Err(invalid_policy_doc(
                        "Policy condition object must contain exactly one key-value pair.",
                    ));
                }
                let (k, v) = m.iter().next().unwrap();
                let Value::String(expected) = v else {
                    return Err(invalid_policy_doc(
                        "Policy condition value must be a string.",
                    ));
                };
                conds.push(PostCondition::Exact {
                    field_lower: k.to_ascii_lowercase(),
                    expected: expected.clone(),
                });
            }
            Value::Array(arr) => {
                if arr.len() != 3 {
                    return Err(invalid_policy_doc(
                        "Policy condition array must have exactly 3 elements.",
                    ));
                }
                let Some( op ) = arr[0].as_str() else {
                    return Err(invalid_policy_doc("Policy condition operator must be a string."));
                };
                if op.eq_ignore_ascii_case("content-length-range") {
                    let Some(min) = arr[1].as_u64() else {
                        return Err(invalid_policy_doc(
                            "content-length-range min must be a non-negative integer.",
                        ));
                    };
                    let Some(max) = arr[2].as_u64() else {
                        return Err(invalid_policy_doc(
                            "content-length-range max must be a non-negative integer.",
                        ));
                    };
                    if min > max {
                        return Err(invalid_policy_doc(
                            "content-length-range min cannot exceed max.",
                        ));
                    }
                    conds.push(PostCondition::ContentLengthRange { min, max });
                } else if op.eq_ignore_ascii_case("eq") || op.eq_ignore_ascii_case("starts-with") {
                    let Some(raw_f) = arr[1].as_str() else {
                        return Err(invalid_policy_doc("Condition field name must be a string."));
                    };
                    if !raw_f.starts_with('$') || raw_f.len() < 2 {
                        return Err(invalid_policy_doc(
                            "Condition field name must start with '$'.",
                        ));
                    }
                    let Some(expected) = arr[2].as_str() else {
                        return Err(invalid_policy_doc(
                            "Condition expected value must be a string.",
                        ));
                    };
                    let field_lower = raw_f[1..].to_ascii_lowercase();
                    if op.eq_ignore_ascii_case("starts-with")
                        && field_lower == "content-length-range"
                    {
                        return Err(invalid_policy_doc(
                            "$content-length-range does not support starts-with.",
                        ));
                    }
                    if op.eq_ignore_ascii_case("eq") {
                        conds.push(PostCondition::Exact {
                            field_lower,
                            expected: expected.to_string(),
                        });
                    } else {
                        conds.push(PostCondition::StartsWith {
                            field_lower,
                            prefix: expected.to_string(),
                        });
                    }
                } else {
                    return Err(invalid_policy_doc("Unknown policy condition operator."));
                }
            }
            _ => {
                return Err(invalid_policy_doc(
                    "Invalid condition entry in policy document.",
                ));
            }
        }
    }

    Ok((exp_ms, conds))
}

fn get_field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn is_exempt_post_field(field_lower: &str) -> bool {
    matches!(
        field_lower,
        "file"
            | "policy"
            | "signature"
            | "awsaccesskeyid"
            | "x-amz-signature"
            | "x-amz-algorithm"
            | "x-amz-credential"
            | "x-amz-date"
            | "x-amz-security-token"
    ) || field_lower.starts_with("x-ignore-")
        || field_lower.starts_with("x-amz-checksum-")
}

/// Parse and verify an HTML Form `PostObject` (`POST /{bucket}`) request (`FR-48` / P1).
pub fn parse_and_verify_post_object(
    verifier: &SigV4Verifier,
    bucket: &str,
    content_type_hdr: &str,
    body: Bytes,
    now_ms: i64,
) -> StoreResult<ParsedPostObject> {
    let boundary = parse_multipart_boundary(content_type_hdr)?;
    let (fields, filename, part_content_type, file_bytes) = parse_multipart_form(&body, &boundary)?;

    let policy_b64 = get_field(&fields, "policy");
    let sig_v2 = get_field(&fields, "signature");
    let ak_v2 = get_field(&fields, "AWSAccessKeyId");

    let sig_v4 = get_field(&fields, "x-amz-signature");
    let alg_v4 = get_field(&fields, "x-amz-algorithm");
    let cred_v4 = get_field(&fields, "x-amz-credential");
    let date_v4 = get_field(&fields, "x-amz-date");

    let has_any_v4 =
        sig_v4.is_some() || alg_v4.is_some() || cred_v4.is_some() || date_v4.is_some();
    let has_any_v2 = sig_v2.is_some() || ak_v2.is_some();

    let (caller, is_authenticated) = if !has_any_v4 && !has_any_v2 && policy_b64.is_none() {
        (None, false)
    } else if has_any_v4 {
        if has_any_v2 {
            return Err(invalid_arg(
                "Cannot mix SigV2 and SigV4 POST authentication fields.",
            ));
        }
        let (Some(pol), Some(alg), Some(cred), Some(amz_date), Some(sig_hex)) =
            (policy_b64, alg_v4, cred_v4, date_v4, sig_v4)
        else {
            return Err(invalid_arg(
                "Missing required SigV4 POST form fields (policy, x-amz-algorithm, x-amz-credential, x-amz-date, x-amz-signature).",
            ));
        };
        if !alg.eq_ignore_ascii_case("AWS4-HMAC-SHA256") {
            return Err(invalid_arg("Unsupported x-amz-algorithm for POST."));
        }
        let cred_parts: Vec<&str> = cred.split('/').collect();
        if cred_parts.len() != 5 || cred_parts[3] != "s3" || cred_parts[4] != "aws4_request" {
            return Err(invalid_arg("Malformed x-amz-credential in POST form."));
        }
        let (ak, date_ymd, region) = (cred_parts[0], cred_parts[1], cred_parts[2]);
        if date_ymd.len() != 8 || !date_ymd.bytes().all(|c| c.is_ascii_digit()) {
            return Err(invalid_arg("Invalid date in x-amz-credential."));
        }
        if region != verifier.region() {
            return Err(S3Error::new(
                S3ErrorCode::AuthorizationHeaderMalformed,
                "Wrong region in x-amz-credential.",
            ));
        }
        if parse_iso8601_compact_ms(amz_date).is_err() || !amz_date.starts_with(date_ymd) {
            return Err(invalid_arg("Invalid x-amz-date in POST form."));
        }
        let account = verifier.lookup_account(ak).ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::InvalidAccessKeyId,
                "The AWS Access Key Id you provided does not exist in our records.",
            )
        })?;
        let signing_key = verifier.derive_post_signing_key(account, date_ymd);
        let expected_hex = hex::encode(hmac_sha256(&signing_key, pol.trim().as_bytes()));
        if !constant_time_eq_str(&sig_hex.trim().to_ascii_lowercase(), &expected_hex) {
            return Err(S3Error::new(
                S3ErrorCode::SignatureDoesNotMatch,
                "The request signature we calculated does not match the signature you provided.",
            ));
        }
        (Some(account.owner.clone()), true)
    } else {
        let (Some(pol), Some(sig), Some(ak)) = (policy_b64, sig_v2, ak_v2) else {
            return Err(invalid_arg(
                "All three of policy, AWSAccessKeyId, and signature must be specified for authenticated POST.",
            ));
        };
        let account = verifier.lookup_account(ak).ok_or_else(|| {
            S3Error::new(
                S3ErrorCode::InvalidAccessKeyId,
                "The AWS Access Key Id you provided does not exist in our records.",
            )
        })?;
        let mut mac = HmacSha1::new_from_slice(account.secret_key.expose().as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(pol.trim().as_bytes());
        let expected_b64 = B64_STD.encode(mac.finalize().into_bytes());
        if !constant_time_eq_str(sig.trim(), &expected_b64) {
            return Err(S3Error::new(
                S3ErrorCode::SignatureDoesNotMatch,
                "The request signature we calculated does not match the signature you provided.",
            ));
        }
        (Some(account.owner.clone()), true)
    };

    // Validate policy JSON structure & expiration BEFORE missing-key check so malformed policies return 400 InvalidPolicyDocument
    let parsed_policy = if let Some(pol_str) = policy_b64 {
        let (exp_ms, conds) = parse_post_policy_json(pol_str)?;
        if now_ms > exp_ms {
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Invalid according to Policy: Policy expired.",
            ));
        }
        Some(conds)
    } else {
        None
    };

    // Resolve `key` (substituting `${filename}`)
    let raw_key = get_field(&fields, "key").ok_or_else(|| {
        invalid_arg("Bucket POST must contain a field named 'key'.")
    })?;
    let resolved_key = raw_key.replace("${filename}", &filename);
    if resolved_key.is_empty() {
        return Err(invalid_arg(
            "User key must have a length greater than 0.",
        ));
    }

    if let Some(form_bkt) = get_field(&fields, "bucket")
        && form_bkt != bucket {
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Invalid according to Policy: Policy Condition failed: bucket mismatch",
            ));
        }

    if let Some(conds) = parsed_policy {
        let mut covered_fields: HashSet<String> = HashSet::new();
        let mut has_bucket_cond = false;

        for cond in &conds {
            match cond {
                PostCondition::ContentLengthRange { min, max } => {
                    let flen = file_bytes.len() as u64;
                    if flen < *min {
                        return Err(S3Error::new(
                            S3ErrorCode::EntityTooSmall,
                            "Your proposed upload is smaller than the minimum allowed size",
                        ));
                    }
                    if flen > *max {
                        return Err(S3Error::new(
                            S3ErrorCode::EntityTooLarge,
                            "Your proposed upload exceeds the maximum allowed size",
                        ));
                    }
                }
                PostCondition::Exact {
                    field_lower,
                    expected,
                } => {
                    covered_fields.insert(field_lower.clone());
                    if field_lower == "bucket" {
                        has_bucket_cond = true;
                    }
                    let actual_opt = if field_lower == "bucket" {
                        Some(bucket)
                    } else if field_lower == "key" {
                        Some(resolved_key.as_str())
                    } else {
                        get_field(&fields, field_lower)
                    };
                    let Some(actual) = actual_opt else {
                        return Err(S3Error::new(
                            S3ErrorCode::AccessDenied,
                            "Invalid according to Policy: Policy Condition failed",
                        ));
                    };
                    if actual != expected {
                        return Err(S3Error::new(
                            S3ErrorCode::AccessDenied,
                            "Invalid according to Policy: Policy Condition failed",
                        ));
                    }
                }
                PostCondition::StartsWith {
                    field_lower,
                    prefix,
                } => {
                    covered_fields.insert(field_lower.clone());
                    if field_lower == "bucket" {
                        has_bucket_cond = true;
                    }
                    let actual_opt = if field_lower == "bucket" {
                        Some(bucket)
                    } else if field_lower == "key" {
                        Some(resolved_key.as_str())
                    } else {
                        get_field(&fields, field_lower)
                    };
                    let actual = actual_opt.unwrap_or("");
                    if !actual.starts_with(prefix) {
                        return Err(S3Error::new(
                            S3ErrorCode::AccessDenied,
                            "Invalid according to Policy: Policy Condition failed",
                        ));
                    }
                }
            }
        }

        if !has_bucket_cond {
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Invalid according to Policy: Extra input fields: bucket",
            ));
        }

        for (fname, _) in &fields {
            let fl = fname.to_ascii_lowercase();
            if !is_exempt_post_field(&fl) && !covered_fields.contains(&fl) {
                return Err(S3Error::new(
                    S3ErrorCode::AccessDenied,
                    format!("Invalid according to Policy: Extra input fields: {fname}"),
                ));
            }
        }
    }

    // Extract ACL
    let mut acl = None;
    let mut x_amz_acl_raw = None;
    if let Some(acl_str) = get_field(&fields, "acl") {
        let canned = CannedAcl::from_aws_str(acl_str)
            .ok_or_else(|| invalid_arg("Invalid canned ACL in POST form."))?;
        acl = Some(AclSpec::Canned(canned));
        x_amz_acl_raw = Some(acl_str.trim().to_string());
    }

    // Extract SystemMeta & UserMeta
    if let Some(sc) = get_field(&fields, "x-amz-storage-class")
        && sc.trim() != "STANDARD" {
            return Err(S3Error::new(
                S3ErrorCode::InvalidStorageClass,
                "The storage class you specified is not valid",
            ));
        }
    let sys_meta = SystemMeta {
        content_type: get_field(&fields, "content-type")
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or(part_content_type)
            .unwrap_or_else(|| "binary/octet-stream".to_string()),
        cache_control: get_field(&fields, "cache-control").map(str::to_string),
        content_disposition: get_field(&fields, "content-disposition").map(str::to_string),
        content_encoding: get_field(&fields, "content-encoding").map(str::to_string),
        content_language: get_field(&fields, "content-language").map(str::to_string),
        expires: get_field(&fields, "expires").map(str::to_string),
    };

    let mut user_meta = Vec::new();
    let mut meta_bytes = 0usize;
    for (fname, fval) in &fields {
        if fname.len() > 11
            && fname
                .get(..11)
                .is_some_and(|p| p.eq_ignore_ascii_case("x-amz-meta-"))
        {
            let mk = fname[11..].to_ascii_lowercase();
            meta_bytes += mk.len() + fval.len();
            if meta_bytes > MAX_USER_METADATA_BYTES {
                return Err(S3Error::new(
                    S3ErrorCode::MetadataTooLarge,
                    "Your metadata headers exceed the maximum allowed metadata size",
                ));
            }
            user_meta.push((mk, fval.clone()));
        }
    }

    // Extract Tagging XML
    let tags = match get_field(&fields, "tagging") {
        Some(tag_xml) => Some(parse_tagging_xml(tag_xml.as_bytes(), MAX_OBJECT_TAGS)?),
        None => None,
    };

    // Verify Content-MD5 if provided
    if let Some(md5_b64) = get_field(&fields, "content-md5") {
        let raw = B64_STD.decode(md5_b64.trim()).map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidDigest,
                "The Content-MD5 you specified is not valid.",
            )
        })?;
        let expected: [u8; 16] = raw.try_into().map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidDigest,
                "The Content-MD5 you specified is not valid.",
            )
        })?;
        let actual: [u8; 16] = Md5::digest(&file_bytes).into();
        if actual != expected {
            return Err(S3Error::new(
                S3ErrorCode::BadDigest,
                "The Content-MD5 you specified did not match what we received.",
            ));
        }
    }

    // Verify x-amz-checksum-* if provided (all P0 + P2 algorithms per PR-20)
    let mut expected_checksum: Option<(ChecksumAlgorithm, String)> = None;
    for alg in ChecksumAlgorithm::ALL {
        let hdr = alg.header_name();
        if let Some(val_str) = get_field(&fields, hdr) {
            if expected_checksum.is_some() {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "Multiple checksum algorithms cannot be specified.",
                ));
            }
            let trimmed = val_str.trim();
            validate_checksum_b64_format(alg, trimmed)?;
            let mut hasher = ActiveHasher::new(alg);
            hasher.update(&file_bytes);
            let actual_b64 = hasher.finalize_b64();
            if trimmed != actual_b64 {
                return Err(S3Error::new(
                    S3ErrorCode::BadDigest,
                    "The checksum you specified did not match what we received.",
                ));
            }
            expected_checksum = Some((alg, actual_b64));
        }
    }

    let success_redirect = get_field(&fields, "success_action_redirect")
        .or_else(|| get_field(&fields, "redirect"))
        .map(str::trim)
        .filter(|u| {
            let lower = u.to_ascii_lowercase();
            lower.starts_with("http://") || lower.starts_with("https://")
        })
        .map(str::to_string);

    let success_status = match get_field(&fields, "success_action_status").map(str::trim) {
        Some("200") => 200,
        Some("201") => 201,
        _ => 204,
    };

    let raw_sse = RawSseHeaders {
        sse_algorithm: get_field(&fields, "x-amz-server-side-encryption").map(str::to_string),
        sse_kms_key_id: get_field(&fields, "x-amz-server-side-encryption-aws-kms-key-id")
            .map(str::to_string),
        sse_customer_algorithm: get_field(&fields, "x-amz-server-side-encryption-customer-algorithm")
            .map(str::to_string),
        sse_customer_key_b64: get_field(&fields, "x-amz-server-side-encryption-customer-key")
            .map(str::to_string),
        sse_customer_key_md5_b64: get_field(
            &fields,
            "x-amz-server-side-encryption-customer-key-md5",
        )
        .map(str::to_string),
    };
    let raw_lock = RawUploadObjectLockHeaders {
        mode: get_field(&fields, "x-amz-object-lock-mode").map(str::to_string),
        retain_until_date: get_field(&fields, "x-amz-object-lock-retain-until-date")
            .map(str::to_string),
        legal_hold: get_field(&fields, "x-amz-object-lock-legal-hold").map(str::to_string),
    };

    Ok(ParsedPostObject {
        caller,
        is_authenticated,
        key: resolved_key,
        file_bytes,
        sys_meta,
        user_meta,
        acl,
        tags,
        expected_checksum,
        success_redirect,
        success_status,
        x_amz_acl_raw,
        raw_sse,
        raw_lock,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigv4::SigV4Verifier;
    use s3d_types::{AccountRecord, OwnerInfo};

    #[test]
    fn post_object_multibyte_utf8_field_name_across_byte_11_does_not_panic() {
        let verifier = SigV4Verifier::new(
            "us-east-1",
            vec![AccountRecord {
                owner: OwnerInfo {
                    user_id: "u1".into(),
                    display_name: "u1".into(),
                    email: "u1@example.com".into(),
                },
                access_key: "AKIA0000000000000001".into(),
                secret_key: s3d_types::SecretKey::new("secret0000000000000000000000000000000001"),
            }],
        );
        // '\u{0494}' ('Ӕ') is 2 bytes in UTF-8, placed at bytes 10..12 so index 11 is mid-codepoint!
        let body = concat!(
            "--BOUND\r\n",
            "Content-Disposition: form-data; name=\"key\"\r\n\r\n",
            "hello.txt\r\n",
            "--BOUND\r\n",
            "Content-Disposition: form-data; name=\"0123456789\u{0494}tail\"\r\n\r\n",
            "val\r\n",
            "--BOUND\r\n",
            "Content-Disposition: form-data; name=\"X-Amz-Meta-\u{0494}k\"\r\n\r\n",
            "meta-val\r\n",
            "--BOUND\r\n",
            "Content-Disposition: form-data; name=\"file\"; filename=\"hello.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "payload\r\n",
            "--BOUND--\r\n",
        );
        let parsed = parse_and_verify_post_object(
            &verifier,
            "bkt",
            "multipart/form-data; boundary=BOUND",
            Bytes::from_static(body.as_bytes()),
            1_794_441_600_000,
        )
        .unwrap();
        assert_eq!(parsed.key, "hello.txt");
        assert_eq!(parsed.user_meta, vec![("\u{0494}k".to_string(), "meta-val".to_string())]);
    }
}
