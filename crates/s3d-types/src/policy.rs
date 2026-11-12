use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::acl::{AccessControlPolicy, AclPermission, AclSpec, CannedAcl};
use crate::error::{S3Error, S3ErrorCode, StoreResult};
use crate::store::{CallerContext, ObjectOwnership, OwnerInfo};

pub const MAX_BUCKET_POLICY_BYTES: usize = 20 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PublicAccessBlockConfig {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

/// Request-level condition context extracted from HTTP headers / socket address (`PR-30`).
#[derive(Debug, Clone, Default)]
pub struct RequestPolicyContext {
    pub source_ip: Option<IpAddr>,
    pub referer: Option<String>,
    pub x_amz_acl: Option<String>,
    pub x_amz_grant_full_control: Option<String>,
    pub x_amz_grant_read: Option<String>,
    pub x_amz_grant_write: Option<String>,
    pub x_amz_grant_read_acp: Option<String>,
    pub x_amz_grant_write_acp: Option<String>,
    /// Normalized `bucket/key` without leading `/` or `?versionId=...`.
    pub x_amz_copy_source: Option<String>,
    /// Present ONLY when `x-amz-metadata-directive` header was explicitly sent.
    pub x_amz_metadata_directive: Option<String>,
    pub x_amz_server_side_encryption: Option<String>,
    pub x_amz_sse_customer_algorithm: Option<String>,
}

/// Operation-specific condition keys combined with `RequestPolicyContext`.
#[derive(Debug, Clone, Default)]
pub struct PolicyEvalExtra<'a> {
    pub prefix: Option<&'a str>,
    pub delimiter: Option<&'a str>,
    pub existing_object_tags: Option<&'a BTreeMap<String, String>>,
    pub request_object_tags: Option<&'a BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Action {
    // Bucket actions
    ListBucket,
    ListBucketVersions,
    ListBucketMultipartUploads,
    GetBucketLocation,
    DeleteBucket,
    GetBucketVersioning,
    PutBucketVersioning,
    GetBucketAcl,
    PutBucketAcl,
    GetBucketPolicy,
    PutBucketPolicy,
    DeleteBucketPolicy,
    GetBucketPolicyStatus,
    GetBucketPublicAccessBlock,
    PutBucketPublicAccessBlock,
    GetBucketOwnershipControls,
    PutBucketOwnershipControls,
    GetBucketTagging,
    PutBucketTagging,
    GetBucketCORS,
    PutBucketCORS,
    // Object actions
    GetObject,
    GetObjectVersion,
    PutObject,
    DeleteObject,
    DeleteObjectVersion,
    AbortMultipartUpload,
    ListMultipartUploadParts,
    GetObjectAttributes,
    GetObjectVersionAttributes,
    GetObjectAcl,
    GetObjectVersionAcl,
    PutObjectAcl,
    PutObjectVersionAcl,
    GetObjectTagging,
    GetObjectVersionTagging,
    PutObjectTagging,
    PutObjectVersionTagging,
    DeleteObjectTagging,
    DeleteObjectVersionTagging,
}

impl S3Action {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListBucket => "s3:ListBucket",
            Self::ListBucketVersions => "s3:ListBucketVersions",
            Self::ListBucketMultipartUploads => "s3:ListBucketMultipartUploads",
            Self::GetBucketLocation => "s3:GetBucketLocation",
            Self::DeleteBucket => "s3:DeleteBucket",
            Self::GetBucketVersioning => "s3:GetBucketVersioning",
            Self::PutBucketVersioning => "s3:PutBucketVersioning",
            Self::GetBucketAcl => "s3:GetBucketAcl",
            Self::PutBucketAcl => "s3:PutBucketAcl",
            Self::GetBucketPolicy => "s3:GetBucketPolicy",
            Self::PutBucketPolicy => "s3:PutBucketPolicy",
            Self::DeleteBucketPolicy => "s3:DeleteBucketPolicy",
            Self::GetBucketPolicyStatus => "s3:GetBucketPolicyStatus",
            Self::GetBucketPublicAccessBlock => "s3:GetBucketPublicAccessBlock",
            Self::PutBucketPublicAccessBlock => "s3:PutBucketPublicAccessBlock",
            Self::GetBucketOwnershipControls => "s3:GetBucketOwnershipControls",
            Self::PutBucketOwnershipControls => "s3:PutBucketOwnershipControls",
            Self::GetBucketTagging => "s3:GetBucketTagging",
            Self::PutBucketTagging => "s3:PutBucketTagging",
            Self::GetBucketCORS => "s3:GetBucketCORS",
            Self::PutBucketCORS => "s3:PutBucketCORS",
            Self::GetObject => "s3:GetObject",
            Self::GetObjectVersion => "s3:GetObjectVersion",
            Self::PutObject => "s3:PutObject",
            Self::DeleteObject => "s3:DeleteObject",
            Self::DeleteObjectVersion => "s3:DeleteObjectVersion",
            Self::AbortMultipartUpload => "s3:AbortMultipartUpload",
            Self::ListMultipartUploadParts => "s3:ListMultipartUploadParts",
            Self::GetObjectAttributes => "s3:GetObjectAttributes",
            Self::GetObjectVersionAttributes => "s3:GetObjectVersionAttributes",
            Self::GetObjectAcl => "s3:GetObjectAcl",
            Self::GetObjectVersionAcl => "s3:GetObjectVersionAcl",
            Self::PutObjectAcl => "s3:PutObjectAcl",
            Self::PutObjectVersionAcl => "s3:PutObjectVersionAcl",
            Self::GetObjectTagging => "s3:GetObjectTagging",
            Self::GetObjectVersionTagging => "s3:GetObjectVersionTagging",
            Self::PutObjectTagging => "s3:PutObjectTagging",
            Self::PutObjectVersionTagging => "s3:PutObjectVersionTagging",
            Self::DeleteObjectTagging => "s3:DeleteObjectTagging",
            Self::DeleteObjectVersionTagging => "s3:DeleteObjectVersionTagging",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrincipalEntry {
    Any,
    Aws(String),
    CanonicalUser(String),
    Service(String),
}

impl PrincipalEntry {
    fn matches(&self, caller: Option<&OwnerInfo>, is_authenticated: bool) -> bool {
        match self {
            Self::Any => true,
            Self::CanonicalUser(uid) => {
                is_authenticated && caller.is_some_and(|c| c.user_id == *uid)
            }
            Self::Aws(spec) => {
                if spec == "*" {
                    return true;
                }
                if !is_authenticated {
                    return false;
                }
                let Some(c) = caller else { return false };
                if c.user_id == *spec {
                    return true;
                }
                // Match IAM ARNs such as `arn:aws:iam::<account>:root` or `arn:aws:iam::<account>:user/<name>`
                if let Some(rest) = spec.strip_prefix("arn:aws:iam::") {
                    if let Some((acct, suffix)) = rest.split_once(':') {
                        if acct == c.user_id {
                            return true;
                        }
                        if let Some(uname) = suffix.strip_prefix("user/") {
                            if uname == c.user_id || uname == c.display_name {
                                return true;
                            }
                        }
                    }
                }
                false
            }
            Self::Service(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConditionBaseOp {
    StringEquals,
    StringNotEquals,
    StringEqualsIgnoreCase,
    StringNotEqualsIgnoreCase,
    StringLike,
    StringNotLike,
    NumericEquals,
    NumericNotEquals,
    NumericLessThan,
    NumericLessThanEquals,
    NumericGreaterThan,
    NumericGreaterThanEquals,
    Bool,
    Null,
    IpAddress,
    NotIpAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConditionClause {
    op: ConditionBaseOp,
    if_exists: bool,
    key_lower: String,
    raw_key: String,
    expected_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyStatement {
    effect: PolicyEffect,
    is_not_principal: bool,
    principals: Vec<PrincipalEntry>,
    is_not_action: bool,
    actions: Vec<String>,
    is_not_resource: bool,
    resources: Vec<String>,
    conditions: Vec<ConditionClause>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketPolicyDoc {
    raw_json: String,
    statements: Vec<PolicyStatement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    ExplicitDeny,
    ExplicitAllow { via_public_statement: bool },
    ImplicitDeny,
}

impl BucketPolicyDoc {
    pub fn raw_json(&self) -> &str {
        &self.raw_json
    }

    pub fn parse_and_validate(raw_json: &str, bucket_name: &str) -> StoreResult<Self> {
        if raw_json.len() > MAX_BUCKET_POLICY_BYTES {
            return Err(malformed_policy("Bucket policy exceeds maximum size of 20 KiB"));
        }
        let root: Value = serde_json::from_str(raw_json)
            .map_err(|e| malformed_policy(format!("Invalid policy JSON: {e}")))?;
        let obj = root
            .as_object()
            .ok_or_else(|| malformed_policy("Policy document must be a JSON object"))?;

        for k in obj.keys() {
            if !matches!(k.as_str(), "Version" | "Id" | "Statement") {
                return Err(malformed_policy(format!("Unknown policy field '{k}'")));
            }
        }

        if let Some(ver) = obj.get("Version") {
            let v_str = ver
                .as_str()
                .ok_or_else(|| malformed_policy("Version must be a string"))?;
            if !matches!(v_str, "2012-10-17" | "2008-10-17") {
                return Err(malformed_policy(format!("Unsupported Version '{v_str}'")));
            }
        }

        let stmt_val = obj
            .get("Statement")
            .ok_or_else(|| malformed_policy("Policy missing 'Statement'"))?;
        let raw_stmts: Vec<&Value> = match stmt_val {
            Value::Array(arr) => {
                if arr.is_empty() {
                    return Err(malformed_policy("Statement array cannot be empty"));
                }
                arr.iter().collect()
            }
            Value::Object(_) => vec![stmt_val],
            _ => return Err(malformed_policy("Statement must be an object or array")),
        };

        let mut statements = Vec::with_capacity(raw_stmts.len());
        for s in raw_stmts {
            statements.push(parse_statement(s, bucket_name)?);
        }

        Ok(Self {
            raw_json: raw_json.to_string(),
            statements,
        })
    }

    pub fn is_public(&self) -> bool {
        self.statements.iter().any(is_public_statement)
    }

    pub fn evaluate(
        &self,
        ctx: &CallerContext,
        actions: &[S3Action],
        resource_arn: &str,
        extra: &PolicyEvalExtra<'_>,
    ) -> PolicyDecision {
        let mut allowed = false;
        let mut allowed_only_via_public = true;

        for stmt in &self.statements {
            if !stmt_matches(stmt, ctx, actions, resource_arn, extra) {
                continue;
            }
            match stmt.effect {
                PolicyEffect::Deny => return PolicyDecision::ExplicitDeny,
                PolicyEffect::Allow => {
                    allowed = true;
                    if !is_public_statement(stmt) {
                        allowed_only_via_public = false;
                    }
                }
            }
        }

        if allowed {
            PolicyDecision::ExplicitAllow {
                via_public_statement: allowed_only_via_public,
            }
        } else {
            PolicyDecision::ImplicitDeny
        }
    }
}

fn malformed_policy(msg: impl Into<String>) -> S3Error {
    S3Error::new(S3ErrorCode::MalformedPolicy, msg)
}

fn parse_statement(val: &Value, bucket_name: &str) -> StoreResult<PolicyStatement> {
    let obj = val
        .as_object()
        .ok_or_else(|| malformed_policy("Statement entry must be a JSON object"))?;

    for k in obj.keys() {
        if !matches!(
            k.as_str(),
            "Sid"
                | "Effect"
                | "Principal"
                | "NotPrincipal"
                | "Action"
                | "NotAction"
                | "Resource"
                | "NotResource"
                | "Condition"
        ) {
            return Err(malformed_policy(format!("Unknown Statement field '{k}'")));
        }
    }

    let effect = match obj.get("Effect").and_then(Value::as_str) {
        Some("Allow") => PolicyEffect::Allow,
        Some("Deny") => PolicyEffect::Deny,
        _ => return Err(malformed_policy("Effect must be 'Allow' or 'Deny'")),
    };

    let (is_not_principal, principals) = match (obj.get("Principal"), obj.get("NotPrincipal")) {
        (Some(p), None) => (false, parse_principals(p)?),
        (None, Some(np)) => {
            if effect == PolicyEffect::Allow {
                // `test_bucket_policy_allow_notprincipal` (`test_s3.py:14192`)
                return Err(malformed_policy(
                    "Unsupported combination: Effect 'Allow' with 'NotPrincipal'",
                ));
            }
            (true, parse_principals(np)?)
        }
        _ => {
            return Err(malformed_policy(
                "Statement must contain Principal or NotPrincipal",
            ))
        }
    };

    let (is_not_action, actions) = match (obj.get("Action"), obj.get("NotAction")) {
        (Some(a), None) => (false, parse_string_or_array(a, "Action")?),
        (None, Some(na)) => (true, parse_string_or_array(na, "NotAction")?),
        _ => return Err(malformed_policy("Statement must contain Action or NotAction")),
    };
    for act in &actions {
        validate_action_pattern(act)?;
    }

    let (is_not_resource, resources) = match (obj.get("Resource"), obj.get("NotResource")) {
        (Some(r), None) => (false, parse_string_or_array(r, "Resource")?),
        (None, Some(nr)) => (true, parse_string_or_array(nr, "NotResource")?),
        _ => {
            return Err(malformed_policy(
                "Statement must contain Resource or NotResource",
            ))
        }
    };
    for res in &resources {
        validate_resource_pattern(res, bucket_name)?;
    }

    let conditions = match obj.get("Condition") {
        Some(c) => parse_conditions(c)?,
        None => Vec::new(),
    };

    Ok(PolicyStatement {
        effect,
        is_not_principal,
        principals,
        is_not_action,
        actions,
        is_not_resource,
        resources,
        conditions,
    })
}

fn parse_string_or_array(val: &Value, field: &str) -> StoreResult<Vec<String>> {
    match val {
        Value::String(s) => {
            if s.is_empty() {
                return Err(malformed_policy(format!("{field} cannot be empty")));
            }
            Ok(vec![s.clone()])
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(malformed_policy(format!("{field} array cannot be empty")));
            }
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| malformed_policy(format!("{field} item must be a string")))?;
                if s.is_empty() {
                    return Err(malformed_policy(format!("{field} item cannot be empty")));
                }
                out.push(s.to_string());
            }
            Ok(out)
        }
        _ => Err(malformed_policy(format!(
            "{field} must be a string or array of strings"
        ))),
    }
}

fn parse_principals(val: &Value) -> StoreResult<Vec<PrincipalEntry>> {
    match val {
        Value::String(s) if s == "*" => Ok(vec![PrincipalEntry::Any]),
        Value::Object(map) => {
            if map.is_empty() {
                return Err(malformed_policy("Principal object cannot be empty"));
            }
            let mut out = Vec::new();
            for (k, v) in map {
                let vals = parse_string_or_array(v, "Principal")?;
                match k.as_str() {
                    "AWS" => {
                        for item in vals {
                            if item == "*" {
                                out.push(PrincipalEntry::Any);
                            } else {
                                out.push(PrincipalEntry::Aws(item));
                            }
                        }
                    }
                    "CanonicalUser" => {
                        for item in vals {
                            out.push(PrincipalEntry::CanonicalUser(item));
                        }
                    }
                    "Service" | "Federated" => {
                        for item in vals {
                            out.push(PrincipalEntry::Service(item));
                        }
                    }
                    _ => return Err(malformed_policy(format!("Invalid Principal type '{k}'"))),
                }
            }
            Ok(out)
        }
        _ => Err(malformed_policy("Invalid Principal specification")),
    }
}

fn validate_action_pattern(act: &str) -> StoreResult<()> {
    if act == "*" {
        return Ok(());
    }
    let lower = act.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("s3:") else {
        return Err(malformed_policy(format!(
            "Action does not apply to S3 service: '{act}'"
        )));
    };
    if rest.is_empty() {
        return Err(malformed_policy("Empty S3 action name"));
    }
    Ok(())
}

fn validate_resource_pattern(res: &str, bucket_name: &str) -> StoreResult<()> {
    let rest = res
        .strip_prefix("arn:aws:s3:::")
        .or_else(|| res.strip_prefix("arn:aws-cn:s3:::"))
        .or_else(|| res.strip_prefix("arn:aws-us-gov:s3:::"))
        .ok_or_else(|| malformed_policy(format!("Invalid S3 resource ARN '{res}'")))?;
    if rest.is_empty() {
        return Err(malformed_policy("Empty resource bucket in ARN"));
    }
    let bucket_pat = rest.split('/').next().unwrap_or("");
    if !bucket_pat.contains('*') && !bucket_pat.contains('?') && bucket_pat != bucket_name {
        return Err(malformed_policy(format!(
            "Policy has invalid resource '{res}' for bucket '{bucket_name}'"
        )));
    }
    Ok(())
}

fn parse_conditions(val: &Value) -> StoreResult<Vec<ConditionClause>> {
    let map = val
        .as_object()
        .ok_or_else(|| malformed_policy("Condition must be a JSON object"))?;
    let mut clauses = Vec::new();
    for (op_raw, inner) in map {
        // Strip optional ForAnyValue: / ForAllValues: set prefix if present
        let op_trimmed = op_raw
            .strip_prefix("ForAnyValue:")
            .or_else(|| op_raw.strip_prefix("ForAllValues:"))
            .unwrap_or(op_raw.as_str());
        let (base_str, if_exists) = match op_trimmed.strip_suffix("IfExists") {
            Some(b) if !b.eq_ignore_ascii_case("Null") => (b, true),
            _ => (op_trimmed, false),
        };
        let op = match base_str {
            "StringEquals" | "ArnEquals" | "DateEquals" => ConditionBaseOp::StringEquals,
            "StringNotEquals" | "ArnNotEquals" | "DateNotEquals" => {
                ConditionBaseOp::StringNotEquals
            }
            "StringEqualsIgnoreCase" => ConditionBaseOp::StringEqualsIgnoreCase,
            "StringNotEqualsIgnoreCase" => ConditionBaseOp::StringNotEqualsIgnoreCase,
            "StringLike" | "ArnLike" => ConditionBaseOp::StringLike,
            "StringNotLike" | "ArnNotLike" => ConditionBaseOp::StringNotLike,
            "NumericEquals" => ConditionBaseOp::NumericEquals,
            "NumericNotEquals" => ConditionBaseOp::NumericNotEquals,
            "NumericLessThan" => ConditionBaseOp::NumericLessThan,
            "NumericLessThanEquals" => ConditionBaseOp::NumericLessThanEquals,
            "NumericGreaterThan" => ConditionBaseOp::NumericGreaterThan,
            "NumericGreaterThanEquals" => ConditionBaseOp::NumericGreaterThanEquals,
            "Bool" => ConditionBaseOp::Bool,
            "Null" => ConditionBaseOp::Null,
            "IpAddress" => ConditionBaseOp::IpAddress,
            "NotIpAddress" => ConditionBaseOp::NotIpAddress,
            _ => {
                return Err(malformed_policy(format!(
                    "Unsupported Condition operator '{op_raw}'"
                )))
            }
        };

        let kv_map = inner
            .as_object()
            .ok_or_else(|| malformed_policy("Condition operator body must be a JSON object"))?;
        for (cond_key, cond_val) in kv_map {
            let expected_values = parse_condition_values(cond_val)?;
            if matches!(op, ConditionBaseOp::IpAddress | ConditionBaseOp::NotIpAddress) {
                for cidr in &expected_values {
                    if parse_cidr(cidr).is_none() {
                        return Err(malformed_policy(format!("Invalid CIDR '{cidr}'")));
                    }
                }
            }
            clauses.push(ConditionClause {
                op: op.clone(),
                if_exists,
                key_lower: cond_key.to_ascii_lowercase(),
                raw_key: cond_key.clone(),
                expected_values,
            });
        }
    }
    Ok(clauses)
}

fn parse_condition_values(val: &Value) -> StoreResult<Vec<String>> {
    match val {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Bool(b) => Ok(vec![b.to_string()]),
        Value::Number(n) => Ok(vec![n.to_string()]),
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(malformed_policy("Condition value array cannot be empty"));
            }
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    Value::Bool(b) => out.push(b.to_string()),
                    Value::Number(n) => out.push(n.to_string()),
                    _ => return Err(malformed_policy("Invalid Condition value item")),
                }
            }
            Ok(out)
        }
        _ => Err(malformed_policy("Invalid Condition value")),
    }
}

fn is_public_statement(stmt: &PolicyStatement) -> bool {
    if stmt.effect != PolicyEffect::Allow || stmt.is_not_principal {
        return false;
    }
    if !stmt.principals.iter().any(|p| matches!(p, PrincipalEntry::Any)) {
        return false;
    }
    // Check if conditions restrict public access (e.g. non-wildcard IpAddress on aws:SourceIp)
    for c in &stmt.conditions {
        if c.op == ConditionBaseOp::IpAddress && c.key_lower == "aws:sourceip" && !c.if_exists {
            let has_world_cidr = c
                .expected_values
                .iter()
                .any(|v| v == "0.0.0.0/0" || v == "::/0");
            if !has_world_cidr {
                return false;
            }
        }
        if matches!(
            c.op,
            ConditionBaseOp::StringEquals | ConditionBaseOp::StringEqualsIgnoreCase
        ) && matches!(
            c.key_lower.as_str(),
            "aws:sourceaccount" | "aws:sourcearn" | "aws:principalarn" | "aws:principalorgid"
        ) && !c.if_exists
        {
            return false;
        }
    }
    true
}

fn stmt_matches(
    stmt: &PolicyStatement,
    ctx: &CallerContext,
    actions: &[S3Action],
    resource_arn: &str,
    extra: &PolicyEvalExtra<'_>,
) -> bool {
    let prin_hit = stmt
        .principals
        .iter()
        .any(|p| p.matches(ctx.caller.as_ref(), ctx.is_authenticated));
    if stmt.is_not_principal == prin_hit {
        return false;
    }

    let act_hit = actions.iter().any(|req_act| {
        stmt.actions
            .iter()
            .any(|pat| match_iam_wildcard(pat, req_act.as_str(), true))
    });
    if stmt.is_not_action == act_hit {
        return false;
    }

    let res_hit = stmt
        .resources
        .iter()
        .any(|pat| match_iam_wildcard(pat, resource_arn, false));
    if stmt.is_not_resource == res_hit {
        return false;
    }

    stmt.conditions
        .iter()
        .all(|clause| eval_condition_clause(clause, ctx, extra))
}

fn lookup_condition_value(
    raw_key: &str,
    key_lower: &str,
    ctx: &CallerContext,
    extra: &PolicyEvalExtra<'_>,
) -> Option<String> {
    let pctx = &ctx.policy_ctx;
    if let Some(tag_key) = strip_prefix_ignore_case(raw_key, "s3:ExistingObjectTag/") {
        return extra
            .existing_object_tags
            .and_then(|m| m.get(tag_key))
            .cloned();
    }
    if let Some(tag_key) = strip_prefix_ignore_case(raw_key, "s3:RequestObjectTag/") {
        return extra
            .request_object_tags
            .and_then(|m| m.get(tag_key))
            .cloned();
    }

    match key_lower {
        "aws:referer" => pctx.referer.clone(),
        "aws:sourceip" => pctx.source_ip.map(|ip| ip.to_string()),
        "aws:securetransport" => Some("false".to_string()),
        "aws:username" => ctx.caller.as_ref().map(|c| c.display_name.clone()),
        "aws:userid" => ctx.caller.as_ref().map(|c| c.user_id.clone()),
        "s3:prefix" => extra.prefix.map(str::to_string),
        "s3:delimiter" => extra.delimiter.map(str::to_string),
        "s3:x-amz-acl" => pctx.x_amz_acl.clone(),
        "s3:x-amz-grant-full-control" => pctx.x_amz_grant_full_control.clone(),
        "s3:x-amz-grant-read" => pctx.x_amz_grant_read.clone(),
        "s3:x-amz-grant-write" => pctx.x_amz_grant_write.clone(),
        "s3:x-amz-grant-read-acp" => pctx.x_amz_grant_read_acp.clone(),
        "s3:x-amz-grant-write-acp" => pctx.x_amz_grant_write_acp.clone(),
        "s3:x-amz-copy-source" => pctx.x_amz_copy_source.clone(),
        "s3:x-amz-metadata-directive" => pctx.x_amz_metadata_directive.clone(),
        "s3:x-amz-server-side-encryption" => pctx.x_amz_server_side_encryption.clone(),
        "s3:x-amz-server-side-encryption-customer-algorithm" => {
            pctx.x_amz_sse_customer_algorithm.clone()
        }
        _ => None,
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s.is_char_boundary(prefix.len()) {
        if s[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return Some(&s[prefix.len()..]);
        }
    }
    None
}

fn eval_condition_clause(
    clause: &ConditionClause,
    ctx: &CallerContext,
    extra: &PolicyEvalExtra<'_>,
) -> bool {
    let actual_opt = lookup_condition_value(&clause.raw_key, &clause.key_lower, ctx, extra);

    if clause.op == ConditionBaseOp::Null {
        let is_null = actual_opt.is_none();
        return clause.expected_values.iter().any(|exp| {
            let want_null = exp.eq_ignore_ascii_case("true");
            is_null == want_null
        });
    }

    let Some(actual) = actual_opt else {
        return clause.if_exists;
    };

    match clause.op {
        ConditionBaseOp::StringEquals => clause.expected_values.iter().any(|e| *e == actual),
        ConditionBaseOp::StringNotEquals => clause.expected_values.iter().all(|e| *e != actual),
        ConditionBaseOp::StringEqualsIgnoreCase => clause
            .expected_values
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&actual)),
        ConditionBaseOp::StringNotEqualsIgnoreCase => clause
            .expected_values
            .iter()
            .all(|e| !e.eq_ignore_ascii_case(&actual)),
        ConditionBaseOp::StringLike => clause
            .expected_values
            .iter()
            .any(|e| match_iam_wildcard(e, &actual, false)),
        ConditionBaseOp::StringNotLike => clause
            .expected_values
            .iter()
            .all(|e| !match_iam_wildcard(e, &actual, false)),
        ConditionBaseOp::NumericEquals => compare_numeric(&actual, &clause.expected_values, |a, b| (a - b).abs() < f64::EPSILON, true),
        ConditionBaseOp::NumericNotEquals => compare_numeric(&actual, &clause.expected_values, |a, b| (a - b).abs() >= f64::EPSILON, false),
        ConditionBaseOp::NumericLessThan => compare_numeric(&actual, &clause.expected_values, |a, b| a < b, true),
        ConditionBaseOp::NumericLessThanEquals => compare_numeric(&actual, &clause.expected_values, |a, b| a <= b, true),
        ConditionBaseOp::NumericGreaterThan => compare_numeric(&actual, &clause.expected_values, |a, b| a > b, true),
        ConditionBaseOp::NumericGreaterThanEquals => compare_numeric(&actual, &clause.expected_values, |a, b| a >= b, true),
        ConditionBaseOp::Bool => {
            let Some(act_b) = parse_bool_str(&actual) else {
                return false;
            };
            clause
                .expected_values
                .iter()
                .any(|e| parse_bool_str(e) == Some(act_b))
        }
        ConditionBaseOp::Null => unreachable!(),
        ConditionBaseOp::IpAddress => {
            let Ok(ip) = actual.parse::<IpAddr>() else {
                return false;
            };
            clause
                .expected_values
                .iter()
                .any(|cidr| cidr_contains(cidr, ip))
        }
        ConditionBaseOp::NotIpAddress => {
            let Ok(ip) = actual.parse::<IpAddr>() else {
                return false;
            };
            clause
                .expected_values
                .iter()
                .all(|cidr| !cidr_contains(cidr, ip))
        }
    }
}

fn parse_bool_str(s: &str) -> Option<bool> {
    if s.eq_ignore_ascii_case("true") {
        Some(true)
    } else if s.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

fn compare_numeric<F>(actual: &str, expected: &[String], cmp: F, any_mode: bool) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let Ok(act_n) = actual.trim().parse::<f64>() else {
        return false;
    };
    if any_mode {
        expected
            .iter()
            .any(|e| e.trim().parse::<f64>().is_ok_and(|en| cmp(act_n, en)))
    } else {
        expected
            .iter()
            .all(|e| e.trim().parse::<f64>().is_ok_and(|en| cmp(act_n, en)))
    }
}

fn parse_cidr(raw: &str) -> Option<(IpAddr, u8)> {
    if let Some((ip_str, prefix_str)) = raw.split_once('/') {
        let ip: IpAddr = ip_str.parse().ok()?;
        let bits: u8 = prefix_str.parse().ok()?;
        let max_bits = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if bits > max_bits {
            return None;
        }
        Some((ip, bits))
    } else {
        let ip: IpAddr = raw.parse().ok()?;
        let bits = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Some((ip, bits))
    }
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((net_ip, bits)) = parse_cidr(cidr) else {
        return false;
    };
    match (net_ip, ip) {
        (IpAddr::V4(net), IpAddr::V4(cand)) => {
            if bits == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - bits);
            (u32::from(net) & mask) == (u32::from(cand) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(cand)) => {
            if bits == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - bits);
            (u128::from(net) & mask) == (u128::from(cand) & mask)
        }
        _ => false,
    }
}

/// IAM wildcard matcher supporting `*` (0+ chars) and `?` (exact 1 char).
pub fn match_iam_wildcard(pattern: &str, text: &str, ignore_case: bool) -> bool {
    let p_chars: Vec<char> = if ignore_case {
        pattern.chars().map(|c| c.to_ascii_lowercase()).collect()
    } else {
        pattern.chars().collect()
    };
    let t_chars: Vec<char> = if ignore_case {
        text.chars().map(|c| c.to_ascii_lowercase()).collect()
    } else {
        text.chars().collect()
    };

    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (None, 0usize);

    while ti < t_chars.len() {
        if pi < p_chars.len() && (p_chars[pi] == '?' || p_chars[pi] == t_chars[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p_chars.len() && p_chars[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p_chars.len() && p_chars[pi] == '*' {
        pi += 1;
    }
    pi == p_chars.len()
}

// ---- Unified Authorization Engine (`PR-28` ~ `PR-33`, `docs/03-protocol-and-api.md` §6.1) ----

pub struct BucketAuthView<'a> {
    pub name: &'a str,
    pub owner: &'a OwnerInfo,
    pub acl: &'a AccessControlPolicy,
    pub ownership: ObjectOwnership,
    pub policy: Option<&'a BucketPolicyDoc>,
    pub public_access_block: Option<&'a PublicAccessBlockConfig>,
}

impl<'a> BucketAuthView<'a> {
    pub fn ignore_public_acls(&self) -> bool {
        self.public_access_block
            .is_some_and(|pab| pab.ignore_public_acls)
    }

    pub fn block_public_acls(&self) -> bool {
        self.public_access_block
            .is_some_and(|pab| pab.block_public_acls)
    }

    pub fn block_public_policy(&self) -> bool {
        self.public_access_block
            .is_some_and(|pab| pab.block_public_policy)
    }

    pub fn restrict_public_buckets(&self) -> bool {
        self.public_access_block
            .is_some_and(|pab| pab.restrict_public_buckets)
    }

    pub fn is_caller_bucket_owner(&self, ctx: &CallerContext) -> bool {
        ctx.is_authenticated
            && ctx
                .caller
                .as_ref()
                .is_some_and(|c| c.user_id == self.owner.user_id)
    }

    /// Compute `?policyStatus` `<IsPublic>` (`docs/03-protocol-and-api.md` §6.2).
    pub fn compute_is_public(&self) -> bool {
        let public_via_acl = self.ownership != ObjectOwnership::BucketOwnerEnforced
            && !self.ignore_public_acls()
            && self.acl.has_public_grants();
        let public_via_policy =
            !self.restrict_public_buckets() && self.policy.is_some_and(|p| p.is_public());
        public_via_acl || public_via_policy
    }
}

/// Enforce `PublicAccessBlock.BlockPublicAcls` before writing any bucket/object ACL (`PR-33`).
pub fn enforce_block_public_acl_spec(
    block_public_acls: bool,
    spec: Option<&AclSpec>,
) -> StoreResult<()> {
    if !block_public_acls {
        return Ok(());
    }
    let Some(spec) = spec else {
        return Ok(());
    };
    let is_pub = match spec {
        AclSpec::Canned(c) => CannedAcl::is_public(*c),
        AclSpec::Grants(grants) => grants.iter().any(|g| g.grantee.is_public_group()),
        AclSpec::Policy(pol) => pol.has_public_grants(),
    };
    if is_pub {
        return Err(S3Error::new(
            S3ErrorCode::AccessDenied,
            "Access Denied",
        ));
    }
    Ok(())
}

/// Unified authorization for bucket-targeted operations (`arn:aws:s3:::{bucket}`).
/// If `acl_needed` is `None`, only Bucket Policy `Allow` or `caller == bucket.owner` authorizes.
pub fn authorize_bucket_action(
    bucket: &BucketAuthView<'_>,
    ctx: &CallerContext,
    actions: &[S3Action],
    acl_needed: Option<AclPermission>,
    extra: &PolicyEvalExtra<'_>,
) -> bool {
    let caller_is_bucket_owner = bucket.is_caller_bucket_owner(ctx);
    let arn = format!("arn:aws:s3:::{}", bucket.name);

    if let Some(pol) = bucket.policy {
        match pol.evaluate(ctx, actions, &arn, extra) {
            PolicyDecision::ExplicitDeny => return false,
            PolicyDecision::ExplicitAllow {
                via_public_statement,
            } => {
                if !(bucket.restrict_public_buckets() && via_public_statement && !caller_is_bucket_owner)
                {
                    return true;
                }
            }
            PolicyDecision::ImplicitDeny => {}
        }
    }

    if caller_is_bucket_owner {
        return true;
    }

    let Some(needed) = acl_needed else {
        return false;
    };

    if bucket.ownership == ObjectOwnership::BucketOwnerEnforced {
        return false;
    }

    bucket.acl.allows(
        ctx.caller.as_ref(),
        ctx.is_authenticated,
        needed,
        bucket.ignore_public_acls(),
    )
}

/// Unified authorization for object-targeted operations (`arn:aws:s3:::{bucket}/{key}`).
///
/// - `resource_owner`: `Some(ver.owner)` for existing-object reads/ACL/tagging; `Some(bucket.owner)` for
///   bucket-scoped object writes (`PutObject`, `CreateMultipartUpload`, `DeleteObject` per `PR-31`).
/// - `target_acl`: either `Some(&bucket.acl)` (for `PutObject`/`DeleteObject`) or `Some(&ver.acl)` (for `GetObject`/`GetObjectAcl`),
///   or `None` when ACLs never grant the operation (e.g. `?tagging`, `GetObjectAttributes`).
pub fn authorize_object_action(
    bucket: &BucketAuthView<'_>,
    ctx: &CallerContext,
    key: &str,
    actions: &[S3Action],
    resource_owner: Option<&OwnerInfo>,
    target_acl_and_perm: Option<(&AccessControlPolicy, AclPermission)>,
    bucket_owner_always_allowed: bool,
    extra: &PolicyEvalExtra<'_>,
) -> bool {
    let caller_is_bucket_owner = bucket.is_caller_bucket_owner(ctx);
    let arn = format!("arn:aws:s3:::{}/{}", bucket.name, key);

    if let Some(pol) = bucket.policy {
        match pol.evaluate(ctx, actions, &arn, extra) {
            PolicyDecision::ExplicitDeny => return false,
            PolicyDecision::ExplicitAllow {
                via_public_statement,
            } => {
                if !(bucket.restrict_public_buckets() && via_public_statement && !caller_is_bucket_owner)
                {
                    return true;
                }
            }
            PolicyDecision::ImplicitDeny => {}
        }
    }

    if bucket_owner_always_allowed && caller_is_bucket_owner {
        return true;
    }

    if bucket.ownership == ObjectOwnership::BucketOwnerEnforced {
        return caller_is_bucket_owner;
    }

    if let Some(res_owner) = resource_owner {
        let is_res_owner = ctx.is_authenticated
            && ctx
                .caller
                .as_ref()
                .is_some_and(|c| c.user_id == res_owner.user_id);
        // [PR-30, PR-31] Resource owner is always allowed unless an explicit Bucket Policy Deny matched above.
        if is_res_owner {
            return true;
        }
    }

    let Some((acl, needed)) = target_acl_and_perm else {
        return false;
    };

    acl.allows(
        ctx.caller.as_ref(),
        ctx.is_authenticated,
        needed,
        bucket.ignore_public_acls(),
    )
}

/// Missing-object `404 NoSuchKey` / `404 NoSuchVersion` vs `403 AccessDenied` rule (`test_head_object_404_with_policy_prefix`):
/// returns `true` if caller has `s3:ListBucket` (or `s3:ListBucketVersions` when `has_version_id`) on `{bucket}` with `s3:prefix = target_key`.
pub fn can_reveal_missing_key(
    bucket: &BucketAuthView<'_>,
    ctx: &CallerContext,
    key: &str,
    has_version_id: bool,
) -> bool {
    let extra = PolicyEvalExtra {
        prefix: Some(key),
        delimiter: None,
        existing_object_tags: None,
        request_object_tags: None,
    };
    let actions: &[S3Action] = if has_version_id {
        &[S3Action::ListBucketVersions, S3Action::ListBucket]
    } else {
        &[S3Action::ListBucket]
    };
    authorize_bucket_action(bucket, ctx, actions, Some(AclPermission::Read), &extra)
}
