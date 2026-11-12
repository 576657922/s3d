use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use http::header::HeaderValue;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use rand::RngCore;
use s3d_proto::*;
use s3d_types::*;
use tracing::info;

use crate::body::{
    collect_raw_incoming_bounded, drain_empty_or_ignore, HyperVerifiedBodyStream,
    PreVerifiedBytesStream, S3ResponseBody,
};
use crate::config::ServerConfig;
use crate::metrics::ServerMetrics;

const MAX_HEADER_SECTION_BYTES: usize = 8192; // PR-19

const UNIMPLEMENTED_BUCKET_SUBRESOURCES: &[&str] = &[
    "website",
    "replication",
    "notification",
    "inventory",
    "analytics",
    "metrics",
    "intelligent-tiering",
    "accelerate",
    "requestPayment",
];

const UNIMPLEMENTED_OBJECT_SUBRESOURCES: &[&str] = &[
    "select",
    "restore",
    "torrent",
];

pub struct AppState<S: ObjectStore> {
    pub store: Arc<S>,
    pub auth: Arc<SigV4Verifier>,
    pub cfg: ServerConfig,
    pub metrics: Arc<ServerMetrics>,
}

pub async fn handle_s3_request<S: ObjectStore>(
    state: Arc<AppState<S>>,
    req: Request<Incoming>,
    peer_ip: Option<IpAddr>,
) -> Response<S3ResponseBody<S::Reader>> {
    let start = Instant::now();
    let (request_id, host_id) = generate_request_ids();
    let is_head = req.method() == Method::HEAD;
    let method = req.method().clone();
    let raw_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let origin_hdr = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let ac_req_method_hdr = req
        .headers()
        .get("access-control-request-method")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let req_bytes_est: u64 = req
        .headers()
        .get("x-amz-decoded-content-length")
        .or_else(|| req.headers().get("content-length"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let mut op_name: &'static str = "Unknown";
    let mut bucket_log: Option<String> = None;
    let mut key_log: Option<String> = None;
    let mut caller_log: Option<String> = None;

    let result = dispatch_inner(
        &state,
        req,
        peer_ip,
        &mut op_name,
        &mut bucket_log,
        &mut key_log,
        &mut caller_log,
    )
    .await;

    let (mut resp, error_code): (_, &'static str) = match result {
        Ok(mut r) => {
            inject_common_headers(r.headers_mut(), &request_id, &host_id);
            (r, "")
        }
        Err(err) => {
            let code_str = err.code.as_str();
            (build_error_response(err, is_head, &request_id, &host_id), code_str)
        }
    };

    if method != Method::OPTIONS
        && let (Some(origin), Some(bkt)) = (&origin_hdr, &bucket_log)
            && let Ok(Some(cors)) = state.store.lookup_bucket_cors_unauth(bkt).await {
                let eff_method = ac_req_method_hdr
                    .as_deref()
                    .unwrap_or_else(|| method.as_str());
                if let Some(cors_hdrs) = cors.match_origin_request(origin, eff_method) {
                    apply_cors_headers(resp.headers_mut(), &cors_hdrs);
                }
            }

    let resp_bytes: u64 = if is_head {
        0
    } else {
        match resp.body() {
            S3ResponseBody::Fixed(Some(b)) => b.len() as u64,
            S3ResponseBody::Fixed(None) => 0,
            S3ResponseBody::Stream(_) => resp
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0),
        }
    };
    let logged_bytes = if req_bytes_est > 0 && error_code.is_empty() {
        req_bytes_est
    } else {
        resp_bytes
    };

    if req_bytes_est > 0 && error_code.is_empty() {
        state
            .metrics
            .bytes_in_total
            .fetch_add(req_bytes_est, std::sync::atomic::Ordering::Relaxed);
    }
    if resp_bytes > 0 {
        state
            .metrics
            .bytes_out_total
            .fetch_add(resp_bytes, std::sync::atomic::Ordering::Relaxed);
    }

    let status = resp.status().as_u16();
    let elapsed_us = start.elapsed().as_micros() as u64;
    state.metrics.record_request(op_name, status, elapsed_us);

    info!(
        request_id = %request_id,
        method = %method,
        uri = %raw_uri,
        op = op_name,
        bucket = bucket_log.as_deref().unwrap_or(""),
        key = key_log.as_deref().unwrap_or(""),
        caller = caller_log.as_deref().unwrap_or("anonymous"),
        status,
        error_code,
        bytes = logged_bytes,
        latency_us = elapsed_us,
        "s3_request"
    );

    resp
}

async fn dispatch_inner<S: ObjectStore>(
    state: &AppState<S>,
    req: Request<Incoming>,
    peer_ip: Option<IpAddr>,
    op_name: &mut &'static str,
    bucket_log: &mut Option<String>,
    key_log: &mut Option<String>,
    caller_log: &mut Option<String>,
) -> StoreResult<Response<S3ResponseBody<S::Reader>>> {
    let (parts, incoming) = req.into_parts();
    let headers = &parts.headers;
    let method = &parts.method;

    // 1. Header section size limit <= 8 KB (`PR-19`)
    let header_bytes: usize = headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4)
        .sum();
    if header_bytes > MAX_HEADER_SECTION_BYTES {
        *op_name = "HeaderGuard";
        return Err(S3Error::new(
            S3ErrorCode::RequestHeaderSectionTooLarge,
            "Your header section exceeds the maximum allowed size of 8192 bytes.",
        ));
    }

    // 2. Validate `Content-Length` syntax if present (`test_headers.py`)
    let content_length = parse_optional_content_length(headers)?;

    // 3. Parse URI & target (`PR-1` ~ `PR-3`)
    let raw_uri = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let host_hdr = headers.get("host").and_then(|v| v.to_str().ok());
    let parsed_uri = parse_s3_uri(host_hdr, raw_uri, &state.cfg.base_domain)?;

    match &parsed_uri.target {
        S3Target::ServiceRoot => {}
        S3Target::Bucket { bucket } => {
            *bucket_log = Some(bucket.clone());
        }
        S3Target::Object { bucket, key } => {
            *bucket_log = Some(bucket.clone());
            *key_log = Some(key.clone());
        }
    }

    // 4. Handle CORS Preflight `OPTIONS` before SigV4 (`OPTIONS` is never signed)
    if *method == Method::OPTIONS {
        *op_name = "OptionsPreflight";
        drain_empty_or_ignore(incoming).await;
        let bkt = match &parsed_uri.target {
            S3Target::Bucket { bucket } | S3Target::Object { bucket, .. } => bucket.as_str(),
            S3Target::ServiceRoot => {
                return Err(S3Error::new(
                    S3ErrorCode::BadRequest,
                    "Insufficient information. Bucket target needed.",
                ));
            }
        };
        let origin = headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let req_method = headers
            .get("access-control-request-method")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let (Some(origin), Some(req_method)) = (origin, req_method) else {
            return Err(S3Error::new(
                S3ErrorCode::BadRequest,
                "Insufficient information. Origin request header needed.",
            ));
        };
        if !is_valid_cors_method(&req_method.to_ascii_uppercase()) {
            return Err(S3Error::new(
                S3ErrorCode::BadRequest,
                format!("Invalid Access-Control-Request-Method: {req_method}"),
            ));
        }

        let mut req_headers = Vec::new();
        for hv in headers.get_all("access-control-request-headers") {
            if let Ok(s) = hv.to_str() {
                for tok in s.split(',') {
                    let t = tok.trim();
                    if !t.is_empty() {
                        req_headers.push(t.to_string());
                    }
                }
            }
        }

        let Some(cors) = state.store.lookup_bucket_cors_unauth(bkt).await? else {
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "CORSResponse: This CORS request is not allowed.",
            ));
        };
        let Some(cors_hdrs) = cors.match_preflight(origin, req_method, &req_headers) else {
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "CORSResponse: This CORS request is not allowed.",
            ));
        };

        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Length", "0")
            .body(S3ResponseBody::empty())
            .unwrap();
        apply_cors_headers(resp.headers_mut(), &cors_hdrs);
        return Ok(resp);
    }

    let now_ms = now_epoch_ms();

    // 4b. HTML Form `PostObject` (`POST /{bucket}` without subresource query) (`FR-48` / P1)
    if let S3Target::Bucket { bucket } = &parsed_uri.target
        && *method == Method::POST && parsed_uri.query.is_empty() {
            *op_name = "PostObject";
            return handle_post_object(
                state,
                headers,
                incoming,
                bucket.clone(),
                peer_ip,
                now_ms,
                key_log,
                caller_log,
            )
            .await;
        }

    // 5. SigV4 / Presigned / Anonymous authentication (`PR-6` ~ `PR-12`)
    let auth_out = state
        .auth
        .verify_request(method, &parsed_uri, headers, now_ms)?;
    if let Some(c) = &auth_out.caller {
        *caller_log = Some(c.user_id.clone());
    }

    let expected_bucket_owner = headers
        .get("x-amz-expected-bucket-owner")
        .map(|v| {
            v.to_str()
                .map(|s| s.trim().to_string())
                .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid expected owner"))
        })
        .transpose()?;

    let policy_ctx = build_request_policy_context(headers, peer_ip);
    let ctx = CallerContext {
        caller: auth_out.caller.clone(),
        request_time_ms: now_ms,
        expected_bucket_owner,
        is_authenticated: auth_out.is_authenticated,
        policy_ctx,
    };

    // 6. Dispatch by `(S3Target, Method, subresource)`
    match parsed_uri.target {
        S3Target::ServiceRoot => {
            if *method != Method::GET {
                *op_name = "ServiceMethodNotAllowed";
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "The specified method is not allowed against this resource.",
                ));
            }
            *op_name = "ListBuckets";
            drain_empty_or_ignore(incoming).await;
            handle_list_buckets(state, ctx, &parsed_uri.query).await
        }
        S3Target::Bucket { bucket } => {
            handle_bucket_target(
                state,
                ctx,
                auth_out,
                method,
                headers,
                content_length,
                incoming,
                bucket,
                &parsed_uri.query,
                op_name,
            )
            .await
        }
        S3Target::Object { bucket, key } => {
            handle_object_target(
                state,
                ctx,
                auth_out,
                method,
                headers,
                content_length,
                incoming,
                bucket,
                key,
                &parsed_uri.query,
                op_name,
            )
            .await
        }
    }
}

async fn handle_list_buckets<S: ObjectStore>(
    state: &AppState<S>,
    ctx: CallerContext,
    query: &[(String, String)],
) -> StoreResult<Response<S3ResponseBody<S::Reader>>> {
    let max_buckets = match get_query_param(query, "max-buckets") {
        Some(raw) => Some(raw.parse::<usize>().map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid max-buckets parameter",
            )
        })?),
        None => None,
    };
    let prefix = get_query_param(query, "prefix").map(str::to_string);
    let continuation_token = get_query_param(query, "continuation-token").map(str::to_string);
    if let Some(region_filter) = get_query_param(query, "bucket-region")
        && !region_filter.is_empty() && region_filter != state.cfg.region {
            // Return empty list if filtering for another region
            let owner = ctx
                .caller
                .ok_or_else(|| S3Error::new(S3ErrorCode::AccessDenied, "Access Denied"))?;
            let xml = render_list_buckets_xml(&ListBucketsResp {
                owner,
                buckets: Vec::new(),
                next_continuation_token: None,
            });
            return Ok(xml_response(StatusCode::OK, xml));
        }

    let resp = state
        .store
        .list_buckets(ListBucketsReq {
            ctx,
            prefix,
            max_buckets,
            continuation_token,
        })
        .await?;
    Ok(xml_response(StatusCode::OK, render_list_buckets_xml(&resp)))
}

#[allow(clippy::too_many_arguments)]
async fn handle_bucket_target<S: ObjectStore>(
    state: &AppState<S>,
    ctx: CallerContext,
    auth_out: AuthOutcome,
    method: &Method,
    headers: &HeaderMap,
    content_length: Option<u64>,
    incoming: Incoming,
    bucket: String,
    query: &[(String, String)],
    op_name: &mut &'static str,
) -> StoreResult<Response<S3ResponseBody<S::Reader>>> {
    // Reject unimplemented bucket subresources with `501 NotImplemented` (`PR-5`)
    for sub in UNIMPLEMENTED_BUCKET_SUBRESOURCES {
        if has_query_key(query, sub) {
            *op_name = "NotImplementedBucketSubresource";
            return Err(S3Error::new(
                S3ErrorCode::NotImplemented,
                format!("Bucket subresource '?{sub}' is not implemented yet."),
            )
            .with_bucket(&bucket));
        }
    }

    if has_query_key(query, "ownershipControls") {
        match *method {
            Method::GET => {
                *op_name = "GetBucketOwnershipControls";
                drain_empty_or_ignore(incoming).await;
                let own = state
                    .store
                    .get_bucket_ownership_controls(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(
                    StatusCode::OK,
                    render_ownership_controls_xml(own),
                ));
            }
            Method::PUT => {
                *op_name = "PutBucketOwnershipControls";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let ownership = parse_ownership_controls_xml(&raw_xml)?;
                state
                    .store
                    .put_bucket_ownership_controls(PutBucketOwnershipControlsReq {
                        ctx,
                        bucket,
                        ownership,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            Method::DELETE => {
                *op_name = "DeleteBucketOwnershipControls";
                drain_empty_or_ignore(incoming).await;
                state
                    .store
                    .delete_bucket_ownership_controls(BucketRef { ctx, bucket })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "tagging") {
        match *method {
            Method::GET => {
                *op_name = "GetBucketTagging";
                drain_empty_or_ignore(incoming).await;
                let tags = state
                    .store
                    .get_bucket_tagging(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(StatusCode::OK, render_tagging_xml(&tags)));
            }
            Method::PUT => {
                *op_name = "PutBucketTagging";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    128 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let tags = parse_tagging_xml(&raw_xml, MAX_BUCKET_TAGS)?;
                state
                    .store
                    .put_bucket_tagging(PutBucketTaggingReq { ctx, bucket, tags })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            Method::DELETE => {
                *op_name = "DeleteBucketTagging";
                drain_empty_or_ignore(incoming).await;
                state
                    .store
                    .delete_bucket_tagging(BucketRef { ctx, bucket })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "cors") {
        match *method {
            Method::GET => {
                *op_name = "GetBucketCors";
                drain_empty_or_ignore(incoming).await;
                let cors = state
                    .store
                    .get_bucket_cors(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(StatusCode::OK, render_cors_xml(&cors)));
            }
            Method::PUT => {
                *op_name = "PutBucketCors";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    128 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let cors = parse_cors_xml(&raw_xml)?;
                state
                    .store
                    .put_bucket_cors(PutBucketCorsReq { ctx, bucket, cors })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            Method::DELETE => {
                *op_name = "DeleteBucketCors";
                drain_empty_or_ignore(incoming).await;
                state
                    .store
                    .delete_bucket_cors(BucketRef { ctx, bucket })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "policyStatus") {
        if *method != Method::GET {
            return Err(S3Error::new(
                S3ErrorCode::MethodNotAllowed,
                "Method not allowed",
            ));
        }
        *op_name = "GetBucketPolicyStatus";
        drain_empty_or_ignore(incoming).await;
        let is_public = state
            .store
            .get_bucket_policy_status(BucketRef { ctx, bucket })
            .await?;
        return Ok(xml_response(
            StatusCode::OK,
            render_policy_status_xml(is_public),
        ));
    }

    if has_query_key(query, "policy") {
        match *method {
            Method::GET => {
                *op_name = "GetBucketPolicy";
                drain_empty_or_ignore(incoming).await;
                let policy_json = state
                    .store
                    .get_bucket_policy(BucketRef { ctx, bucket })
                    .await?;
                let len = policy_json.len().to_string();
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", len)
                    .body(S3ResponseBody::from_bytes(Bytes::from(policy_json)))
                    .unwrap());
            }
            Method::PUT => {
                *op_name = "PutBucketPolicy";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_body, _) = stream.collect_bounded().await?;
                let policy_json = std::str::from_utf8(&raw_body)
                    .map_err(|_| {
                        S3Error::new(
                            S3ErrorCode::MalformedPolicy,
                            "Bucket policy must be valid UTF-8 JSON",
                        )
                    })?
                    .to_string();
                state
                    .store
                    .put_bucket_policy(PutBucketPolicyReq {
                        ctx,
                        bucket,
                        policy_json,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            Method::DELETE => {
                *op_name = "DeleteBucketPolicy";
                drain_empty_or_ignore(incoming).await;
                state
                    .store
                    .delete_bucket_policy(BucketRef { ctx, bucket })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "publicAccessBlock") {
        match *method {
            Method::GET => {
                *op_name = "GetPublicAccessBlock";
                drain_empty_or_ignore(incoming).await;
                let pab = state
                    .store
                    .get_public_access_block(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(
                    StatusCode::OK,
                    render_public_access_block_xml(&pab),
                ));
            }
            Method::PUT => {
                *op_name = "PutPublicAccessBlock";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let config = parse_public_access_block_xml(&raw_xml)?;
                state
                    .store
                    .put_public_access_block(PutPublicAccessBlockReq {
                        ctx,
                        bucket,
                        config,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            Method::DELETE => {
                *op_name = "DeletePublicAccessBlock";
                drain_empty_or_ignore(incoming).await;
                state
                    .store
                    .delete_public_access_block(BucketRef { ctx, bucket })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "object-lock") {
        match *method {
            Method::GET => {
                *op_name = "GetObjectLockConfiguration";
                drain_empty_or_ignore(incoming).await;
                let cfg = state
                    .store
                    .get_object_lock_configuration(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(
                    StatusCode::OK,
                    render_object_lock_configuration_xml(&cfg),
                ));
            }
            Method::PUT => {
                *op_name = "PutObjectLockConfiguration";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let config = parse_object_lock_configuration_xml(&raw_xml)?;
                state
                    .store
                    .put_object_lock_configuration(PutObjectLockConfigurationReq {
                        ctx,
                        bucket,
                        config,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "lifecycle") {
        match *method {
            Method::GET => {
                *op_name = "GetBucketLifecycleConfiguration";
                drain_empty_or_ignore(incoming).await;
                let cfg = state
                    .store
                    .get_bucket_lifecycle_configuration(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(
                    StatusCode::OK,
                    render_lifecycle_configuration_xml(&cfg),
                ));
            }
            Method::PUT => {
                *op_name = "PutBucketLifecycleConfiguration";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    2 * 1024 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let config = parse_lifecycle_configuration_xml(&raw_xml)?;
                state
                    .store
                    .put_bucket_lifecycle_configuration(PutBucketLifecycleReq {
                        ctx,
                        bucket,
                        config,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            Method::DELETE => {
                *op_name = "DeleteBucketLifecycle";
                drain_empty_or_ignore(incoming).await;
                state
                    .store
                    .delete_bucket_lifecycle(BucketRef { ctx, bucket })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "encryption") {
        match *method {
            Method::GET => {
                *op_name = "GetBucketEncryption";
                drain_empty_or_ignore(incoming).await;
                let cfg = state
                    .store
                    .get_bucket_encryption(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(
                    StatusCode::OK,
                    render_bucket_encryption_xml(&cfg),
                ));
            }
            Method::PUT => {
                *op_name = "PutBucketEncryption";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let config = parse_bucket_encryption_xml(&raw_xml)?;
                state
                    .store
                    .put_bucket_encryption(PutBucketEncryptionReq {
                        ctx,
                        bucket,
                        config,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            Method::DELETE => {
                *op_name = "DeleteBucketEncryption";
                drain_empty_or_ignore(incoming).await;
                state
                    .store
                    .delete_bucket_encryption(BucketRef { ctx, bucket })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "logging") {
        match *method {
            Method::GET => {
                *op_name = "GetBucketLogging";
                drain_empty_or_ignore(incoming).await;
                let status = state
                    .store
                    .get_bucket_logging(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(
                    StatusCode::OK,
                    render_bucket_logging_xml(&status),
                ));
            }
            Method::PUT => {
                *op_name = "PutBucketLogging";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let status = parse_bucket_logging_xml(
                    &raw_xml,
                    |uid| state.auth.lookup_by_user_id(uid),
                    |em| state.auth.lookup_by_email(em),
                )?;
                state
                    .store
                    .put_bucket_logging(PutBucketLoggingReq {
                        ctx,
                        bucket,
                        status,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "acl") {
        match *method {
            Method::GET => {
                *op_name = "GetBucketAcl";
                drain_empty_or_ignore(incoming).await;
                let pol = state
                    .store
                    .get_bucket_acl(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(StatusCode::OK, render_acl_xml(&pol)));
            }
            Method::PUT => {
                *op_name = "PutBucketAcl";
                let header_acl = parse_acl_headers(headers, &state.auth)?;
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_body, _) = stream.collect_bounded().await?;
                let acl = match header_acl {
                    Some(spec) => {
                        if !raw_body.is_empty() {
                            return Err(S3Error::new(
                                S3ErrorCode::InvalidRequest,
                                "This request does not support content when ACL headers are provided",
                            ));
                        }
                        spec
                    }
                    None => {
                        if raw_body.is_empty() {
                            return Err(S3Error::new(
                                S3ErrorCode::MissingSecurityHeader,
                                "Your request was missing a required header",
                            ));
                        }
                        let pol = parse_acl_xml(
                            &raw_body,
                            |uid| state.auth.lookup_by_user_id(uid),
                            |em| state.auth.lookup_by_email(em),
                        )?;
                        AclSpec::Policy(pol)
                    }
                };
                state
                    .store
                    .put_bucket_acl(PutBucketAclReq { ctx, bucket, acl })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "versioning") {
        match *method {
            Method::GET => {
                *op_name = "GetBucketVersioning";
                drain_empty_or_ignore(incoming).await;
                let vstate = state
                    .store
                    .get_bucket_versioning(BucketRef { ctx, bucket })
                    .await?;
                return Ok(xml_response(
                    StatusCode::OK,
                    render_bucket_versioning_xml(vstate),
                ));
            }
            Method::PUT => {
                *op_name = "PutBucketVersioning";
                if headers.contains_key("x-amz-mfa") {
                    return Err(S3Error::new(
                        S3ErrorCode::NotImplemented,
                        "MFA Delete is not supported.",
                    )
                    .with_bucket(&bucket));
                }
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let status = parse_bucket_versioning_xml(&raw_xml)?;
                state
                    .store
                    .put_bucket_versioning(PutBucketVersioningReq {
                        ctx,
                        bucket,
                        status,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "Method not allowed",
                ));
            }
        }
    }

    if has_query_key(query, "uploads") {
        if *method != Method::GET {
            return Err(S3Error::new(
                S3ErrorCode::MethodNotAllowed,
                "Method not allowed",
            ));
        }
        *op_name = "ListMultipartUploads";
        drain_empty_or_ignore(incoming).await;
        let url_encode = parse_encoding_type(query)?;
        let max_uploads = parse_bounded_limit_param(query, "max-uploads", 1000)?;
        let prefix = get_query_param(query, "prefix")
            .unwrap_or_default()
            .to_string();
        let delimiter = get_query_param(query, "delimiter")
            .filter(|d| !d.is_empty())
            .map(str::to_string);
        let key_marker = get_query_param(query, "key-marker")
            .filter(|m| !m.is_empty())
            .map(str::to_string);
        let upload_id_marker = get_query_param(query, "upload-id-marker")
            .filter(|m| !m.is_empty())
            .map(str::to_string);

        let resp = state
            .store
            .list_multipart_uploads(ListMultipartUploadsReq {
                ctx,
                bucket,
                prefix,
                delimiter,
                key_marker,
                upload_id_marker,
                max_uploads,
            })
            .await?;
        return Ok(xml_response(
            StatusCode::OK,
            render_list_multipart_uploads_xml(&resp, url_encode),
        ));
    }

    if has_query_key(query, "location") {
        if *method != Method::GET {
            return Err(S3Error::new(
                S3ErrorCode::MethodNotAllowed,
                "Method not allowed",
            ));
        }
        *op_name = "GetBucketLocation";
        drain_empty_or_ignore(incoming).await;
        let snap = state
            .store
            .head_bucket(BucketRef {
                ctx,
                bucket: bucket.clone(),
            })
            .await?;
        return Ok(xml_response(
            StatusCode::OK,
            render_bucket_location_xml(&snap.region),
        ));
    }

    if has_query_key(query, "versions") {
        if *method != Method::GET {
            return Err(S3Error::new(
                S3ErrorCode::MethodNotAllowed,
                "Method not allowed",
            ));
        }
        *op_name = "ListObjectVersions";
        drain_empty_or_ignore(incoming).await;
        let url_encode = parse_encoding_type(query)?;
        let max_keys = parse_max_keys(query)?;
        let prefix = get_query_param(query, "prefix")
            .unwrap_or_default()
            .to_string();
        let delimiter = get_query_param(query, "delimiter")
            .filter(|d| !d.is_empty())
            .map(str::to_string);
        let key_marker = get_query_param(query, "key-marker")
            .filter(|m| !m.is_empty())
            .map(str::to_string);
        let version_id_marker = get_query_param(query, "version-id-marker")
            .filter(|m| !m.is_empty())
            .map(str::to_string);

        let resp = state
            .store
            .list_object_versions(ListObjectVersionsReq {
                ctx,
                bucket,
                prefix,
                delimiter,
                key_marker,
                version_id_marker,
                max_keys,
            })
            .await?;
        return Ok(xml_response(
            StatusCode::OK,
            render_list_object_versions_xml(&resp, url_encode),
        ));
    }

    if has_query_key(query, "delete") {
        if *method != Method::POST {
            return Err(S3Error::new(
                S3ErrorCode::MethodNotAllowed,
                "Method not allowed",
            ));
        }
        *op_name = "DeleteObjects";
        let expected_md5 = parse_optional_md5(headers)?;
        let header_csum = parse_header_checksum(headers)?;
        let has_trailer_csum = matches!(
            &auth_out.payload_mode,
            PayloadAuthMode::StreamingUnsignedTrailer { .. }
                | PayloadAuthMode::StreamingSignedChunked {
                    trailer_header: Some(_),
                    ..
                }
        );
        // [FR-46] DeleteObjects requires Content-MD5 or x-amz-checksum-*
        if expected_md5.is_none()
            && header_csum.as_ref().and_then(|(_, v)| v.as_ref()).is_none()
            && !has_trailer_csum
        {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Missing required header for this request: Content-MD5 or x-amz-checksum-*",
            ));
        }

        let stream = HyperVerifiedBodyStream::new(
            incoming,
            auth_out.payload_mode,
            content_length,
            expected_md5,
            header_csum,
            1024 * 1024,
        )?;
        let (raw_xml, _) = stream.collect_bounded().await?;
        let (quiet, items) = parse_delete_objects_xml(&raw_xml)?;
        let bypass_governance = parse_bypass_governance_header(headers);
        let resp = state
            .store
            .delete_objects(DeleteObjectsReq {
                ctx,
                bucket,
                quiet,
                items,
                bypass_governance,
            })
            .await?;
        return Ok(xml_response(
            StatusCode::OK,
            render_delete_objects_xml(&resp),
        ));
    }

    match *method {
        Method::PUT => {
            *op_name = "CreateBucket";
            let acl = parse_acl_headers(headers, &state.auth)?;
            let object_ownership = parse_object_ownership_header(headers)?;
            let object_lock_enabled = parse_bucket_object_lock_enabled_header(headers)?;
            let expected_md5 = parse_optional_md5(headers)?;
            let header_csum = parse_header_checksum(headers)?;

            // Note: `CreateBucket` allows missing Content-Length (`test_bucket_create_contentlength_none`)
            let stream = HyperVerifiedBodyStream::new(
                incoming,
                auth_out.payload_mode,
                content_length,
                expected_md5,
                header_csum,
                64 * 1024,
            )?;
            let (body_bytes, _) = stream.collect_bounded().await?;
            let location_constraint = parse_create_bucket_xml(&body_bytes)?;

            let snap = state
                .store
                .create_bucket(CreateBucketReq {
                    ctx,
                    bucket: bucket.clone(),
                    location_constraint,
                    object_ownership,
                    acl,
                    object_lock_enabled,
                })
                .await?;

            let mut resp = Response::builder()
                .status(StatusCode::OK)
                .header("Location", format!("/{}", snap.name))
                .header("Content-Length", "0")
                .body(S3ResponseBody::empty())
                .unwrap();
            let _ = &mut resp;
            Ok(resp)
        }
        Method::HEAD => {
            *op_name = "HeadBucket";
            drain_empty_or_ignore(incoming).await;
            let snap = state.store.head_bucket(BucketRef { ctx, bucket }).await?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("x-amz-bucket-region", snap.region)
                .header("Content-Length", "0")
                .body(S3ResponseBody::empty())
                .unwrap())
        }
        Method::DELETE => {
            *op_name = "DeleteBucket";
            drain_empty_or_ignore(incoming).await;
            state.store.delete_bucket(BucketRef { ctx, bucket }).await?;
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(S3ResponseBody::empty())
                .unwrap())
        }
        Method::GET => {
            drain_empty_or_ignore(incoming).await;
            let url_encode = parse_encoding_type(query)?;
            let max_keys = parse_max_keys(query)?;
            let prefix = get_query_param(query, "prefix")
                .unwrap_or_default()
                .to_string();
            let delimiter = get_query_param(query, "delimiter")
                .filter(|d| !d.is_empty())
                .map(str::to_string);

            match get_query_param(query, "list-type") {
                Some("2") => {
                    *op_name = "ListObjectsV2";
                    let start_after = get_query_param(query, "start-after").map(str::to_string);
                    let continuation_token =
                        get_query_param(query, "continuation-token").map(str::to_string);
                    let fetch_owner = get_query_param(query, "fetch-owner")
                        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
                    let resp = state
                        .store
                        .list_objects_v2(ListObjectsV2Req {
                            ctx,
                            bucket,
                            prefix,
                            delimiter,
                            start_after,
                            continuation_token,
                            max_keys,
                            fetch_owner,
                        })
                        .await?;
                    Ok(xml_response(
                        StatusCode::OK,
                        render_list_objects_v2_xml(&resp, fetch_owner, url_encode),
                    ))
                }
                Some(_) => Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid list-type parameter; only '2' is supported.",
                )),
                None => {
                    *op_name = "ListObjectsV1";
                    let marker = get_query_param(query, "marker").map(str::to_string);
                    let resp = state
                        .store
                        .list_objects_v1(ListObjectsV1Req {
                            ctx,
                            bucket,
                            prefix,
                            delimiter,
                            marker,
                            max_keys,
                        })
                        .await?;
                    Ok(xml_response(
                        StatusCode::OK,
                        render_list_objects_v1_xml(&resp, url_encode),
                    ))
                }
            }
        }
        Method::POST => {
            *op_name = "PostObjectNotImplemented";
            Err(S3Error::new(
                S3ErrorCode::NotImplemented,
                "POST Object form upload is scheduled for M2.",
            )
            .with_bucket(&bucket))
        }
        _ => Err(S3Error::new(
            S3ErrorCode::MethodNotAllowed,
            "The specified method is not allowed against this resource.",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_object_target<S: ObjectStore>(
    state: &AppState<S>,
    ctx: CallerContext,
    auth_out: AuthOutcome,
    method: &Method,
    headers: &HeaderMap,
    content_length: Option<u64>,
    incoming: Incoming,
    bucket: String,
    key: String,
    query: &[(String, String)],
    op_name: &mut &'static str,
) -> StoreResult<Response<S3ResponseBody<S::Reader>>> {
    // Reject unimplemented object subresources with `501 NotImplemented` (`PR-5`)
    for sub in UNIMPLEMENTED_OBJECT_SUBRESOURCES {
        if has_query_key(query, sub) {
            *op_name = "NotImplementedObjectSubresource";
            return Err(S3Error::new(
                S3ErrorCode::NotImplemented,
                format!("Object subresource '?{sub}' is not implemented yet."),
            )
            .with_key(&bucket, &key));
        }
    }

    // 0a. `GET/PUT/DELETE /{b}/{k}?tagging`
    if has_query_key(query, "tagging") {
        let version_id = get_query_param(query, "versionId").map(str::to_string);
        match *method {
            Method::GET => {
                *op_name = "GetObjectTagging";
                drain_empty_or_ignore(incoming).await;
                let resp = state
                    .store
                    .get_object_tagging(ObjectTaggingRef {
                        ctx,
                        bucket,
                        key,
                        version_id,
                    })
                    .await?;
                let xml = render_tagging_xml(&resp.tags);
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/xml")
                    .header("Content-Length", xml.len().to_string());
                if let Some(vid) = &resp.version_id {
                    builder = builder.header("x-amz-version-id", vid);
                }
                return Ok(builder.body(S3ResponseBody::from_bytes(xml)).unwrap());
            }
            Method::PUT => {
                *op_name = "PutObjectTagging";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    128 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let tags = parse_tagging_xml(&raw_xml, MAX_OBJECT_TAGS)?;
                let vid_out = state
                    .store
                    .put_object_tagging(PutObjectTaggingReq {
                        ctx,
                        bucket,
                        key,
                        version_id,
                        tags,
                    })
                    .await?;
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0");
                if let Some(vid) = &vid_out {
                    builder = builder.header("x-amz-version-id", vid);
                }
                return Ok(builder.body(S3ResponseBody::empty()).unwrap());
            }
            Method::DELETE => {
                *op_name = "DeleteObjectTagging";
                drain_empty_or_ignore(incoming).await;
                let vid_out = state
                    .store
                    .delete_object_tagging(ObjectTaggingRef {
                        ctx,
                        bucket,
                        key,
                        version_id,
                    })
                    .await?;
                let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
                if let Some(vid) = &vid_out {
                    builder = builder.header("x-amz-version-id", vid);
                }
                return Ok(builder.body(S3ResponseBody::empty()).unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "The specified method is not allowed against this resource.",
                ));
            }
        }
    }

    // 0aa. `GET/PUT /{b}/{k}?retention` (`PR-35`)
    if has_query_key(query, "retention") {
        let version_id = get_query_param(query, "versionId").map(str::to_string);
        match *method {
            Method::GET => {
                *op_name = "GetObjectRetention";
                drain_empty_or_ignore(incoming).await;
                let ret = state
                    .store
                    .get_object_retention(ObjectLockRef {
                        ctx,
                        bucket,
                        key,
                        version_id,
                    })
                    .await?;
                return Ok(xml_response(
                    StatusCode::OK,
                    render_object_retention_xml(&ret),
                ));
            }
            Method::PUT => {
                *op_name = "PutObjectRetention";
                let bypass_governance = parse_bypass_governance_header(headers);
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let retention = parse_object_retention_xml(&raw_xml)?;
                state
                    .store
                    .put_object_retention(PutObjectRetentionReq {
                        ctx,
                        bucket,
                        key,
                        version_id,
                        retention,
                        bypass_governance,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "The specified method is not allowed against this resource.",
                ));
            }
        }
    }

    // 0ab. `GET/PUT /{b}/{k}?legal-hold` (`PR-36`)
    if has_query_key(query, "legal-hold") {
        let version_id = get_query_param(query, "versionId").map(str::to_string);
        match *method {
            Method::GET => {
                *op_name = "GetObjectLegalHold";
                drain_empty_or_ignore(incoming).await;
                let status = state
                    .store
                    .get_object_legal_hold(ObjectLockRef {
                        ctx,
                        bucket,
                        key,
                        version_id,
                    })
                    .await?;
                return Ok(xml_response(
                    StatusCode::OK,
                    render_object_legal_hold_xml(status),
                ));
            }
            Method::PUT => {
                *op_name = "PutObjectLegalHold";
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let status = parse_object_legal_hold_xml(&raw_xml)?;
                state
                    .store
                    .put_object_legal_hold(PutObjectLegalHoldReq {
                        ctx,
                        bucket,
                        key,
                        version_id,
                        status,
                    })
                    .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0")
                    .body(S3ResponseBody::empty())
                    .unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "The specified method is not allowed against this resource.",
                ));
            }
        }
    }

    // 0b. `GET/PUT /{b}/{k}?acl` (`PR-32`)
    if has_query_key(query, "acl") {
        let version_id = get_query_param(query, "versionId").map(str::to_string);
        match *method {
            Method::GET => {
                *op_name = "GetObjectAcl";
                drain_empty_or_ignore(incoming).await;
                let resp = state
                    .store
                    .get_object_acl(GetObjectAclReq {
                        ctx,
                        bucket,
                        key,
                        version_id,
                    })
                    .await?;
                let xml = render_acl_xml(&resp.policy);
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/xml")
                    .header("Content-Length", xml.len().to_string());
                if let Some(vid) = &resp.version_id {
                    builder = builder.header("x-amz-version-id", vid);
                }
                return Ok(builder.body(S3ResponseBody::from_bytes(xml)).unwrap());
            }
            Method::PUT => {
                *op_name = "PutObjectAcl";
                let header_acl = parse_acl_headers(headers, &state.auth)?;
                let expected_md5 = parse_optional_md5(headers)?;
                let header_csum = parse_header_checksum(headers)?;
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    header_csum,
                    64 * 1024,
                )?;
                let (raw_body, _) = stream.collect_bounded().await?;
                let acl = match header_acl {
                    Some(spec) => {
                        if !raw_body.is_empty() {
                            return Err(S3Error::new(
                                S3ErrorCode::InvalidRequest,
                                "This request does not support content when ACL headers are provided",
                            ));
                        }
                        spec
                    }
                    None => {
                        if raw_body.is_empty() {
                            return Err(S3Error::new(
                                S3ErrorCode::MissingSecurityHeader,
                                "Your request was missing a required header",
                            ));
                        }
                        let pol = parse_acl_xml(
                            &raw_body,
                            |uid| state.auth.lookup_by_user_id(uid),
                            |em| state.auth.lookup_by_email(em),
                        )?;
                        AclSpec::Policy(pol)
                    }
                };
                let vid_out = state
                    .store
                    .put_object_acl(PutObjectAclReq {
                        ctx,
                        bucket,
                        key,
                        version_id,
                        acl,
                    })
                    .await?;
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Length", "0");
                if let Some(vid) = &vid_out {
                    builder = builder.header("x-amz-version-id", vid);
                }
                return Ok(builder.body(S3ResponseBody::empty()).unwrap());
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::MethodNotAllowed,
                    "The specified method is not allowed against this resource.",
                ));
            }
        }
    }

    // 1. `GET /{b}/{k}?attributes` (`FR-47`)
    if has_query_key(query, "attributes") {
        if *method != Method::GET {
            return Err(S3Error::new(
                S3ErrorCode::MethodNotAllowed,
                "The specified method is not allowed against this resource.",
            ));
        }
        *op_name = "GetObjectAttributes";
        drain_empty_or_ignore(incoming).await;
        let attrs = parse_object_attributes_header(headers)?;
        let max_parts = parse_optional_max_parts_header(headers)?;
        let part_number_marker = parse_optional_part_marker_header(headers)?;
        let version_id = get_query_param(query, "versionId").map(str::to_string);
        let raw_sse = extract_raw_sse_headers(headers)?;

        let resp = state
            .store
            .get_object_attributes(GetObjectAttributesReq {
                ctx,
                bucket,
                key,
                version_id,
                attrs,
                max_parts,
                part_number_marker,
                raw_sse,
            })
            .await?;

        let last_modified_http = httpdate::fmt_http_date(
            UNIX_EPOCH + std::time::Duration::from_millis(resp.last_modified_ms.max(0) as u64),
        );
        let xml = render_get_object_attributes_xml(&resp);
        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/xml")
            .header("Content-Length", xml.len().to_string())
            .header("Last-Modified", last_modified_http);
        if let Some(vid) = &resp.version_id
            && vid != "null" {
                builder = builder.header("x-amz-version-id", vid);
            }
        builder = apply_sse_builder(builder, &resp.sse);
        return Ok(builder.body(S3ResponseBody::from_bytes(xml)).unwrap());
    }

    // 2. `POST /{b}/{k}?uploads` (`CreateMultipartUpload`, `FR-23`)
    if has_query_key(query, "uploads") {
        if *method != Method::POST {
            return Err(S3Error::new(
                S3ErrorCode::MethodNotAllowed,
                "The specified method is not allowed against this resource.",
            ));
        }
        *op_name = "CreateMultipartUpload";
        validate_storage_class(headers)?;
        let acl = parse_acl_headers(headers, &state.auth)?;
        drain_empty_or_ignore(incoming).await;

        let sys_meta = extract_system_meta(headers);
        let user_meta = extract_user_meta(headers)?;
        let tags = parse_optional_object_tagging_header(headers)?;
        let raw_sse = extract_raw_sse_headers(headers)?;
        let raw_lock = extract_raw_upload_lock_headers(headers)?;
        let checksum_algorithm = match headers.get("x-amz-checksum-algorithm") {
            Some(hv) => {
                let s = hv
                    .to_str()
                    .map_err(|_| {
                        S3Error::new(
                            S3ErrorCode::InvalidRequest,
                            "Invalid x-amz-checksum-algorithm header",
                        )
                    })?
                    .trim();
                Some(ChecksumAlgorithm::from_aws_str(s).ok_or_else(|| {
                    S3Error::new(
                        S3ErrorCode::InvalidRequest,
                        "Checksum algorithm provided is unsupported.",
                    )
                })?)
            }
            None => None,
        };
        let checksum_type = match headers.get("x-amz-checksum-type") {
            Some(hv) => {
                let s = hv
                    .to_str()
                    .map_err(|_| {
                        S3Error::new(
                            S3ErrorCode::InvalidRequest,
                            "Invalid x-amz-checksum-type header",
                        )
                    })?
                    .trim();
                Some(ChecksumType::from_aws_str(s).ok_or_else(|| {
                    S3Error::new(
                        S3ErrorCode::InvalidRequest,
                        "Invalid x-amz-checksum-type header",
                    )
                })?)
            }
            None => None,
        };

        let resp = state
            .store
            .create_multipart_upload(CreateMultipartUploadReq {
                ctx,
                bucket,
                key,
                sys_meta,
                user_meta,
                acl,
                tags,
                checksum_algorithm,
                checksum_type,
                raw_sse,
                raw_lock,
            })
            .await?;

        let xml = render_initiate_multipart_xml(&resp);
        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/xml")
            .header("Content-Length", xml.len().to_string());
        if let Some(alg) = resp.checksum_algorithm {
            builder = builder.header("x-amz-checksum-algorithm", alg.as_aws_str());
        }
        if let Some(ct) = resp.checksum_type {
            builder = builder.header("x-amz-checksum-type", ct.as_aws_str());
        }
        builder = apply_sse_builder(builder, &resp.sse);
        return Ok(builder.body(S3ResponseBody::from_bytes(xml)).unwrap());
    }

    // 3. `?uploadId=U` (`UploadPart`, `UploadPartCopy`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListParts`)
    if let Some(upload_id_raw) = get_query_param(query, "uploadId") {
        let upload_id = upload_id_raw.to_string();
        let part_num_param = get_query_param(query, "partNumber");

        return match (method, part_num_param) {
            (&Method::PUT, Some(pn_raw)) => {
                let part_number = pn_raw.parse::<u32>().map_err(|_| {
                    S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Part number must be an integer between 1 and 10000, inclusive",
                    )
                })?;
                if part_number == 0 || part_number > MAX_PARTS_COUNT {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Part number must be an integer between 1 and 10000, inclusive",
                    ));
                }

                if let Some(copy_src_val) = headers.get("x-amz-copy-source") {
                    *op_name = "UploadPartCopy";
                    drain_empty_or_ignore(incoming).await;
                    let copy_src_raw = copy_src_val.to_str().map_err(|_| {
                        S3Error::new(S3ErrorCode::InvalidArgument, "Invalid x-amz-copy-source")
                    })?;
                    let (src_bucket, src_key, src_version_id) = parse_copy_source(copy_src_raw)?;
                    let src_range = match headers.get("x-amz-copy-source-range") {
                        Some(hv) => {
                            let s = hv.to_str().map_err(|_| {
                                S3Error::new(
                                    S3ErrorCode::InvalidArgument,
                                    "Invalid x-amz-copy-source-range header",
                                )
                            })?;
                            Some(parse_copy_source_range(s)?)
                        }
                        None => None,
                    };
                    let src_preconditions = extract_copy_source_preconditions(headers)?;
                    let raw_copy_src_sse = extract_raw_copy_source_sse_headers(headers)?;
                    let raw_sse = extract_raw_sse_headers(headers)?;

                    let resp = state
                        .store
                        .upload_part_copy(UploadPartCopyReq {
                            ctx,
                            src_bucket,
                            src_key,
                            src_version_id,
                            src_range,
                            src_preconditions,
                            dst_bucket: bucket,
                            dst_key: key,
                            upload_id,
                            part_number,
                            raw_copy_src_sse,
                            raw_sse,
                        })
                        .await?;

                    let xml = render_copy_part_xml(&resp);
                    let mut builder = Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/xml")
                        .header("Content-Length", xml.len().to_string());
                    if let Some(sv) = &resp.src_version_id
                        && sv != "null" {
                            builder = builder.header("x-amz-copy-source-version-id", sv);
                        }
                    builder = apply_sse_builder(builder, &resp.sse);
                    Ok(builder.body(S3ResponseBody::from_bytes(xml)).unwrap())
                } else {
                    *op_name = "UploadPart";
                    let is_streaming_aws_chunked = matches!(
                        auth_out.payload_mode,
                        PayloadAuthMode::StreamingSignedChunked { .. }
                            | PayloadAuthMode::StreamingUnsignedTrailer { .. }
                    );
                    let is_http_chunked = headers
                        .get("transfer-encoding")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|s| s.to_ascii_lowercase().contains("chunked"));

                    if content_length.is_none() && !is_streaming_aws_chunked && !is_http_chunked {
                        return Err(S3Error::new(
                            S3ErrorCode::MissingContentLength,
                            "You must provide the Content-Length HTTP header.",
                        ));
                    }

                    let expected_md5 = parse_optional_md5(headers)?;
                    let header_csum = parse_header_checksum(headers)?;
                    let raw_sse = extract_raw_sse_headers(headers)?;
                    let effective_expected_len = if is_http_chunked && !is_streaming_aws_chunked {
                        headers
                            .get("x-amz-decoded-content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.trim().parse::<u64>().ok())
                    } else {
                        content_length
                    };

                    let stream = HyperVerifiedBodyStream::new(
                        incoming,
                        auth_out.payload_mode,
                        effective_expected_len,
                        expected_md5,
                        header_csum,
                        MAX_PART_SIZE_BYTES,
                    )?;

                    let resp = state
                        .store
                        .upload_part(
                            UploadPartReq {
                                ctx,
                                bucket,
                                key,
                                upload_id,
                                part_number,
                                max_bytes_limit: MAX_PART_SIZE_BYTES,
                                raw_sse,
                            },
                            stream,
                        )
                        .await?;

                    let mut builder = Response::builder()
                        .status(StatusCode::OK)
                        .header("ETag", &resp.etag)
                        .header("Content-Length", "0");
                    if let Some(csum) = &resp.checksum {
                        builder = builder.header(csum.algorithm.header_name(), &csum.value_b64);
                    }
                    builder = apply_sse_builder(builder, &resp.sse);
                    Ok(builder.body(S3ResponseBody::empty()).unwrap())
                }
            }
            (&Method::POST, None) => {
                *op_name = "CompleteMultipartUpload";
                let expected_object_size = match headers.get("x-amz-mp-object-size") {
                    Some(hv) => {
                        let s = hv
                            .to_str()
                            .map_err(|_| {
                                S3Error::new(
                                    S3ErrorCode::InvalidArgument,
                                    "Invalid x-amz-mp-object-size header",
                                )
                            })?
                            .trim();
                        Some(s.parse::<u64>().map_err(|_| {
                            S3Error::new(
                                S3ErrorCode::InvalidArgument,
                                "Invalid x-amz-mp-object-size header",
                            )
                        })?)
                    }
                    None => None,
                };
                let expected_checksum = parse_complete_mp_checksum_header(headers)?;
                let preconditions = extract_write_preconditions(headers);
                let expected_md5 = parse_optional_md5(headers)?;
                let raw_sse = extract_raw_sse_headers(headers)?;

                // Note: Do NOT pass `x-amz-checksum-*` into `HyperVerifiedBodyStream` here,
                // because on `CompleteMultipartUpload` `x-amz-checksum-*` specifies the target
                // assembled object's checksum, NOT the XML request body's checksum!
                let stream = HyperVerifiedBodyStream::new(
                    incoming,
                    auth_out.payload_mode,
                    content_length,
                    expected_md5,
                    None,
                    2 * 1024 * 1024, // 2 MiB (`NFR-8`)
                )?;
                let (raw_xml, _) = stream.collect_bounded().await?;
                let parts = parse_complete_multipart_xml(&raw_xml)?;

                let resp = state
                    .store
                    .complete_multipart_upload(CompleteMultipartUploadReq {
                        ctx,
                        bucket,
                        key,
                        upload_id,
                        parts,
                        expected_checksum,
                        expected_object_size,
                        preconditions,
                        raw_sse,
                    })
                    .await?;

                let host_str = headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("localhost");
                let location = format!(
                    "http://{host_str}/{}/{}",
                    aws_uri_encode(&resp.bucket, true),
                    aws_uri_encode(&resp.key, false)
                );
                let xml = render_complete_multipart_xml(&location, &resp);
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/xml")
                    .header("Content-Length", xml.len().to_string());
                if let Some(vid) = &resp.version_id
                    && vid != "null" {
                        builder = builder.header("x-amz-version-id", vid);
                    }
                if let Some(csum) = &resp.checksum {
                    builder = builder
                        .header(csum.algorithm.header_name(), &csum.value_b64)
                        .header("x-amz-checksum-type", csum.checksum_type.as_aws_str());
                }
                builder = apply_sse_builder(builder, &resp.sse);
                if let Some(exp) = &resp.expiration_header {
                    builder = builder.header("x-amz-expiration", exp);
                }
                Ok(builder.body(S3ResponseBody::from_bytes(xml)).unwrap())
            }
            (&Method::DELETE, None) => {
                *op_name = "AbortMultipartUpload";
                drain_empty_or_ignore(incoming).await;
                state
                    .store
                    .abort_multipart_upload(AbortMultipartUploadReq {
                        ctx,
                        bucket,
                        key,
                        upload_id,
                    })
                    .await?;
                Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(S3ResponseBody::empty())
                    .unwrap())
            }
            (&Method::GET, None) => {
                *op_name = "ListParts";
                drain_empty_or_ignore(incoming).await;
                let url_encode = parse_encoding_type(query)?;
                let max_parts = parse_bounded_limit_param(query, "max-parts", 1000)?;
                let part_number_marker = match get_query_param(query, "part-number-marker") {
                    None | Some("") => 0u32,
                    Some(raw) => {
                        let v = raw.parse::<i64>().map_err(|_| {
                            S3Error::new(
                                S3ErrorCode::InvalidArgument,
                                "Argument partNumberMarker must be an integer between 0 and 10000",
                            )
                        })?;
                        if !(0..=2_147_483_647).contains(&v) {
                            return Err(S3Error::new(
                                S3ErrorCode::InvalidArgument,
                                "Argument partNumberMarker must be an integer between 0 and 10000",
                            ));
                        }
                        v as u32
                    }
                };

                let resp = state
                    .store
                    .list_parts(ListPartsReq {
                        ctx,
                        bucket,
                        key,
                        upload_id,
                        max_parts,
                        part_number_marker,
                    })
                    .await?;
                Ok(xml_response(
                    StatusCode::OK,
                    render_list_parts_xml(&resp, url_encode),
                ))
            }
            _ => Err(S3Error::new(
                S3ErrorCode::MethodNotAllowed,
                "The specified method is not allowed against this resource.",
            )),
        };
    }

    match *method {
        Method::PUT => {
            validate_storage_class(headers)?;
            let acl = parse_acl_headers(headers, &state.auth)?;

            if let Some(copy_src_val) = headers.get("x-amz-copy-source") {
                *op_name = "CopyObject";
                drain_empty_or_ignore(incoming).await;
                let copy_src_raw = copy_src_val.to_str().map_err(|_| {
                    S3Error::new(S3ErrorCode::InvalidArgument, "Invalid x-amz-copy-source")
                })?;
                let (src_bucket, src_key, src_version_id) = parse_copy_source(copy_src_raw)?;
                let replace_metadata = match headers
                    .get("x-amz-metadata-directive")
                    .and_then(|v| v.to_str().ok())
                {
                    None | Some("COPY") => false,
                    Some("REPLACE") => true,
                    Some(_) => {
                        return Err(S3Error::new(
                            S3ErrorCode::InvalidArgument,
                            "Unknown metadata directive.",
                        ))
                    }
                };
                let tagging_directive = parse_tagging_directive_header(headers)?;
                let tags = parse_optional_object_tagging_header(headers)?;
                let sys_meta = extract_system_meta(headers);
                let user_meta = extract_user_meta(headers)?;
                let src_preconditions = extract_copy_source_preconditions(headers)?;
                let dst_preconditions = extract_write_preconditions(headers);
                let raw_copy_src_sse = extract_raw_copy_source_sse_headers(headers)?;
                let raw_sse = extract_raw_sse_headers(headers)?;
                let raw_lock = extract_raw_upload_lock_headers(headers)?;

                let resp = state
                    .store
                    .copy_object(CopyObjectReq {
                        ctx,
                        src_bucket,
                        src_key,
                        src_version_id,
                        dst_bucket: bucket,
                        dst_key: key,
                        replace_metadata,
                        sys_meta,
                        user_meta,
                        acl,
                        tagging_directive,
                        tags,
                        src_preconditions,
                        dst_preconditions,
                        raw_copy_src_sse,
                        raw_sse,
                        raw_lock,
                    })
                    .await?;

                let xml = render_copy_object_xml(&resp);
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/xml")
                    .header("Content-Length", xml.len().to_string());
                if let Some(sv) = &resp.src_version_id {
                    builder = builder.header("x-amz-copy-source-version-id", sv);
                }
                if let Some(dv) = &resp.dst_version_id
                    && dv != "null" {
                        builder = builder.header("x-amz-version-id", dv);
                    }
                builder = apply_sse_builder(builder, &resp.sse);
                if let Some(exp) = &resp.expiration_header {
                    builder = builder.header("x-amz-expiration", exp);
                }
                return Ok(builder.body(S3ResponseBody::from_bytes(xml)).unwrap());
            }

            // Standard `PutObject`
            *op_name = "PutObject";
            let is_streaming_aws_chunked = matches!(
                auth_out.payload_mode,
                PayloadAuthMode::StreamingSignedChunked { .. }
                    | PayloadAuthMode::StreamingUnsignedTrailer { .. }
            );
            let is_http_chunked = headers
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.to_ascii_lowercase().contains("chunked"));

            if content_length.is_none() && !is_streaming_aws_chunked && !is_http_chunked {
                return Err(S3Error::new(
                    S3ErrorCode::MissingContentLength,
                    "You must provide the Content-Length HTTP header.",
                ));
            }

            let expected_md5 = parse_optional_md5(headers)?;
            let header_csum = parse_header_checksum(headers)?;
            let sys_meta = extract_system_meta(headers);
            let user_meta = extract_user_meta(headers)?;
            let tags = parse_optional_object_tagging_header(headers)?;
            let preconditions = extract_write_preconditions(headers);
            let raw_sse = extract_raw_sse_headers(headers)?;
            let raw_lock = extract_raw_upload_lock_headers(headers)?;
            let max_put = MAX_SINGLE_PUT_BYTES.min(state.cfg.max_object_size);

            let effective_expected_len = if is_http_chunked && !is_streaming_aws_chunked {
                headers
                    .get("x-amz-decoded-content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.trim().parse::<u64>().ok())
            } else {
                content_length
            };

            let stream = HyperVerifiedBodyStream::new(
                incoming,
                auth_out.payload_mode,
                effective_expected_len,
                expected_md5,
                header_csum,
                max_put,
            )?;

            let resp = state
                .store
                .put_object(
                    PutObjectReq {
                        ctx,
                        bucket,
                        key,
                        sys_meta,
                        user_meta,
                        acl,
                        tags,
                        preconditions,
                        max_bytes_limit: max_put,
                        raw_sse,
                        raw_lock,
                    },
                    stream,
                )
                .await?;

            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header("ETag", &resp.etag)
                .header("Content-Length", "0")
                .header(
                    resp.checksum.algorithm.header_name(),
                    &resp.checksum.value_b64,
                )
                .header("x-amz-checksum-type", resp.checksum.checksum_type.as_str());
            if let Some(vid) = &resp.version_id
                && vid != "null" {
                    builder = builder.header("x-amz-version-id", vid);
                }
            builder = apply_sse_builder(builder, &resp.sse);
            if let Some(exp) = &resp.expiration_header {
                builder = builder.header("x-amz-expiration", exp);
            }
            Ok(builder.body(S3ResponseBody::empty()).unwrap())
        }
        Method::GET | Method::HEAD => {
            let is_head = *method == Method::HEAD;
            *op_name = if is_head { "HeadObject" } else { "GetObject" };
            drain_empty_or_ignore(incoming).await;

            // [FR-11] Check `response-*` query overrides
            let overrides = extract_response_overrides(query);
            if overrides.has_any() && !ctx.is_authenticated {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "Request specific response headers cannot be used for anonymous GET requests.",
                ));
            }

            let version_id = get_query_param(query, "versionId").map(str::to_string);
            let part_number = match get_query_param(query, "partNumber") {
                Some(raw) => Some(raw.parse::<u32>().map_err(|_| {
                    S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Part number must be an integer between 1 and 10000, inclusive",
                    )
                })?),
                None => None,
            };

            let range = match headers.get("range").and_then(|v| v.to_str().ok()) {
                Some(r) if part_number.is_none() => match parse_range_header(r) {
                    ParsedRangeHeader::Single(spec) => Some(spec),
                    ParsedRangeHeader::Ignore | ParsedRangeHeader::Invalid => {
                        if matches!(parse_range_header(r), ParsedRangeHeader::Invalid) {
                            return Err(S3Error::new(
                                S3ErrorCode::InvalidRange,
                                "The requested range is not satisfiable",
                            ));
                        }
                        None
                    }
                },
                _ => None,
            };

            let preconditions = extract_read_preconditions(headers)?;
            let checksum_mode_enabled = headers
                .get("x-amz-checksum-mode")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("ENABLED"));
            let raw_sse = extract_raw_sse_headers(headers)?;

            let get_req = GetObjectReq {
                ctx,
                bucket,
                key,
                version_id,
                range,
                part_number,
                preconditions,
                checksum_mode_enabled,
                raw_sse,
            };

            if is_head {
                let meta = state.store.head_object(get_req).await?;
                build_object_read_response(meta, &overrides, S3ResponseBody::empty())
            } else {
                let resp = state.store.get_object(get_req).await?;
                state
                    .metrics
                    .bytes_out_total
                    .fetch_add(resp.meta.content_length, std::sync::atomic::Ordering::Relaxed);
                build_object_read_response(
                    resp.meta,
                    &overrides,
                    S3ResponseBody::Stream(resp.reader),
                )
            }
        }
        Method::DELETE => {
            *op_name = "DeleteObject";
            drain_empty_or_ignore(incoming).await;
            let version_id = get_query_param(query, "versionId").map(str::to_string);
            let if_match = parse_etag_list_header(headers, "if-match");
            let bypass_governance = parse_bypass_governance_header(headers);

            let resp = state
                .store
                .delete_object(DeleteObjectReq {
                    ctx,
                    bucket,
                    key,
                    version_id,
                    if_match,
                    bypass_governance,
                })
                .await?;

            let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
            if resp.is_delete_marker {
                builder = builder.header("x-amz-delete-marker", "true");
            }
            if let Some(vid) = &resp.version_id {
                builder = builder.header("x-amz-version-id", vid);
            }
            Ok(builder.body(S3ResponseBody::empty()).unwrap())
        }
        _ => Err(S3Error::new(
            S3ErrorCode::MethodNotAllowed,
            "The specified method is not allowed against this resource.",
        )),
    }
}

trait ChecksumTypeExt {
    fn as_str(&self) -> &'static str;
}

impl ChecksumTypeExt for ChecksumType {
    fn as_str(&self) -> &'static str {
        self.as_aws_str()
    }
}

struct ResponseOverrides {
    content_type: Option<String>,
    content_language: Option<String>,
    expires: Option<String>,
    cache_control: Option<String>,
    content_disposition: Option<String>,
    content_encoding: Option<String>,
}

impl ResponseOverrides {
    fn has_any(&self) -> bool {
        self.content_type.is_some()
            || self.content_language.is_some()
            || self.expires.is_some()
            || self.cache_control.is_some()
            || self.content_disposition.is_some()
            || self.content_encoding.is_some()
    }
}

fn extract_response_overrides(query: &[(String, String)]) -> ResponseOverrides {
    ResponseOverrides {
        content_type: get_query_param(query, "response-content-type").map(str::to_string),
        content_language: get_query_param(query, "response-content-language").map(str::to_string),
        expires: get_query_param(query, "response-expires").map(str::to_string),
        cache_control: get_query_param(query, "response-cache-control").map(str::to_string),
        content_disposition: get_query_param(query, "response-content-disposition")
            .map(str::to_string),
        content_encoding: get_query_param(query, "response-content-encoding").map(str::to_string),
    }
}

fn build_object_read_response<R>(
    meta: ObjectMetaSnapshot,
    overrides: &ResponseOverrides,
    body: S3ResponseBody<R>,
) -> StoreResult<Response<S3ResponseBody<R>>> {
    let status = if meta.content_range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };

    let last_modified_http = httpdate::fmt_http_date(
        UNIX_EPOCH + std::time::Duration::from_millis(meta.last_modified_ms.max(0) as u64),
    );
    let content_type = overrides
        .content_type
        .as_deref()
        .unwrap_or(&meta.sys_meta.content_type);

    let mut resp = Response::builder()
        .status(status)
        .header("ETag", &meta.etag)
        .header("Last-Modified", last_modified_http)
        .header("Accept-Ranges", "bytes")
        .header("Content-Length", meta.content_length.to_string())
        .body(body)
        .unwrap();

    let hdrs = resp.headers_mut();
    insert_header_latin1_safe(hdrs, "content-type", content_type);

    if let Some((start, end, total)) = meta.content_range {
        insert_header_latin1_safe(
            hdrs,
            "content-range",
            &format!("bytes {start}-{end}/{total}"),
        );
    }
    if let Some(vid) = &meta.version_id
        && vid != "null" {
            insert_header_latin1_safe(hdrs, "x-amz-version-id", vid);
        }
    if let Some(pc) = meta.parts_count {
        insert_header_latin1_safe(hdrs, "x-amz-mp-parts-count", &pc.to_string());
    }
    if meta.tags_count > 0 {
        insert_header_latin1_safe(hdrs, "x-amz-tagging-count", &meta.tags_count.to_string());
    }
    if let Some(csum) = &meta.checksum {
        insert_header_latin1_safe(hdrs, csum.algorithm.header_name(), &csum.value_b64);
        insert_header_latin1_safe(hdrs, "x-amz-checksum-type", csum.checksum_type.as_aws_str());
    }
    apply_sse_hdr_map(hdrs, &meta.sse);
    if let Some(ret) = &meta.retention {
        insert_header_latin1_safe(hdrs, "x-amz-object-lock-mode", ret.mode.as_aws_str());
        insert_header_latin1_safe(
            hdrs,
            "x-amz-object-lock-retain-until-date",
            &format_iso8601_utc_us(ret.retain_until_us),
        );
    }
    if let Some(lh) = &meta.legal_hold {
        insert_header_latin1_safe(hdrs, "x-amz-object-lock-legal-hold", lh.as_aws_str());
    }
    if let Some(exp) = &meta.expiration_header {
        insert_header_latin1_safe(hdrs, "x-amz-expiration", exp);
    }

    if let Some(v) = overrides
        .content_encoding
        .as_deref()
        .or(meta.sys_meta.content_encoding.as_deref())
    {
        insert_header_latin1_safe(hdrs, "content-encoding", v);
    }
    if let Some(v) = overrides
        .content_disposition
        .as_deref()
        .or(meta.sys_meta.content_disposition.as_deref())
    {
        insert_header_latin1_safe(hdrs, "content-disposition", v);
    }
    if let Some(v) = overrides
        .content_language
        .as_deref()
        .or(meta.sys_meta.content_language.as_deref())
    {
        insert_header_latin1_safe(hdrs, "content-language", v);
    }
    if let Some(v) = overrides
        .cache_control
        .as_deref()
        .or(meta.sys_meta.cache_control.as_deref())
    {
        insert_header_latin1_safe(hdrs, "cache-control", v);
    }
    if let Some(v) = overrides
        .expires
        .as_deref()
        .or(meta.sys_meta.expires.as_deref())
    {
        insert_header_latin1_safe(hdrs, "expires", v);
    }

    for (mk, mv) in &meta.user_meta {
        let hname = format!("x-amz-meta-{mk}");
        insert_header_latin1_safe(hdrs, &hname, mv);
    }

    Ok(resp)
}

fn insert_header_latin1_safe(hdrs: &mut HeaderMap, name: &str, value: &str) {
    let Ok(hname) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    if value.is_ascii() {
        if let Ok(hv) = HeaderValue::from_str(value) {
            hdrs.insert(hname, hv);
        }
    } else if value.chars().all(|c| (c as u32) <= 0xFF) {
        let latin1: Vec<u8> = value.chars().map(|c| c as u8).collect();
        if let Ok(hv) = HeaderValue::from_bytes(&latin1) {
            hdrs.insert(hname, hv);
        }
    } else {
        let encoded = format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
        );
        if let Ok(hv) = HeaderValue::from_str(&encoded) {
            hdrs.insert(hname, hv);
        }
    }
}

fn build_error_response<R>(
    err: S3Error,
    is_head: bool,
    request_id: &str,
    host_id: &str,
) -> Response<S3ResponseBody<R>> {
    let status =
        StatusCode::from_u16(err.code.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let no_body = is_head || status == StatusCode::NOT_MODIFIED;

    let body = if no_body {
        S3ResponseBody::empty()
    } else {
        let xml = render_error_xml(&err, request_id, host_id);
        S3ResponseBody::from_bytes(Bytes::from(xml))
    };

    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let hdrs = resp.headers_mut();
    if !no_body {
        hdrs.insert("content-type", HeaderValue::from_static("application/xml"));
    }
    for (k, v) in &err.extra_headers {
        insert_header_latin1_safe(hdrs, k, v);
    }
    inject_common_headers(hdrs, request_id, host_id);
    resp
}

fn inject_common_headers(hdrs: &mut HeaderMap, request_id: &str, host_id: &str) {
    if let Ok(hv) = HeaderValue::from_str(request_id) {
        hdrs.insert("x-amz-request-id", hv);
    }
    if let Ok(hv) = HeaderValue::from_str(host_id) {
        hdrs.insert("x-amz-id-2", hv);
    }
    if let Ok(hv) = HeaderValue::from_str(&httpdate::fmt_http_date(SystemTime::now())) {
        hdrs.insert("date", hv);
    }
    hdrs.insert("server", HeaderValue::from_static("s3d"));
}

fn xml_response<R>(status: StatusCode, xml: String) -> Response<S3ResponseBody<R>> {
    let len = xml.len().to_string();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/xml")
        .header("Content-Length", len)
        .body(S3ResponseBody::from_bytes(Bytes::from(xml)))
        .unwrap()
}

fn generate_request_ids() -> (String, String) {
    let mut rng = rand::thread_rng();
    let req_u64 = rng.next_u64();
    let mut host_raw = [0u8; 32];
    rng.fill_bytes(&mut host_raw);
    (
        format!("{req_u64:016X}"),
        base64::engine::general_purpose::STANDARD.encode(host_raw),
    )
}

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn get_query_param<'a>(query: &'a [(String, String)], key: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn has_query_key(query: &[(String, String)], key: &str) -> bool {
    query.iter().any(|(k, _)| k == key)
}

fn parse_encoding_type(query: &[(String, String)]) -> StoreResult<bool> {
    match get_query_param(query, "encoding-type") {
        None | Some("") => Ok(false),
        Some("url") => Ok(true),
        Some(_) => Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid Encoding Method specified in Request",
        )),
    }
}

fn parse_max_keys(query: &[(String, String)]) -> StoreResult<usize> {
    parse_bounded_limit_param(query, "max-keys", 1000)
}

fn parse_bounded_limit_param(
    query: &[(String, String)],
    param_name: &str,
    cap: usize,
) -> StoreResult<usize> {
    match get_query_param(query, param_name) {
        None => Ok(cap),
        Some(raw) => {
            let val = raw.parse::<i64>().map_err(|_| {
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    format!("Argument {param_name} must be an integer between 0 and 2147483647"),
                )
            })?;
            if !(0..=2_147_483_647).contains(&val) {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    format!("Argument {param_name} must be an integer between 0 and 2147483647"),
                ));
            }
            Ok((val as usize).min(cap))
        }
    }
}

pub fn parse_copy_source_range(raw: &str) -> StoreResult<(u64, u64)> {
    let s = raw.trim();
    let Some(rest) = s.strip_prefix("bytes=") else {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The x-amz-copy-source-range value must be of the form bytes=first-last",
        ));
    };
    if rest.contains(',') {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The x-amz-copy-source-range value must be of the form bytes=first-last",
        ));
    }
    let Some((start_s, end_s)) = rest.split_once('-') else {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The x-amz-copy-source-range value must be of the form bytes=first-last",
        ));
    };
    if start_s.is_empty() || end_s.is_empty() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The x-amz-copy-source-range value must be of the form bytes=first-last",
        ));
    }
    let start = start_s.parse::<u64>().map_err(|_| {
        S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The x-amz-copy-source-range value must be of the form bytes=first-last",
        )
    })?;
    let end = end_s.parse::<u64>().map_err(|_| {
        S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The x-amz-copy-source-range value must be of the form bytes=first-last",
        )
    })?;
    if start > end {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The first byte position must be less than or equal to the last byte position.",
        ));
    }
    Ok((start, end))
}

fn parse_object_attributes_header(headers: &HeaderMap) -> StoreResult<ObjectAttributesMask> {
    let mut mask = ObjectAttributesMask::default();
    let mut any = false;
    for hv in headers.get_all("x-amz-object-attributes") {
        let s = hv.to_str().map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid x-amz-object-attributes header",
            )
        })?;
        for tok in s.split(',') {
            let t = tok.trim();
            if t.is_empty() {
                continue;
            }
            any = true;
            match t {
                "ETag" => mask.etag = true,
                "Checksum" => mask.checksum = true,
                "ObjectParts" => mask.object_parts = true,
                "StorageClass" => mask.storage_class = true,
                "ObjectSize" => mask.object_size = true,
                _ => {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Invalid attribute name specified.",
                    ))
                }
            }
        }
    }
    if !any {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "At least one attribute must be specified in x-amz-object-attributes.",
        ));
    }
    Ok(mask)
}

fn parse_optional_max_parts_header(headers: &HeaderMap) -> StoreResult<usize> {
    let Some(hv) = headers.get("x-amz-max-parts") else {
        return Ok(1000);
    };
    let s = hv
        .to_str()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid x-amz-max-parts"))?
        .trim();
    let v = s
        .parse::<i64>()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid x-amz-max-parts"))?;
    if !(0..=2_147_483_647).contains(&v) {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid x-amz-max-parts",
        ));
    }
    Ok((v as usize).min(1000))
}

fn parse_optional_part_marker_header(headers: &HeaderMap) -> StoreResult<u32> {
    let Some(hv) = headers.get("x-amz-part-number-marker") else {
        return Ok(0);
    };
    let s = hv
        .to_str()
        .map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid x-amz-part-number-marker",
            )
        })?
        .trim();
    if s.is_empty() {
        return Ok(0);
    }
    let v = s.parse::<i64>().map_err(|_| {
        S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid x-amz-part-number-marker",
        )
    })?;
    if !(0..=2_147_483_647).contains(&v) {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid x-amz-part-number-marker",
        ));
    }
    Ok(v as u32)
}

fn parse_complete_mp_checksum_header(
    headers: &HeaderMap,
) -> StoreResult<Option<(ChecksumAlgorithm, String)>> {
    let candidates = [
        (ChecksumAlgorithm::Crc32, "x-amz-checksum-crc32"),
        (ChecksumAlgorithm::Crc32c, "x-amz-checksum-crc32c"),
        (ChecksumAlgorithm::Crc64Nvme, "x-amz-checksum-crc64nvme"),
        (ChecksumAlgorithm::Sha1, "x-amz-checksum-sha1"),
        (ChecksumAlgorithm::Sha256, "x-amz-checksum-sha256"),
    ];
    let mut found: Option<(ChecksumAlgorithm, String)> = None;
    for (alg, hname) in candidates {
        if let Some(hv) = headers.get(hname) {
            if found.is_some() {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "Expecting a single x-amz-checksum- header.",
                ));
            }
            let s = hv
                .to_str()
                .map_err(|_| S3Error::new(S3ErrorCode::BadDigest, "Invalid checksum header"))?
                .trim()
                .to_string();
            found = Some((alg, s));
        }
    }
    Ok(found)
}

fn parse_optional_content_length(headers: &HeaderMap) -> StoreResult<Option<u64>> {
    let mut vals = headers.get_all("content-length").iter();
    let Some(first) = vals.next() else {
        return Ok(None);
    };
    if vals.next().is_some() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Duplicate Content-Length headers",
        ));
    }
    let s = first
        .to_str()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid Content-Length"))?
        .trim();
    if s.is_empty() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Empty Content-Length",
        ));
    }
    let n = s
        .parse::<u64>()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid Content-Length"))?;
    Ok(Some(n))
}

fn parse_optional_md5(headers: &HeaderMap) -> StoreResult<Option<[u8; 16]>> {
    let Some(val) = headers.get("content-md5") else {
        return Ok(None);
    };
    let raw = val
        .to_str()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidDigest, "Invalid Content-MD5"))?;
    Ok(Some(parse_content_md5_header(raw)?))
}

fn parse_header_checksum(
    headers: &HeaderMap,
) -> StoreResult<Option<(ChecksumAlgorithm, Option<String>)>> {
    let candidates = [
        (ChecksumAlgorithm::Crc32, "x-amz-checksum-crc32"),
        (ChecksumAlgorithm::Crc32c, "x-amz-checksum-crc32c"),
        (ChecksumAlgorithm::Crc64Nvme, "x-amz-checksum-crc64nvme"),
        (ChecksumAlgorithm::Sha1, "x-amz-checksum-sha1"),
        (ChecksumAlgorithm::Sha256, "x-amz-checksum-sha256"),
    ];

    let mut found: Option<(ChecksumAlgorithm, String)> = None;
    for (alg, hname) in candidates {
        if let Some(hv) = headers.get(hname) {
            if found.is_some() {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "Expecting a single x-amz-checksum- header.",
                ));
            }
            let s = hv
                .to_str()
                .map_err(|_| S3Error::new(S3ErrorCode::InvalidRequest, "Invalid checksum header"))?
                .trim()
                .to_string();
            validate_checksum_b64_format(alg, &s)?;
            found = Some((alg, s));
        }
    }

    if let Some((alg, b64)) = found {
        return Ok(Some((alg, Some(b64))));
    }

    if !headers.contains_key("x-amz-trailer")
        && let Some(sdk_alg) = headers.get("x-amz-sdk-checksum-algorithm") {
            let s = sdk_alg
                .to_str()
                .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid algorithm"))?
                .trim();
            let alg = match s {
                "CRC32" => ChecksumAlgorithm::Crc32,
                "CRC32C" => ChecksumAlgorithm::Crc32c,
                "CRC64NVME" => ChecksumAlgorithm::Crc64Nvme,
                "SHA1" => ChecksumAlgorithm::Sha1,
                "SHA256" => ChecksumAlgorithm::Sha256,
                _ => {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Unsupported checksum algorithm",
                    ))
                }
            };
            return Ok(Some((alg, None)));
        }

    Ok(None)
}

fn validate_storage_class(headers: &HeaderMap) -> StoreResult<()> {
    if let Some(sc) = headers.get("x-amz-storage-class") {
        let s = sc.to_str().unwrap_or("");
        if s.trim() != "STANDARD" {
            return Err(S3Error::new(
                S3ErrorCode::InvalidStorageClass,
                "The storage class you specified is not valid",
            ));
        }
    }
    Ok(())
}

fn parse_acl_headers(headers: &HeaderMap, auth: &SigV4Verifier) -> StoreResult<Option<AclSpec>> {
    let canned = match headers.get("x-amz-acl") {
        Some(hv) => {
            let s = hv
                .to_str()
                .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid canned ACL"))?
                .trim();
            Some(
                CannedAcl::from_aws_str(s)
                    .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid canned ACL"))?,
            )
        }
        None => None,
    };

    let grant_headers = [
        ("x-amz-grant-read", AclPermission::Read),
        ("x-amz-grant-write", AclPermission::Write),
        ("x-amz-grant-read-acp", AclPermission::ReadAcp),
        ("x-amz-grant-write-acp", AclPermission::WriteAcp),
        ("x-amz-grant-full-control", AclPermission::FullControl),
    ];
    let resolve_id = |uid: &str| auth.lookup_by_user_id(uid);
    let resolve_email = |em: &str| auth.lookup_by_email(em);

    let mut grants = Vec::new();
    let mut saw_grant_hdr = false;
    for (hname, perm) in grant_headers {
        for hv in headers.get_all(hname) {
            saw_grant_hdr = true;
            let raw = hv.to_str().map_err(|_| {
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    format!("Invalid {hname} header"),
                )
            })?;
            let parsed = parse_acl_grant_header(raw, perm, &resolve_id, &resolve_email)?;
            grants.extend(parsed);
        }
    }

    match (canned, saw_grant_hdr) {
        (Some(_), true) => Err(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Specifying both Canned ACLs and Header Grants is not allowed",
        )),
        (Some(c), false) => Ok(Some(AclSpec::Canned(c))),
        (None, true) => Ok(Some(AclSpec::Grants(grants))),
        (None, false) => Ok(None),
    }
}

fn parse_object_ownership_header(headers: &HeaderMap) -> StoreResult<Option<ObjectOwnership>> {
    let Some(hv) = headers.get("x-amz-object-ownership") else {
        return Ok(None);
    };
    let s = hv
        .to_str()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid x-amz-object-ownership"))?
        .trim();
    match s {
        "BucketOwnerEnforced" => Ok(Some(ObjectOwnership::BucketOwnerEnforced)),
        "ObjectWriter" => Ok(Some(ObjectOwnership::ObjectWriter)),
        "BucketOwnerPreferred" => Ok(Some(ObjectOwnership::BucketOwnerPreferred)),
        _ => Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid x-amz-object-ownership header",
        )),
    }
}

fn extract_system_meta(headers: &HeaderMap) -> SystemMeta {
    let get_opt = |name: &str| -> Option<String> {
        headers
            .get(name)
            .map(decode_header_value_str)
    };
    let content_type =
        get_opt("content-type").unwrap_or_else(|| "binary/octet-stream".to_string());
    let raw_ce = get_opt("content-encoding");
    let content_encoding = strip_aws_chunked_encoding(raw_ce.as_deref());

    SystemMeta {
        content_type,
        content_encoding,
        content_disposition: get_opt("content-disposition"),
        content_language: get_opt("content-language"),
        cache_control: get_opt("cache-control"),
        expires: get_opt("expires"),
    }
}

fn extract_user_meta(headers: &HeaderMap) -> StoreResult<Vec<(String, String)>> {
    let mut merged: Vec<(String, String)> = Vec::new();
    for (k, v) in headers {
        if let Some(suffix) = k.as_str().strip_prefix("x-amz-meta-") {
            if suffix.is_empty() {
                continue;
            }
            let key_lower = suffix.to_ascii_lowercase();
            let val_str = decode_header_value_str(v).trim().to_string();
            if let Some(existing) = merged.iter_mut().find(|(ek, _)| ek == &key_lower) {
                existing.1.push(',');
                existing.1.push_str(&val_str);
            } else {
                merged.push((key_lower, val_str));
            }
        }
    }
    validate_user_metadata(&merged)?;
    Ok(merged)
}

fn parse_etag_list_header(headers: &HeaderMap, name: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for hv in headers.get_all(name) {
        if let Ok(s) = hv.to_str() {
            for part in s.split(',') {
                let t = part.trim();
                if !t.is_empty() {
                    out.push(t.to_string());
                }
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn parse_http_date_sec_header(headers: &HeaderMap, name: &str) -> Option<i64> {
    let hv = headers.get(name)?;
    let s = hv.to_str().ok()?.trim();
    let ms = parse_http_or_rfc2822_date_ms(s).ok()?;
    Some(ms.div_euclid(1000))
}

fn extract_read_preconditions(headers: &HeaderMap) -> StoreResult<Preconditions> {
    Ok(Preconditions {
        if_match: parse_etag_list_header(headers, "if-match"),
        if_none_match: parse_etag_list_header(headers, "if-none-match"),
        if_modified_since_sec: parse_http_date_sec_header(headers, "if-modified-since"),
        if_unmodified_since_sec: parse_http_date_sec_header(headers, "if-unmodified-since"),
    })
}

fn extract_write_preconditions(headers: &HeaderMap) -> Preconditions {
    Preconditions {
        if_match: parse_etag_list_header(headers, "if-match"),
        if_none_match: parse_etag_list_header(headers, "if-none-match"),
        if_modified_since_sec: None,
        if_unmodified_since_sec: None,
    }
}

fn extract_copy_source_preconditions(headers: &HeaderMap) -> StoreResult<Preconditions> {
    Ok(Preconditions {
        if_match: parse_etag_list_header(headers, "x-amz-copy-source-if-match"),
        if_none_match: parse_etag_list_header(headers, "x-amz-copy-source-if-none-match"),
        if_modified_since_sec: parse_http_date_sec_header(
            headers,
            "x-amz-copy-source-if-modified-since",
        ),
        if_unmodified_since_sec: parse_http_date_sec_header(
            headers,
            "x-amz-copy-source-if-unmodified-since",
        ),
    })
}

fn parse_copy_source(raw: &str) -> StoreResult<(String, String, Option<String>)> {
    let (path_part, query_part) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };
    let stripped = path_part.strip_prefix('/').unwrap_or(path_part);
    let Some((raw_b, raw_k)) = stripped.split_once('/') else {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid x-amz-copy-source header",
        ));
    };
    if raw_b.is_empty() || raw_k.is_empty() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid x-amz-copy-source header",
        ));
    }
    let src_bucket = percent_decode_once(raw_b)?;
    let src_key = percent_decode_once(raw_k)?;

    let mut src_vid = None;
    if let Some(q) = query_part {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=')
                && k == "versionId" && !v.is_empty() {
                    src_vid = Some(percent_decode_once(v)?);
                }
        }
    }
    Ok((src_bucket, src_key, src_vid))
}

fn apply_cors_headers(hdrs: &mut HeaderMap, cors: &CorsResponseHeaders) {
    insert_header_latin1_safe(hdrs, "access-control-allow-origin", &cors.allow_origin);
    insert_header_latin1_safe(hdrs, "access-control-allow-methods", &cors.allow_methods);
    if cors.allow_credentials {
        hdrs.insert(
            "access-control-allow-credentials",
            HeaderValue::from_static("true"),
        );
    }
    if let Some(ah) = &cors.allow_headers {
        insert_header_latin1_safe(hdrs, "access-control-allow-headers", ah);
    }
    if let Some(eh) = &cors.expose_headers {
        insert_header_latin1_safe(hdrs, "access-control-expose-headers", eh);
    }
    if let Some(age) = cors.max_age_seconds {
        insert_header_latin1_safe(hdrs, "access-control-max-age", &age.to_string());
    }
    hdrs.insert("vary", HeaderValue::from_static("Origin"));
}

fn parse_optional_object_tagging_header(
    headers: &HeaderMap,
) -> StoreResult<Option<std::collections::BTreeMap<String, String>>> {
    let Some(hv) = headers.get("x-amz-tagging") else {
        return Ok(None);
    };
    let s = hv
        .to_str()
        .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid x-amz-tagging header"))?;
    Ok(Some(parse_tagging_header(s, MAX_OBJECT_TAGS)?))
}

fn parse_tagging_directive_header(headers: &HeaderMap) -> StoreResult<TaggingDirective> {
    match headers
        .get("x-amz-tagging-directive")
        .and_then(|v| v.to_str().ok())
    {
        None | Some("COPY") => Ok(TaggingDirective::Copy),
        Some("REPLACE") => Ok(TaggingDirective::Replace),
        Some(_) => Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Unknown tagging directive.",
        )),
    }
}

fn build_request_policy_context(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
) -> RequestPolicyContext {
    let opt_hdr = |name: &str| -> Option<String> {
        headers
            .get(name)
            .map(decode_header_value_str)
            .map(|s| s.trim().to_string())
    };
    let x_amz_copy_source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| parse_copy_source(raw).ok())
        .map(|(b, k, _)| format!("{b}/{k}"));

    RequestPolicyContext {
        source_ip: peer_ip,
        referer: opt_hdr("referer"),
        x_amz_acl: opt_hdr("x-amz-acl"),
        x_amz_grant_full_control: opt_hdr("x-amz-grant-full-control"),
        x_amz_grant_read: opt_hdr("x-amz-grant-read"),
        x_amz_grant_write: opt_hdr("x-amz-grant-write"),
        x_amz_grant_read_acp: opt_hdr("x-amz-grant-read-acp"),
        x_amz_grant_write_acp: opt_hdr("x-amz-grant-write-acp"),
        x_amz_copy_source,
        x_amz_metadata_directive: opt_hdr("x-amz-metadata-directive"),
        x_amz_server_side_encryption: opt_hdr("x-amz-server-side-encryption"),
        x_amz_sse_customer_algorithm: opt_hdr("x-amz-server-side-encryption-customer-algorithm"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_post_object<S: ObjectStore>(
    state: &AppState<S>,
    headers: &HeaderMap,
    incoming: Incoming,
    bucket: String,
    peer_ip: Option<IpAddr>,
    now_ms: i64,
    key_log: &mut Option<String>,
    caller_log: &mut Option<String>,
) -> StoreResult<Response<S3ResponseBody<S::Reader>>> {
    let ct_str = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let max_put = MAX_SINGLE_PUT_BYTES.min(state.cfg.max_object_size);
    let max_form_bytes = max_put.saturating_add(2 * 1024 * 1024);
    let raw_body = collect_raw_incoming_bounded(incoming, max_form_bytes).await?;

    let parsed =
        parse_and_verify_post_object(&state.auth, &bucket, ct_str, raw_body, now_ms)?;
    *key_log = Some(parsed.key.clone());
    if let Some(c) = &parsed.caller {
        *caller_log = Some(c.user_id.clone());
    }

    let referer = headers
        .get("referer")
        .map(decode_header_value_str)
        .map(|s| s.trim().to_string());
    let policy_ctx = RequestPolicyContext {
        source_ip: peer_ip,
        referer,
        x_amz_acl: parsed.x_amz_acl_raw.clone(),
        x_amz_server_side_encryption: parsed.raw_sse.sse_algorithm.clone(),
        x_amz_sse_customer_algorithm: parsed.raw_sse.sse_customer_algorithm.clone(),
        ..Default::default()
    };
    let ctx = CallerContext {
        caller: parsed.caller,
        request_time_ms: now_ms,
        expected_bucket_owner: None,
        is_authenticated: parsed.is_authenticated,
        policy_ctx,
    };

    let key = parsed.key;
    let stream = PreVerifiedBytesStream::new(parsed.file_bytes, parsed.expected_checksum.clone());
    let put_resp = state
        .store
        .put_object(
            PutObjectReq {
                ctx,
                bucket: bucket.clone(),
                key: key.clone(),
                sys_meta: parsed.sys_meta,
                user_meta: parsed.user_meta,
                acl: parsed.acl,
                tags: parsed.tags,
                preconditions: Preconditions::default(),
                max_bytes_limit: max_put,
                raw_sse: parsed.raw_sse,
                raw_lock: parsed.raw_lock,
            },
            stream,
        )
        .await?;

    let host_str = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let location = format!(
        "http://{host_str}/{}/{}",
        aws_uri_encode(&bucket, true),
        aws_uri_encode(&key, false)
    );

    if let Some(redir) = parsed.success_redirect {
        let sep = if redir.contains('?') { '&' } else { '?' };
        let redir_loc = format!(
            "{redir}{sep}bucket={}&key={}&etag={}",
            aws_uri_encode(&bucket, true),
            aws_uri_encode(&key, true),
            aws_uri_encode(&put_resp.etag, true),
        );
        let mut builder = Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header("Location", redir_loc)
            .header("ETag", &put_resp.etag)
            .header("Content-Length", "0");
        if let Some(vid) = &put_resp.version_id
            && vid != "null" {
                builder = builder.header("x-amz-version-id", vid);
            }
        builder = apply_sse_builder(builder, &put_resp.sse);
        if let Some(exp) = &put_resp.expiration_header {
            builder = builder.header("x-amz-expiration", exp);
        }
        return Ok(builder.body(S3ResponseBody::empty()).unwrap());
    }

    if parsed.success_status == 201 {
        let xml = render_post_response_xml(&location, &bucket, &key, &put_resp.etag);
        let mut builder = Response::builder()
            .status(StatusCode::CREATED)
            .header("Content-Type", "application/xml")
            .header("Content-Length", xml.len().to_string())
            .header("Location", &location)
            .header("ETag", &put_resp.etag);
        if let Some(vid) = &put_resp.version_id
            && vid != "null" {
                builder = builder.header("x-amz-version-id", vid);
            }
        if put_resp.checksum.client_requested {
            builder = builder.header(
                put_resp.checksum.algorithm.header_name(),
                &put_resp.checksum.value_b64,
            );
        }
        builder = apply_sse_builder(builder, &put_resp.sse);
        if let Some(exp) = &put_resp.expiration_header {
            builder = builder.header("x-amz-expiration", exp);
        }
        return Ok(builder.body(S3ResponseBody::from_bytes(xml)).unwrap());
    }

    let status = StatusCode::from_u16(parsed.success_status).unwrap_or(StatusCode::NO_CONTENT);
    let mut builder = Response::builder()
        .status(status)
        .header("Location", &location)
        .header("ETag", &put_resp.etag)
        .header("Content-Length", "0");
    if let Some(vid) = &put_resp.version_id
        && vid != "null" {
            builder = builder.header("x-amz-version-id", vid);
        }
    if put_resp.checksum.client_requested {
        builder = builder.header(
            put_resp.checksum.algorithm.header_name(),
            &put_resp.checksum.value_b64,
        );
    }
    builder = apply_sse_builder(builder, &put_resp.sse);
    if let Some(exp) = &put_resp.expiration_header {
        builder = builder.header("x-amz-expiration", exp);
    }
    Ok(builder.body(S3ResponseBody::empty()).unwrap())
}

fn opt_trimmed_ascii_hdr(headers: &HeaderMap, name: &str) -> StoreResult<Option<String>> {
    match headers.get(name) {
        None => Ok(None),
        Some(hv) => {
            let s = hv
                .to_str()
                .map_err(|_| S3Error::new(S3ErrorCode::InvalidArgument, format!("Invalid {name}")))?;
            Ok(Some(s.trim().to_string()))
        }
    }
}

fn extract_raw_sse_headers(headers: &HeaderMap) -> StoreResult<RawSseHeaders> {
    Ok(RawSseHeaders {
        sse_algorithm: opt_trimmed_ascii_hdr(headers, "x-amz-server-side-encryption")?,
        sse_kms_key_id: opt_trimmed_ascii_hdr(
            headers,
            "x-amz-server-side-encryption-aws-kms-key-id",
        )?,
        sse_customer_algorithm: opt_trimmed_ascii_hdr(
            headers,
            "x-amz-server-side-encryption-customer-algorithm",
        )?,
        sse_customer_key_b64: opt_trimmed_ascii_hdr(
            headers,
            "x-amz-server-side-encryption-customer-key",
        )?,
        sse_customer_key_md5_b64: opt_trimmed_ascii_hdr(
            headers,
            "x-amz-server-side-encryption-customer-key-md5",
        )?,
    })
}

fn extract_raw_copy_source_sse_headers(
    headers: &HeaderMap,
) -> StoreResult<RawCopySourceSseHeaders> {
    Ok(RawCopySourceSseHeaders {
        sse_customer_algorithm: opt_trimmed_ascii_hdr(
            headers,
            "x-amz-copy-source-server-side-encryption-customer-algorithm",
        )?,
        sse_customer_key_b64: opt_trimmed_ascii_hdr(
            headers,
            "x-amz-copy-source-server-side-encryption-customer-key",
        )?,
        sse_customer_key_md5_b64: opt_trimmed_ascii_hdr(
            headers,
            "x-amz-copy-source-server-side-encryption-customer-key-md5",
        )?,
    })
}

fn extract_raw_upload_lock_headers(headers: &HeaderMap) -> StoreResult<RawUploadObjectLockHeaders> {
    Ok(RawUploadObjectLockHeaders {
        mode: opt_trimmed_ascii_hdr(headers, "x-amz-object-lock-mode")?,
        retain_until_date: opt_trimmed_ascii_hdr(headers, "x-amz-object-lock-retain-until-date")?,
        legal_hold: opt_trimmed_ascii_hdr(headers, "x-amz-object-lock-legal-hold")?,
    })
}

fn parse_bypass_governance_header(headers: &HeaderMap) -> bool {
    headers
        .get("x-amz-bypass-governance-retention")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("true"))
}

fn parse_bucket_object_lock_enabled_header(headers: &HeaderMap) -> StoreResult<bool> {
    let Some(hv) = headers.get("x-amz-bucket-object-lock-enabled") else {
        return Ok(false);
    };
    let s = hv
        .to_str()
        .map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid x-amz-bucket-object-lock-enabled header",
            )
        })?
        .trim();
    if s.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if s.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Invalid x-amz-bucket-object-lock-enabled value",
        ))
    }
}

fn apply_sse_builder(
    builder: http::response::Builder,
    sse: &SseResponseHeaders,
) -> http::response::Builder {
    match sse {
        SseResponseHeaders::None => builder,
        SseResponseHeaders::SseS3 => builder.header("x-amz-server-side-encryption", "AES256"),
        SseResponseHeaders::SseC { key_md5_b64 } => builder
            .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
            .header(
                "x-amz-server-side-encryption-customer-key-MD5",
                key_md5_b64.as_str(),
            ),
    }
}

fn apply_sse_hdr_map(hdrs: &mut HeaderMap, sse: &SseResponseHeaders) {
    match sse {
        SseResponseHeaders::None => {}
        SseResponseHeaders::SseS3 => {
            insert_header_latin1_safe(hdrs, "x-amz-server-side-encryption", "AES256");
        }
        SseResponseHeaders::SseC { key_md5_b64 } => {
            insert_header_latin1_safe(
                hdrs,
                "x-amz-server-side-encryption-customer-algorithm",
                "AES256",
            );
            insert_header_latin1_safe(
                hdrs,
                "x-amz-server-side-encryption-customer-key-md5",
                key_md5_b64,
            );
        }
    }
}
