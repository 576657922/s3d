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

use crate::body::{drain_empty_or_ignore, HyperVerifiedBodyStream, S3ResponseBody};
use crate::config::ServerConfig;
use crate::metrics::ServerMetrics;

const MAX_HEADER_SECTION_BYTES: usize = 8192; // PR-19

const UNIMPLEMENTED_BUCKET_SUBRESOURCES: &[&str] = &[
    "acl",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "ownershipControls",
    "versioning",
    "tagging",
    "cors",
    "uploads",
    "lifecycle",
    "encryption",
    "object-lock",
    "logging",
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
    "acl",
    "tagging",
    "uploads",
    "uploadId",
    "attributes",
    "retention",
    "legal-hold",
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

    let mut op_name: &'static str = "Unknown";
    let mut bucket_log: Option<String> = None;
    let mut key_log: Option<String> = None;
    let mut caller_log: Option<String> = None;

    let result = dispatch_inner(
        &state,
        req,
        &mut op_name,
        &mut bucket_log,
        &mut key_log,
        &mut caller_log,
    )
    .await;

    let resp = match result {
        Ok(mut r) => {
            inject_common_headers(r.headers_mut(), &request_id, &host_id);
            r
        }
        Err(err) => build_error_response(err, is_head, &request_id, &host_id),
    };

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
        latency_us = elapsed_us,
        "s3_request"
    );

    resp
}

async fn dispatch_inner<S: ObjectStore>(
    state: &AppState<S>,
    req: Request<Incoming>,
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
        if !headers.contains_key("origin") {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "Insufficient information. Origin request header needed.",
            ));
        }
        return Err(S3Error::new(
            S3ErrorCode::AccessDenied,
            "CORSResponse: This CORS request is not allowed.",
        ));
    }

    // 5. SigV4 / Presigned / Anonymous authentication (`PR-6` ~ `PR-12`)
    let now_ms = now_epoch_ms();
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

    let ctx = CallerContext {
        caller: auth_out.caller.clone(),
        request_time_ms: now_ms,
        expected_bucket_owner,
        is_authenticated: auth_out.is_authenticated,
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
    if let Some(region_filter) = get_query_param(query, "bucket-region") {
        if !region_filter.is_empty() && region_filter != state.cfg.region {
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
        let resp = state
            .store
            .delete_objects(DeleteObjectsReq {
                ctx,
                bucket,
                quiet,
                items,
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
            validate_canned_acl_header_if_present(headers)?;
            let object_ownership = parse_object_ownership_header(headers)?;
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
                    if continuation_token.as_deref() == Some("") {
                        return Err(S3Error::new(
                            S3ErrorCode::InvalidArgument,
                            "The continuation token provided is incorrect",
                        ));
                    }
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

    match *method {
        Method::PUT => {
            validate_storage_class(headers)?;
            validate_canned_acl_header_if_present(headers)?;

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
                let sys_meta = extract_system_meta(headers);
                let user_meta = extract_user_meta(headers)?;
                let src_preconditions = extract_copy_source_preconditions(headers)?;
                let dst_preconditions = extract_write_preconditions(headers);

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
                        src_preconditions,
                        dst_preconditions,
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
                if let Some(dv) = &resp.dst_version_id {
                    if dv != "null" {
                        builder = builder.header("x-amz-version-id", dv);
                    }
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
            let preconditions = extract_write_preconditions(headers);
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
                        preconditions,
                        max_bytes_limit: max_put,
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
            if let Some(vid) = &resp.version_id {
                if vid != "null" {
                    builder = builder.header("x-amz-version-id", vid);
                }
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

            let get_req = GetObjectReq {
                ctx,
                bucket,
                key,
                version_id,
                range,
                part_number,
                preconditions,
                checksum_mode_enabled,
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

            let resp = state
                .store
                .delete_object(DeleteObjectReq {
                    ctx,
                    bucket,
                    key,
                    version_id,
                    if_match,
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
    if let Some(vid) = &meta.version_id {
        if vid != "null" {
            insert_header_latin1_safe(hdrs, "x-amz-version-id", vid);
        }
    }
    if let Some(pc) = meta.parts_count {
        insert_header_latin1_safe(hdrs, "x-amz-mp-parts-count", &pc.to_string());
    }
    if let Some(csum) = &meta.checksum {
        insert_header_latin1_safe(hdrs, csum.algorithm.header_name(), &csum.value_b64);
        insert_header_latin1_safe(hdrs, "x-amz-checksum-type", csum.checksum_type.as_aws_str());
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
    match get_query_param(query, "max-keys") {
        None => Ok(1000),
        Some(raw) => {
            let val = raw.parse::<i64>().map_err(|_| {
                S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Argument maxKeys must be an integer between 0 and 2147483647",
                )
            })?;
            if !(0..=2_147_483_647).contains(&val) {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Argument maxKeys must be an integer between 0 and 2147483647",
                ));
            }
            Ok((val as usize).min(1000))
        }
    }
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

    if !headers.contains_key("x-amz-trailer") {
        if let Some(sdk_alg) = headers.get("x-amz-sdk-checksum-algorithm") {
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

fn validate_canned_acl_header_if_present(headers: &HeaderMap) -> StoreResult<()> {
    if let Some(acl) = headers.get("x-amz-acl") {
        let s = acl.to_str().unwrap_or("").trim();
        if !matches!(
            s,
            "private"
                | "public-read"
                | "public-read-write"
                | "authenticated-read"
                | "aws-exec-read"
                | "bucket-owner-read"
                | "bucket-owner-full-control"
                | "log-delivery-write"
        ) {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid canned ACL",
            ));
        }
    }
    Ok(())
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
            .map(|v| decode_header_value_str(v))
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
    let st = httpdate::parse_http_date(s).ok()?;
    let dur = st.duration_since(UNIX_EPOCH).ok()?;
    Some(dur.as_secs() as i64)
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
            if let Some((k, v)) = pair.split_once('=') {
                if k == "versionId" && !v.is_empty() {
                    src_vid = Some(percent_decode_once(v)?);
                }
            }
        }
    }
    Ok((src_bucket, src_key, src_vid))
}
