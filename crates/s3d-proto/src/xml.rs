use std::collections::BTreeMap;

use quick_xml::events::Event;
use quick_xml::Reader;
use s3d_types::*;

use crate::sigv4::format_iso8601_millis;
use crate::uri::{aws_uri_encode, percent_decode_query_component};

pub const S3_XML_NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Reject DTD / XXE constructs unconditionally (`NFR-8`).
fn check_no_dtd_or_entity(raw_xml: &[u8]) -> StoreResult<()> {
    // Case-insensitive scan for `<!DOCTYPE` or `<!ENTITY`
    let upper: Vec<u8> = raw_xml.iter().map(|b| b.to_ascii_uppercase()).collect();
    if upper.windows(9).any(|w| w == b"<!DOCTYPE") || upper.windows(8).any(|w| w == b"<!ENTITY") {
        return Err(S3Error::new(
            S3ErrorCode::MalformedXML,
            "The XML you provided was not well-formed or did not validate against our published schema",
        ));
    }
    Ok(())
}

pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {
                out.push_str(&format!("&#x{:x};", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn encode_field(val: &str, url_encode: bool, encode_slash: bool) -> String {
    if url_encode {
        xml_escape(&aws_uri_encode(val, encode_slash))
    } else {
        xml_escape(val)
    }
}

/// Serialize S3 `<Error>` XML body (`PR-18`).
pub fn render_error_xml(err: &S3Error, request_id: &str, host_id: &str) -> String {
    let mut xml = String::with_capacity(256);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error>");
    xml.push_str(&format!("<Code>{}</Code>", xml_escape(err.code.as_str())));
    xml.push_str(&format!("<Message>{}</Message>", xml_escape(&err.message)));
    if let Some(b) = &err.bucket_name {
        xml.push_str(&format!("<BucketName>{}</BucketName>", xml_escape(b)));
    }
    if let Some(k) = &err.key {
        xml.push_str(&format!("<Key>{}</Key>", xml_escape(k)));
    }
    if let Some(u) = &err.upload_id {
        xml.push_str(&format!("<UploadId>{}</UploadId>", xml_escape(u)));
    }
    if let Some(r) = &err.resource {
        xml.push_str(&format!("<Resource>{}</Resource>", xml_escape(r)));
    }
    xml.push_str(&format!("<RequestId>{}</RequestId>", xml_escape(request_id)));
    xml.push_str(&format!("<HostId>{}</HostId>", xml_escape(host_id)));
    xml.push_str("</Error>");
    xml
}

/// Parse optional `CreateBucketConfiguration` XML body; returns `Option<LocationConstraint>`.
pub fn parse_create_bucket_xml(body: &[u8]) -> StoreResult<Option<String>> {
    if body.len() > 1024 * 1024 {
        return Err(malformed_xml());
    }
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(None);
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut saw_root = false;
    let mut in_location = false;
    let mut location = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local = e.local_name();
                match local.as_ref() {
                    b"CreateBucketConfiguration" => saw_root = true,
                    b"LocationConstraint" if saw_root => in_location = true,
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                if e.local_name().as_ref() == b"CreateBucketConfiguration" {
                    saw_root = true;
                } else if e.local_name().as_ref() == b"LocationConstraint" && saw_root {
                    location = Some(String::new());
                }
            }
            Ok(Event::Text(t)) if in_location => {
                let s = t.unescape().map_err(|_| malformed_xml())?.to_string();
                location = Some(s);
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"LocationConstraint" {
                    in_location = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(malformed_xml()),
            _ => {}
        }
        buf.clear();
    }

    if !saw_root {
        return Err(malformed_xml());
    }
    Ok(location)
}

/// Parse `DeleteObjects` (`POST /{b}?delete`) XML body (`FR-46`, `NFR-8`).
pub fn parse_delete_objects_xml(body: &[u8]) -> StoreResult<(bool, Vec<DeleteObjectsItem>)> {
    if body.is_empty() || body.len() > 1024 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut saw_delete = false;
    let mut quiet = false;
    let mut items = Vec::new();

    let mut in_object = false;
    let mut cur_tag = String::new();
    let mut cur_key: Option<String> = None;
    let mut cur_vid: Option<String> = None;
    let mut cur_etag: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match name.as_str() {
                    "Delete" => saw_delete = true,
                    "Object" if saw_delete => {
                        in_object = true;
                        cur_key = None;
                        cur_vid = None;
                        cur_etag = None;
                    }
                    _ => cur_tag = name,
                }
            }
            Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if in_object && name == "Key" {
                    cur_key = Some(String::new());
                }
            }
            Ok(Event::Text(t)) => {
                let txt = t.unescape().map_err(|_| malformed_xml())?.to_string();
                if in_object {
                    match cur_tag.as_str() {
                        "Key" => *cur_key.get_or_insert_with(String::new) += &txt,
                        "VersionId" => cur_vid = Some(txt.trim().to_string()),
                        "ETag" => cur_etag = Some(txt.trim().to_string()),
                        _ => {}
                    }
                } else if saw_delete && cur_tag == "Quiet" {
                    quiet = txt.trim().eq_ignore_ascii_case("true");
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if name == "Object" && in_object {
                    let key = cur_key.take().ok_or_else(malformed_xml)?;
                    items.push(DeleteObjectsItem {
                        key,
                        version_id: cur_vid.take(),
                        etag_if_match: cur_etag.take().map(|et| vec![et]),
                    });
                    in_object = false;
                }
                cur_tag.clear();
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(malformed_xml()),
            _ => {}
        }
        buf.clear();
    }

    if !saw_delete || items.is_empty() {
        return Err(malformed_xml());
    }
    Ok((quiet, items))
}

pub fn render_list_buckets_xml(resp: &ListBucketsResp) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListAllMyBucketsResult xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!(
        "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner><Buckets>",
        xml_escape(&resp.owner.user_id),
        xml_escape(&resp.owner.display_name)
    ));
    for b in &resp.buckets {
        xml.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
            xml_escape(&b.name),
            format_iso8601_millis(b.created_ms)
        ));
    }
    xml.push_str("</Buckets>");
    if let Some(tok) = &resp.next_continuation_token {
        xml.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml_escape(tok)
        ));
    }
    xml.push_str("</ListAllMyBucketsResult>");
    xml
}

pub fn render_bucket_location_xml(region: &str) -> String {
    if region == "us-east-1" {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint xmlns=\"{S3_XML_NS}\"/>"
        )
    } else {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint xmlns=\"{S3_XML_NS}\">{}</LocationConstraint>",
            xml_escape(region)
        )
    }
}

pub fn render_list_objects_v1_xml(resp: &ListObjectsV1Resp, url_encode: bool) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(&resp.name)));
    xml.push_str(&format!(
        "<Prefix>{}</Prefix>",
        encode_field(&resp.prefix, url_encode, false)
    ));
    xml.push_str(&format!(
        "<Marker>{}</Marker>",
        encode_field(&resp.marker, url_encode, false)
    ));
    if let Some(nm) = &resp.next_marker {
        xml.push_str(&format!(
            "<NextMarker>{}</NextMarker>",
            encode_field(nm, url_encode, false)
        ));
    }
    xml.push_str(&format!("<MaxKeys>{}</MaxKeys>", resp.max_keys));
    if let Some(d) = &resp.delimiter {
        xml.push_str(&format!(
            "<Delimiter>{}</Delimiter>",
            encode_field(d, url_encode, false)
        ));
    }
    if url_encode {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", resp.is_truncated));

    for obj in &resp.contents {
        xml.push_str("<Contents>");
        xml.push_str(&format!(
            "<Key>{}</Key>",
            encode_field(&obj.key, url_encode, false)
        ));
        xml.push_str(&format!(
            "<LastModified>{}</LastModified>",
            format_iso8601_millis(obj.last_modified_ms)
        ));
        xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(&obj.etag)));
        xml.push_str(&format!("<Size>{}</Size>", obj.size));
        xml.push_str("<StorageClass>STANDARD</StorageClass>");
        xml.push_str(&format!(
            "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>",
            xml_escape(&obj.owner.user_id),
            xml_escape(&obj.owner.display_name)
        ));
        xml.push_str("</Contents>");
    }
    for cp in &resp.common_prefixes {
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            encode_field(cp, url_encode, false)
        ));
    }
    xml.push_str("</ListBucketResult>");
    xml
}

pub fn render_list_objects_v2_xml(
    resp: &ListObjectsV2Resp,
    fetch_owner: bool,
    url_encode: bool,
) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(&resp.name)));
    xml.push_str(&format!(
        "<Prefix>{}</Prefix>",
        encode_field(&resp.prefix, url_encode, false)
    ));
    if let Some(sa) = &resp.start_after {
        xml.push_str(&format!(
            "<StartAfter>{}</StartAfter>",
            encode_field(sa, url_encode, false)
        ));
    }
    if let Some(ct) = &resp.continuation_token {
        xml.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml_escape(ct)
        ));
    }
    if let Some(nct) = &resp.next_continuation_token {
        xml.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            xml_escape(nct)
        ));
    }
    xml.push_str(&format!("<KeyCount>{}</KeyCount>", resp.key_count));
    xml.push_str(&format!("<MaxKeys>{}</MaxKeys>", resp.max_keys));
    if let Some(d) = &resp.delimiter {
        xml.push_str(&format!(
            "<Delimiter>{}</Delimiter>",
            encode_field(d, url_encode, false)
        ));
    }
    if url_encode {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", resp.is_truncated));

    for obj in &resp.contents {
        xml.push_str("<Contents>");
        xml.push_str(&format!(
            "<Key>{}</Key>",
            encode_field(&obj.key, url_encode, false)
        ));
        xml.push_str(&format!(
            "<LastModified>{}</LastModified>",
            format_iso8601_millis(obj.last_modified_ms)
        ));
        xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(&obj.etag)));
        xml.push_str(&format!("<Size>{}</Size>", obj.size));
        xml.push_str("<StorageClass>STANDARD</StorageClass>");
        if fetch_owner {
            xml.push_str(&format!(
                "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>",
                xml_escape(&obj.owner.user_id),
                xml_escape(&obj.owner.display_name)
            ));
        }
        xml.push_str("</Contents>");
    }
    for cp in &resp.common_prefixes {
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            encode_field(cp, url_encode, false)
        ));
    }
    xml.push_str("</ListBucketResult>");
    xml
}

pub fn render_list_object_versions_xml(resp: &ListObjectVersionsResp, url_encode: bool) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListVersionsResult xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(&resp.name)));
    xml.push_str(&format!(
        "<Prefix>{}</Prefix>",
        encode_field(&resp.prefix, url_encode, false)
    ));
    xml.push_str(&format!(
        "<KeyMarker>{}</KeyMarker>",
        encode_field(&resp.key_marker, url_encode, false)
    ));
    xml.push_str(&format!(
        "<VersionIdMarker>{}</VersionIdMarker>",
        xml_escape(&resp.version_id_marker)
    ));
    if let Some(nkm) = &resp.next_key_marker {
        xml.push_str(&format!(
            "<NextKeyMarker>{}</NextKeyMarker>",
            encode_field(nkm, url_encode, false)
        ));
    }
    if let Some(nvm) = &resp.next_version_id_marker {
        xml.push_str(&format!(
            "<NextVersionIdMarker>{}</NextVersionIdMarker>",
            xml_escape(nvm)
        ));
    }
    xml.push_str(&format!("<MaxKeys>{}</MaxKeys>", resp.max_keys));
    if let Some(d) = &resp.delimiter {
        xml.push_str(&format!(
            "<Delimiter>{}</Delimiter>",
            encode_field(d, url_encode, false)
        ));
    }
    if url_encode {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", resp.is_truncated));

    for entry in &resp.entries {
        if entry.is_delete_marker {
            xml.push_str("<DeleteMarker>");
            xml.push_str(&format!(
                "<Key>{}</Key>",
                encode_field(&entry.key, url_encode, false)
            ));
            xml.push_str(&format!(
                "<VersionId>{}</VersionId>",
                xml_escape(&entry.version_id)
            ));
            xml.push_str(&format!("<IsLatest>{}</IsLatest>", entry.is_latest));
            xml.push_str(&format!(
                "<LastModified>{}</LastModified>",
                format_iso8601_millis(entry.last_modified_ms)
            ));
            xml.push_str(&format!(
                "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>",
                xml_escape(&entry.owner.user_id),
                xml_escape(&entry.owner.display_name)
            ));
            xml.push_str("</DeleteMarker>");
        } else {
            xml.push_str("<Version>");
            xml.push_str(&format!(
                "<Key>{}</Key>",
                encode_field(&entry.key, url_encode, false)
            ));
            xml.push_str(&format!(
                "<VersionId>{}</VersionId>",
                xml_escape(&entry.version_id)
            ));
            xml.push_str(&format!("<IsLatest>{}</IsLatest>", entry.is_latest));
            xml.push_str(&format!(
                "<LastModified>{}</LastModified>",
                format_iso8601_millis(entry.last_modified_ms)
            ));
            xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(&entry.etag)));
            xml.push_str(&format!("<Size>{}</Size>", entry.size));
            xml.push_str("<StorageClass>STANDARD</StorageClass>");
            xml.push_str(&format!(
                "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>",
                xml_escape(&entry.owner.user_id),
                xml_escape(&entry.owner.display_name)
            ));
            xml.push_str("</Version>");
        }
    }
    for cp in &resp.common_prefixes {
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            encode_field(cp, url_encode, false)
        ));
    }
    xml.push_str("</ListVersionsResult>");
    xml
}

pub fn render_delete_objects_xml(resp: &DeleteObjectsResp) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<DeleteResult xmlns=\"{S3_XML_NS}\">"
    );
    for d in &resp.deleted {
        xml.push_str("<Deleted>");
        xml.push_str(&format!("<Key>{}</Key>", xml_escape(&d.key)));
        if let Some(vid) = &d.version_id {
            xml.push_str(&format!("<VersionId>{}</VersionId>", xml_escape(vid)));
        }
        if d.delete_marker {
            xml.push_str("<DeleteMarker>true</DeleteMarker>");
        }
        if let Some(dm_vid) = &d.delete_marker_version_id {
            xml.push_str(&format!(
                "<DeleteMarkerVersionId>{}</DeleteMarkerVersionId>",
                xml_escape(dm_vid)
            ));
        }
        xml.push_str("</Deleted>");
    }
    for e in &resp.errors {
        xml.push_str("<Error>");
        xml.push_str(&format!("<Key>{}</Key>", xml_escape(&e.key)));
        if let Some(vid) = &e.version_id {
            xml.push_str(&format!("<VersionId>{}</VersionId>", xml_escape(vid)));
        }
        xml.push_str(&format!("<Code>{}</Code>", xml_escape(&e.code)));
        xml.push_str(&format!("<Message>{}</Message>", xml_escape(&e.message)));
        xml.push_str("</Error>");
    }
    xml.push_str("</DeleteResult>");
    xml
}

pub fn render_copy_object_xml(resp: &CopyObjectResp) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CopyObjectResult xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(&resp.etag)));
    xml.push_str(&format!(
        "<LastModified>{}</LastModified>",
        format_iso8601_millis(resp.last_modified_ms)
    ));
    if let Some(csum) = &resp.checksum {
        let tag = csum.algorithm.xml_tag_name();
        xml.push_str(&format!("<{tag}>{}</{tag}>", xml_escape(&csum.value_b64)));
    }
    xml.push_str("</CopyObjectResult>");
    xml
}

/// Parse `PUT /{b}?versioning` XML body (`FR-34`).
pub fn parse_bucket_versioning_xml(body: &[u8]) -> StoreResult<VersioningStatus> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut cur_tag = String::new();
    let mut status_str: Option<String> = None;
    let mut mfa_delete_str: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if name == "VersioningConfiguration" {
                    saw_root = true;
                } else if saw_root {
                    cur_tag = name;
                }
            }
            Ok(Event::Empty(e)) => {
                if e.local_name().as_ref() == b"VersioningConfiguration" {
                    saw_root = true;
                }
            }
            Ok(Event::Text(t)) if saw_root => {
                let txt = t.unescape().map_err(|_| malformed_xml())?.to_string();
                match cur_tag.as_str() {
                    "Status" => status_str = Some(txt),
                    "MfaDelete" => mfa_delete_str = Some(txt),
                    _ => {}
                }
            }
            Ok(Event::End(_)) => {
                cur_tag.clear();
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(malformed_xml()),
            _ => {}
        }
        buf.clear();
    }

    if !saw_root {
        return Err(malformed_xml());
    }

    if let Some(mfa) = mfa_delete_str.as_deref() {
        match mfa {
            "Disabled" => {}
            "Enabled" => {
                return Err(S3Error::new(
                    S3ErrorCode::NotImplemented,
                    "MFA Delete is not supported.",
                ));
            }
            _ => return Err(malformed_xml()),
        }
    }

    match status_str.as_deref() {
        Some("Enabled") => Ok(VersioningStatus::Enabled),
        Some("Suspended") => Ok(VersioningStatus::Suspended),
        _ => Err(malformed_xml()),
    }
}

/// Render `GET /{b}?versioning` XML response (`FR-34`).
pub fn render_bucket_versioning_xml(state: VersioningStatus) -> String {
    match state {
        VersioningStatus::Unversioned => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<VersioningConfiguration xmlns=\"{S3_XML_NS}\"/>"
        ),
        VersioningStatus::Enabled => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<VersioningConfiguration xmlns=\"{S3_XML_NS}\"><Status>Enabled</Status></VersioningConfiguration>"
        ),
        VersioningStatus::Suspended => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<VersioningConfiguration xmlns=\"{S3_XML_NS}\"><Status>Suspended</Status></VersioningConfiguration>"
        ),
    }
}

/// Render `CreateMultipartUpload` (`POST /{b}/{k}?uploads`) XML response (`FR-23`).
pub fn render_initiate_multipart_xml(resp: &CreateMultipartUploadResp) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<InitiateMultipartUploadResult xmlns=\"{S3_XML_NS}\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
        xml_escape(&resp.bucket),
        xml_escape(&resp.key),
        xml_escape(&resp.upload_id),
    )
}

/// Parse `CompleteMultipartUpload` (`POST /{b}/{k}?uploadId=U`) XML body (`FR-25`, `NFR-8`: <= 2 MiB).
pub fn parse_complete_multipart_xml(body: &[u8]) -> StoreResult<Vec<CompletePartSpec>> {
    if body.is_empty() || body.len() > 2 * 1024 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut in_part = false;
    let mut cur_tag = String::new();

    let mut cur_part_num: Option<u32> = None;
    let mut cur_etag: Option<String> = None;
    let mut cur_csum: Option<(ChecksumAlgorithm, String)> = None;
    let mut parts = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match name.as_str() {
                    "CompleteMultipartUpload" => saw_root = true,
                    "Part" if saw_root => {
                        in_part = true;
                        cur_part_num = None;
                        cur_etag = None;
                        cur_csum = None;
                    }
                    _ if in_part => cur_tag = name,
                    _ => {}
                }
            }
            Ok(Event::Text(t)) if in_part => {
                let txt = t.unescape().map_err(|_| malformed_xml())?.to_string();
                match cur_tag.as_str() {
                    "PartNumber" => {
                        let pn = txt.trim().parse::<u32>().map_err(|_| malformed_xml())?;
                        cur_part_num = Some(pn);
                    }
                    "ETag" => {
                        cur_etag = Some(txt.trim().to_string());
                    }
                    "ChecksumCRC32" => cur_csum = Some((ChecksumAlgorithm::Crc32, txt.trim().to_string())),
                    "ChecksumCRC32C" => cur_csum = Some((ChecksumAlgorithm::Crc32c, txt.trim().to_string())),
                    "ChecksumCRC64NVME" => cur_csum = Some((ChecksumAlgorithm::Crc64Nvme, txt.trim().to_string())),
                    "ChecksumSHA1" => cur_csum = Some((ChecksumAlgorithm::Sha1, txt.trim().to_string())),
                    "ChecksumSHA256" => cur_csum = Some((ChecksumAlgorithm::Sha256, txt.trim().to_string())),
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if name == "Part" && in_part {
                    let part_number = cur_part_num.take().ok_or_else(malformed_xml)?;
                    let etag = cur_etag.take().ok_or_else(malformed_xml)?;
                    parts.push(CompletePartSpec {
                        part_number,
                        etag,
                        checksum: cur_csum.take(),
                    });
                    in_part = false;
                }
                cur_tag.clear();
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(malformed_xml()),
            _ => {}
        }
        buf.clear();
    }

    if !saw_root || parts.is_empty() {
        return Err(malformed_xml());
    }
    Ok(parts)
}

/// Render `CompleteMultipartUpload` XML response (`FR-25`).
pub fn render_complete_multipart_xml(location: &str, resp: &CompleteMultipartUploadResp) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUploadResult xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!("<Location>{}</Location>", xml_escape(location)));
    xml.push_str(&format!("<Bucket>{}</Bucket>", xml_escape(&resp.bucket)));
    xml.push_str(&format!("<Key>{}</Key>", xml_escape(&resp.key)));
    xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(&resp.etag)));
    if let Some(csum) = &resp.checksum {
        let tag = csum.algorithm.xml_tag_name();
        xml.push_str(&format!("<{tag}>{}</{tag}>", xml_escape(&csum.value_b64)));
        xml.push_str(&format!(
            "<ChecksumType>{}</ChecksumType>",
            csum.checksum_type.as_aws_str()
        ));
    }
    xml.push_str("</CompleteMultipartUploadResult>");
    xml
}

/// Render `UploadPartCopy` (`CopyPartResult`) XML response (`FR-24`).
pub fn render_copy_part_xml(resp: &UploadPartCopyResp) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CopyPartResult xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(&resp.etag)));
    xml.push_str(&format!(
        "<LastModified>{}</LastModified>",
        format_iso8601_millis(resp.last_modified_ms)
    ));
    if let Some(csum) = &resp.checksum {
        let tag = csum.algorithm.xml_tag_name();
        xml.push_str(&format!("<{tag}>{}</{tag}>", xml_escape(&csum.value_b64)));
    }
    xml.push_str("</CopyPartResult>");
    xml
}

/// Render `ListParts` (`GET /{b}/{k}?uploadId=U`) XML response (`FR-29`).
pub fn render_list_parts_xml(resp: &ListPartsResp, url_encode: bool) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListPartsResult xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!("<Bucket>{}</Bucket>", xml_escape(&resp.bucket)));
    xml.push_str(&format!(
        "<Key>{}</Key>",
        encode_field(&resp.key, url_encode, false)
    ));
    xml.push_str(&format!(
        "<UploadId>{}</UploadId>",
        xml_escape(&resp.upload_id)
    ));
    xml.push_str(&format!(
        "<Initiator><ID>{}</ID><DisplayName>{}</DisplayName></Initiator>",
        xml_escape(&resp.initiator.user_id),
        xml_escape(&resp.initiator.display_name)
    ));
    xml.push_str(&format!(
        "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>",
        xml_escape(&resp.owner.user_id),
        xml_escape(&resp.owner.display_name)
    ));
    xml.push_str(&format!(
        "<StorageClass>{}</StorageClass>",
        xml_escape(&resp.storage_class)
    ));
    if let Some(alg) = resp.checksum_algorithm {
        xml.push_str(&format!(
            "<ChecksumAlgorithm>{}</ChecksumAlgorithm>",
            alg.as_aws_str()
        ));
    }
    if let Some(ct) = resp.checksum_type {
        xml.push_str(&format!(
            "<ChecksumType>{}</ChecksumType>",
            ct.as_aws_str()
        ));
    }
    xml.push_str(&format!(
        "<PartNumberMarker>{}</PartNumberMarker>",
        resp.part_number_marker
    ));
    xml.push_str(&format!(
        "<NextPartNumberMarker>{}</NextPartNumberMarker>",
        resp.next_part_number_marker
    ));
    xml.push_str(&format!("<MaxParts>{}</MaxParts>", resp.max_parts));
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", resp.is_truncated));
    if url_encode {
        xml.push_str("<EncodingType>url</EncodingType>");
    }

    for part in &resp.parts {
        xml.push_str("<Part>");
        xml.push_str(&format!("<PartNumber>{}</PartNumber>", part.part_number));
        xml.push_str(&format!(
            "<LastModified>{}</LastModified>",
            format_iso8601_millis(part.last_modified_ms)
        ));
        xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(&part.etag)));
        xml.push_str(&format!("<Size>{}</Size>", part.size));
        if let Some((alg, val_b64)) = &part.checksum {
            let tag = alg.xml_tag_name();
            xml.push_str(&format!("<{tag}>{}</{tag}>", xml_escape(val_b64)));
        }
        xml.push_str("</Part>");
    }

    xml.push_str("</ListPartsResult>");
    xml
}

/// Render `ListMultipartUploads` (`GET /{b}?uploads`) XML response (`FR-30`).
pub fn render_list_multipart_uploads_xml(
    resp: &ListMultipartUploadsResp,
    url_encode: bool,
) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListMultipartUploadsResult xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!("<Bucket>{}</Bucket>", xml_escape(&resp.bucket)));
    xml.push_str(&format!(
        "<KeyMarker>{}</KeyMarker>",
        encode_field(&resp.key_marker, url_encode, false)
    ));
    xml.push_str(&format!(
        "<UploadIdMarker>{}</UploadIdMarker>",
        xml_escape(&resp.upload_id_marker)
    ));
    if let Some(nkm) = &resp.next_key_marker {
        xml.push_str(&format!(
            "<NextKeyMarker>{}</NextKeyMarker>",
            encode_field(nkm, url_encode, false)
        ));
    }
    xml.push_str(&format!(
        "<Prefix>{}</Prefix>",
        encode_field(&resp.prefix, url_encode, false)
    ));
    if let Some(d) = &resp.delimiter {
        xml.push_str(&format!(
            "<Delimiter>{}</Delimiter>",
            encode_field(d, url_encode, false)
        ));
    }
    if let Some(num) = &resp.next_upload_id_marker {
        xml.push_str(&format!(
            "<NextUploadIdMarker>{}</NextUploadIdMarker>",
            xml_escape(num)
        ));
    }
    xml.push_str(&format!("<MaxUploads>{}</MaxUploads>", resp.max_uploads));
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", resp.is_truncated));
    if url_encode {
        xml.push_str("<EncodingType>url</EncodingType>");
    }

    for up in &resp.uploads {
        xml.push_str("<Upload>");
        xml.push_str(&format!(
            "<Key>{}</Key>",
            encode_field(&up.key, url_encode, false)
        ));
        xml.push_str(&format!(
            "<UploadId>{}</UploadId>",
            xml_escape(&up.upload_id)
        ));
        xml.push_str(&format!(
            "<Initiator><ID>{}</ID><DisplayName>{}</DisplayName></Initiator>",
            xml_escape(&up.initiator.user_id),
            xml_escape(&up.initiator.display_name)
        ));
        xml.push_str(&format!(
            "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>",
            xml_escape(&up.owner.user_id),
            xml_escape(&up.owner.display_name)
        ));
        xml.push_str(&format!(
            "<StorageClass>{}</StorageClass>",
            xml_escape(&up.storage_class)
        ));
        xml.push_str(&format!(
            "<Initiated>{}</Initiated>",
            format_iso8601_millis(up.initiated_ms)
        ));
        if let Some(alg) = up.checksum_algorithm {
            xml.push_str(&format!(
                "<ChecksumAlgorithm>{}</ChecksumAlgorithm>",
                alg.as_aws_str()
            ));
        }
        if let Some(ct) = up.checksum_type {
            xml.push_str(&format!(
                "<ChecksumType>{}</ChecksumType>",
                ct.as_aws_str()
            ));
        }
        xml.push_str("</Upload>");
    }

    for cp in &resp.common_prefixes {
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            encode_field(cp, url_encode, false)
        ));
    }

    xml.push_str("</ListMultipartUploadsResult>");
    xml
}

/// Render `GetObjectAttributes` (`GET /{b}/{k}?attributes`) XML response (`FR-47`).
pub fn render_get_object_attributes_xml(resp: &GetObjectAttributesResp) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<GetObjectAttributesResponse xmlns=\"{S3_XML_NS}\">"
    );
    if let Some(etag) = &resp.etag {
        let unquoted = etag.trim_matches('"');
        xml.push_str(&format!("<ETag>{}</ETag>", xml_escape(unquoted)));
    }
    if let Some(csum) = &resp.checksum {
        let tag = csum.algorithm.xml_tag_name();
        xml.push_str("<Checksum>");
        xml.push_str(&format!("<{tag}>{}</{tag}>", xml_escape(&csum.value_b64)));
        xml.push_str(&format!(
            "<ChecksumType>{}</ChecksumType>",
            csum.checksum_type.as_aws_str()
        ));
        xml.push_str("</Checksum>");
    }
    if let Some(op) = &resp.object_parts {
        xml.push_str("<ObjectParts>");
        xml.push_str(&format!("<PartsCount>{}</PartsCount>", op.total_parts_count));
        xml.push_str(&format!(
            "<PartNumberMarker>{}</PartNumberMarker>",
            op.part_number_marker
        ));
        if let Some(npm) = op.next_part_number_marker {
            xml.push_str(&format!(
                "<NextPartNumberMarker>{npm}</NextPartNumberMarker>"
            ));
        }
        xml.push_str(&format!("<MaxParts>{}</MaxParts>", op.max_parts));
        xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", op.is_truncated));
        for p in &op.parts {
            xml.push_str("<Part>");
            xml.push_str(&format!("<PartNumber>{}</PartNumber>", p.part_number));
            xml.push_str(&format!("<Size>{}</Size>", p.size));
            if let Some((alg, val_b64)) = &p.checksum {
                let tag = alg.xml_tag_name();
                xml.push_str(&format!("<{tag}>{}</{tag}>", xml_escape(val_b64)));
            }
            xml.push_str("</Part>");
        }
        xml.push_str("</ObjectParts>");
    }
    if let Some(sc) = &resp.storage_class {
        xml.push_str(&format!("<StorageClass>{}</StorageClass>", xml_escape(sc)));
    }
    if let Some(sz) = resp.object_size {
        xml.push_str(&format!("<ObjectSize>{sz}</ObjectSize>"));
    }
    xml.push_str("</GetObjectAttributesResponse>");
    xml
}

/// Render `AccessControlPolicy` XML response (`GetBucketAcl` / `GetObjectAcl`, `PR-32`).
pub fn render_acl_xml(policy: &AccessControlPolicy) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AccessControlPolicy xmlns=\"{S3_XML_NS}\">"
    );
    xml.push_str(&format!(
        "<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>",
        xml_escape(&policy.owner.user_id),
        xml_escape(&policy.owner.display_name)
    ));
    xml.push_str("<AccessControlList>");
    for grant in &policy.grants {
        xml.push_str("<Grant>");
        match &grant.grantee {
            AclGrantee::CanonicalUser(u) => {
                xml.push_str(
                    "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">",
                );
                xml.push_str(&format!(
                    "<ID>{}</ID><DisplayName>{}</DisplayName>",
                    xml_escape(&u.user_id),
                    xml_escape(&u.display_name)
                ));
                xml.push_str("</Grantee>");
            }
            AclGrantee::Group(uri) => {
                xml.push_str(
                    "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">",
                );
                xml.push_str(&format!("<URI>{}</URI>", xml_escape(uri)));
                xml.push_str("</Grantee>");
            }
        }
        xml.push_str(&format!(
            "<Permission>{}</Permission>",
            grant.permission.as_aws_str()
        ));
        xml.push_str("</Grant>");
    }
    xml.push_str("</AccessControlList></AccessControlPolicy>");
    xml
}

fn is_valid_acl_group_uri(uri: &str) -> bool {
    matches!(
        uri,
        GROUP_ALL_USERS | GROUP_AUTHENTICATED_USERS | GROUP_LOG_DELIVERY
    )
}

/// Parse `AccessControlPolicy` XML body (`PutBucketAcl` / `PutObjectAcl`, `PR-32`).
pub fn parse_acl_xml<FId, FEmail>(
    body: &[u8],
    resolve_id: FId,
    resolve_email: FEmail,
) -> StoreResult<AccessControlPolicy>
where
    FId: Fn(&str) -> Option<OwnerInfo>,
    FEmail: Fn(&str) -> Option<OwnerInfo>,
{
    if body.is_empty() || body.len() > 1024 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut in_owner = false;
    let mut in_acl_list = false;
    let mut in_grant = false;
    let mut in_grantee = false;
    let mut cur_tag: Option<String> = None;

    let mut owner_id: Option<String> = None;
    let mut owner_display: Option<String> = None;

    let mut grantee_type: Option<String> = None;
    let mut grantee_id: Option<String> = None;
    let mut grantee_email: Option<String> = None;
    let mut grantee_uri: Option<String> = None;
    let mut grant_perm: Option<String> = None;

    type RawAclGrant = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut raw_grants: Vec<RawAclGrant> = Vec::new();

    let malformed_acl = || {
        S3Error::new(
            S3ErrorCode::MalformedACLError,
            "The XML you provided was not well-formed or did not validate against our published schema",
        )
    };

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "AccessControlPolicy" if !saw_root => saw_root = true,
                    "Owner" if saw_root && !in_acl_list => in_owner = true,
                    "AccessControlList" if saw_root && !in_owner => in_acl_list = true,
                    "Grant" if in_acl_list && !in_grant => {
                        in_grant = true;
                        grantee_type = None;
                        grantee_id = None;
                        grantee_email = None;
                        grantee_uri = None;
                        grant_perm = None;
                    }
                    "Grantee" if in_grant && !in_grantee => {
                        in_grantee = true;
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            if (key == "type" || key.ends_with(":type"))
                                && let Ok(v) = attr.unescape_value() {
                                    grantee_type = Some(v.into_owned());
                                }
                        }
                    }
                    "ID" | "DisplayName" | "EmailAddress" | "URI" | "Permission" => {
                        cur_tag = Some(local.to_string());
                    }
                    _ => return Err(malformed_acl()),
                }
            }
            Ok(Event::Empty(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "AccessControlList" if saw_root && !in_owner => {}
                    "DisplayName" => {}
                    _ => return Err(malformed_acl()),
                }
            }
            Ok(Event::Text(t)) => {
                let val = t.unescape().map_err(|_| malformed_acl())?.into_owned();
                match cur_tag.as_deref() {
                    Some("ID") if in_owner => owner_id = Some(val),
                    Some("DisplayName") if in_owner => owner_display = Some(val),
                    Some("ID") if in_grantee => grantee_id = Some(val),
                    Some("DisplayName") if in_grantee => {}
                    Some("EmailAddress") if in_grantee => grantee_email = Some(val),
                    Some("URI") if in_grantee => grantee_uri = Some(val),
                    Some("Permission") if in_grant && !in_grantee => grant_perm = Some(val),
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "Owner" => in_owner = false,
                    "AccessControlList" => in_acl_list = false,
                    "Grantee" => in_grantee = false,
                    "Grant" => {
                        in_grant = false;
                        raw_grants.push((
                            grantee_type.take(),
                            grantee_id.take(),
                            grantee_email.take(),
                            grantee_uri.take(),
                            grant_perm.take(),
                        ));
                    }
                    "ID" | "DisplayName" | "EmailAddress" | "URI" | "Permission" => {
                        cur_tag = None;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(malformed_acl()),
        }
        buf.clear();
    }

    if !saw_root {
        return Err(malformed_acl());
    }
    let Some(oid) = owner_id.filter(|s| !s.is_empty()) else {
        return Err(malformed_acl());
    };
    let owner = resolve_id(&oid).ok_or_else(|| {
        S3Error::new(S3ErrorCode::InvalidArgument, "Invalid id")
    })?;
    let _ = owner_display;

    let mut grants = Vec::with_capacity(raw_grants.len());
    for (g_type, g_id, g_email, g_uri, g_perm) in raw_grants {
        let perm_str = g_perm.ok_or_else(malformed_acl)?;
        let permission = AclPermission::from_aws_str(&perm_str).ok_or_else(malformed_acl)?;

        let effective_type = match g_type.as_deref() {
            Some(t) => t,
            None if g_id.is_some() => "CanonicalUser",
            None if g_email.is_some() => "AmazonCustomerByEmail",
            None if g_uri.is_some() => "Group",
            None => return Err(malformed_acl()),
        };

        let grantee = match effective_type {
            "CanonicalUser" => {
                let uid = g_id.filter(|s| !s.is_empty()).ok_or_else(malformed_acl)?;
                let user = resolve_id(&uid)
                    .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid id"))?;
                AclGrantee::CanonicalUser(user)
            }
            "AmazonCustomerByEmail" => {
                let email = g_email
                    .filter(|s| !s.is_empty())
                    .ok_or_else(malformed_acl)?;
                let user = resolve_email(&email).ok_or_else(|| {
                    S3Error::new(
                        S3ErrorCode::UnresolvableGrantByEmailAddress,
                        "The e-mail address you provided does not match any account on record.",
                    )
                })?;
                AclGrantee::CanonicalUser(user)
            }
            "Group" => {
                let uri = g_uri.filter(|s| !s.is_empty()).ok_or_else(malformed_acl)?;
                if !is_valid_acl_group_uri(&uri) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Invalid group uri",
                    ));
                }
                AclGrantee::Group(uri)
            }
            _ => return Err(malformed_acl()),
        };

        grants.push(AclGrant {
            grantee,
            permission,
        });
    }

    Ok(AccessControlPolicy { owner, grants })
}

/// Parse an `x-amz-grant-{read,write,read-acp,write-acp,full-control}` header value (`PR-32`).
pub fn parse_acl_grant_header<FId, FEmail>(
    raw_value: &str,
    permission: AclPermission,
    resolve_id: &FId,
    resolve_email: &FEmail,
) -> StoreResult<Vec<AclGrant>>
where
    FId: Fn(&str) -> Option<OwnerInfo>,
    FEmail: Fn(&str) -> Option<OwnerInfo>,
{
    let mut out = Vec::new();
    for item in raw_value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some((k, v)) = item.split_once('=') else {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid x-amz-grant header value",
            ));
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().trim_matches('"');
        if val.is_empty() {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Empty grantee value in x-amz-grant header",
            ));
        }
        let grantee = match key.as_str() {
            "id" => {
                let user = resolve_id(val)
                    .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid id"))?;
                AclGrantee::CanonicalUser(user)
            }
            "emailaddress" => {
                let user = resolve_email(val).ok_or_else(|| {
                    S3Error::new(
                        S3ErrorCode::UnresolvableGrantByEmailAddress,
                        "The e-mail address you provided does not match any account on record.",
                    )
                })?;
                AclGrantee::CanonicalUser(user)
            }
            "uri" => {
                if !is_valid_acl_group_uri(val) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Invalid group uri",
                    ));
                }
                AclGrantee::Group(val.to_string())
            }
            _ => {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Unsupported grantee type in x-amz-grant header",
                ));
            }
        };
        out.push(AclGrant {
            grantee,
            permission,
        });
    }
    if out.is_empty() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Empty x-amz-grant header",
        ));
    }
    Ok(out)
}

/// Parse `OwnershipControls` (`PUT /{b}?ownershipControls`) XML body (`FR-50`).
pub fn parse_ownership_controls_xml(body: &[u8]) -> StoreResult<ObjectOwnership> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut in_rule = false;
    let mut cur_tag = String::new();
    let mut cur_ownership: Option<ObjectOwnership> = None;
    let mut rules: Vec<ObjectOwnership> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "OwnershipControls" if !saw_root => saw_root = true,
                    "Rule" if saw_root && !in_rule => {
                        in_rule = true;
                        cur_ownership = None;
                    }
                    "ObjectOwnership" if in_rule && cur_tag.is_empty() => {
                        cur_tag = local.to_string();
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Empty(_)) => return Err(malformed_xml()),
            Ok(Event::Text(t)) => {
                if cur_tag == "ObjectOwnership" {
                    let s = t.unescape().map_err(|_| malformed_xml())?;
                    let parsed = ObjectOwnership::from_aws_str(&s).ok_or_else(malformed_xml)?;
                    cur_ownership = Some(parsed);
                }
            }
            Ok(Event::End(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "ObjectOwnership" => cur_tag.clear(),
                    "Rule" if in_rule => {
                        let own = cur_ownership.take().ok_or_else(malformed_xml)?;
                        rules.push(own);
                        in_rule = false;
                    }
                    "OwnershipControls" => {}
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(malformed_xml()),
        }
        buf.clear();
    }

    if !saw_root || rules.len() != 1 {
        return Err(malformed_xml());
    }
    Ok(rules[0])
}

/// Render `OwnershipControls` (`GET /{b}?ownershipControls`) XML response (`FR-50`).
pub fn render_ownership_controls_xml(ownership: ObjectOwnership) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<OwnershipControls xmlns=\"{S3_XML_NS}\"><Rule><ObjectOwnership>{}</ObjectOwnership></Rule></OwnershipControls>",
        ownership.as_aws_str()
    )
}

/// Parse `<Tagging>` XML body (`PUT /{b}?tagging`, `PUT /{b}/{k}?tagging`, or `PostObject` `tagging` field).
pub fn parse_tagging_xml(body: &[u8], max_tags: usize) -> StoreResult<BTreeMap<String, String>> {
    if body.is_empty() || body.len() > 128 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut saw_tagset = false;
    let mut in_tagset = false;
    let mut in_tag = false;
    let mut cur_tag: Option<String> = None;
    let mut cur_key: Option<String> = None;
    let mut cur_val: Option<String> = None;
    let mut pairs: Vec<(String, String)> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "Tagging" if !saw_root => saw_root = true,
                    "TagSet" if saw_root && !saw_tagset => {
                        saw_tagset = true;
                        in_tagset = true;
                    }
                    "Tag" if in_tagset && !in_tag => {
                        in_tag = true;
                        cur_key = None;
                        cur_val = None;
                    }
                    "Key" if in_tag && cur_tag.is_none() && cur_key.is_none() => {
                        cur_tag = Some("Key".to_string());
                        cur_key = Some(String::new());
                    }
                    "Value" if in_tag && cur_tag.is_none() && cur_val.is_none() => {
                        cur_tag = Some("Value".to_string());
                        cur_val = Some(String::new());
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Empty(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "TagSet" if saw_root && !saw_tagset => {
                        saw_tagset = true;
                    }
                    "Key" if in_tag && cur_tag.is_none() && cur_key.is_none() => {
                        cur_key = Some(String::new());
                    }
                    "Value" if in_tag && cur_tag.is_none() && cur_val.is_none() => {
                        cur_val = Some(String::new());
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Text(t)) => {
                let txt = t.unescape().map_err(|_| malformed_xml())?;
                match cur_tag.as_deref() {
                    Some("Key") => {
                        if let Some(k) = &mut cur_key {
                            k.push_str(&txt);
                        }
                    }
                    Some("Value") => {
                        if let Some(v) = &mut cur_val {
                            v.push_str(&txt);
                        }
                    }
                    _ if txt.chars().all(|c| c.is_ascii_whitespace()) => {}
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::End(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "Key" | "Value" => cur_tag = None,
                    "Tag" if in_tag => {
                        let k = cur_key.take().ok_or_else(malformed_xml)?;
                        let v = cur_val.take().ok_or_else(malformed_xml)?;
                        pairs.push((k, v));
                        in_tag = false;
                    }
                    "TagSet" if in_tagset => in_tagset = false,
                    "Tagging" => {}
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(malformed_xml()),
        }
        buf.clear();
    }

    if !saw_root || !saw_tagset {
        return Err(malformed_xml());
    }
    validate_tags(&pairs, max_tags)
}

/// Render `<Tagging>` XML response (`GET /{b}?tagging` / `GET /{b}/{k}?tagging`).
pub fn render_tagging_xml(tags: &BTreeMap<String, String>) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Tagging xmlns=\"{S3_XML_NS}\"><TagSet>"
    );
    for (k, v) in tags {
        xml.push_str(&format!(
            "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
            xml_escape(k),
            xml_escape(v)
        ));
    }
    xml.push_str("</TagSet></Tagging>");
    xml
}

/// Parse `x-amz-tagging` URL-encoded query header (`k1=v1&k2=v2`, missing `=` -> empty value).
pub fn parse_tagging_header(raw: &str, max_tags: usize) -> StoreResult<BTreeMap<String, String>> {
    if raw.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut pairs = Vec::new();
    for part in raw.split('&') {
        let (rk, rv) = match part.split_once('=') {
            Some((k, v)) => (k, v),
            None => (part, ""),
        };
        let k = percent_decode_query_component(rk).map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidTag,
                "The TagKey you have provided is invalid",
            )
        })?;
        let v = percent_decode_query_component(rv).map_err(|_| {
            S3Error::new(
                S3ErrorCode::InvalidTag,
                "The TagValue you have provided is invalid",
            )
        })?;
        pairs.push((k, v));
    }
    validate_tags(&pairs, max_tags)
}

/// Parse `<CORSConfiguration>` XML body (`PUT /{b}?cors`).
pub fn parse_cors_xml(body: &[u8]) -> StoreResult<CorsConfiguration> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut in_rule = false;
    let mut cur_tag: Option<String> = None;
    let mut cur_rule = CorsRule {
        id: None,
        allowed_origins: Vec::new(),
        allowed_methods: Vec::new(),
        allowed_headers: Vec::new(),
        expose_headers: Vec::new(),
        max_age_seconds: None,
    };
    let mut rules = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "CORSConfiguration" if !saw_root => saw_root = true,
                    "CORSRule" if saw_root && !in_rule => {
                        in_rule = true;
                        cur_rule = CorsRule {
                            id: None,
                            allowed_origins: Vec::new(),
                            allowed_methods: Vec::new(),
                            allowed_headers: Vec::new(),
                            expose_headers: Vec::new(),
                            max_age_seconds: None,
                        };
                    }
                    "ID" | "AllowedOrigin" | "AllowedMethod" | "AllowedHeader" | "ExposeHeader"
                    | "MaxAgeSeconds"
                        if in_rule && cur_tag.is_none() =>
                    {
                        cur_tag = Some(local.to_string());
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Empty(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                if local == "ID" && in_rule && cur_tag.is_none() {
                    cur_rule.id = Some(String::new());
                } else {
                    return Err(malformed_xml());
                }
            }
            Ok(Event::Text(t)) => {
                let val = t.unescape().map_err(|_| malformed_xml())?.into_owned();
                match cur_tag.as_deref() {
                    Some("ID") => {
                        if val.len() > 255 {
                            return Err(malformed_xml());
                        }
                        cur_rule.id = Some(val);
                    }
                    Some("AllowedOrigin") => cur_rule.allowed_origins.push(val),
                    Some("AllowedMethod") => {
                        if !matches!(val.as_str(), "GET" | "PUT" | "POST" | "DELETE" | "HEAD") {
                            return Err(S3Error::new(
                                S3ErrorCode::InvalidRequest,
                                format!("Found unsupported HTTP method in CORS config. Unsupported method is {val}"),
                            ));
                        }
                        cur_rule.allowed_methods.push(val);
                    }
                    Some("AllowedHeader") => cur_rule.allowed_headers.push(val),
                    Some("ExposeHeader") => cur_rule.expose_headers.push(val),
                    Some("MaxAgeSeconds") => {
                        let secs = val.parse::<u32>().map_err(|_| malformed_xml())?;
                        cur_rule.max_age_seconds = Some(secs);
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "ID" | "AllowedOrigin" | "AllowedMethod" | "AllowedHeader" | "ExposeHeader"
                    | "MaxAgeSeconds" => {
                        cur_tag = None;
                    }
                    "CORSRule" if in_rule => {
                        if cur_rule.allowed_origins.is_empty() || cur_rule.allowed_methods.is_empty()
                        {
                            return Err(malformed_xml());
                        }
                        rules.push(std::mem::replace(
                            &mut cur_rule,
                            CorsRule {
                                id: None,
                                allowed_origins: Vec::new(),
                                allowed_methods: Vec::new(),
                                allowed_headers: Vec::new(),
                                expose_headers: Vec::new(),
                                max_age_seconds: None,
                            },
                        ));
                        in_rule = false;
                    }
                    "CORSConfiguration" => {}
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(malformed_xml()),
        }
        buf.clear();
    }

    if !saw_root || rules.is_empty() || rules.len() > 100 {
        return Err(malformed_xml());
    }
    Ok(CorsConfiguration { rules })
}

/// Render `<CORSConfiguration>` XML response (`GET /{b}?cors`).
pub fn render_cors_xml(cors: &CorsConfiguration) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CORSConfiguration xmlns=\"{S3_XML_NS}\">"
    );
    for rule in &cors.rules {
        xml.push_str("<CORSRule>");
        if let Some(id) = &rule.id {
            xml.push_str(&format!("<ID>{}</ID>", xml_escape(id)));
        }
        for o in &rule.allowed_origins {
            xml.push_str(&format!("<AllowedOrigin>{}</AllowedOrigin>", xml_escape(o)));
        }
        for m in &rule.allowed_methods {
            xml.push_str(&format!("<AllowedMethod>{}</AllowedMethod>", xml_escape(m)));
        }
        for h in &rule.allowed_headers {
            xml.push_str(&format!("<AllowedHeader>{}</AllowedHeader>", xml_escape(h)));
        }
        for eh in &rule.expose_headers {
            xml.push_str(&format!("<ExposeHeader>{}</ExposeHeader>", xml_escape(eh)));
        }
        if let Some(age) = rule.max_age_seconds {
            xml.push_str(&format!("<MaxAgeSeconds>{age}</MaxAgeSeconds>"));
        }
        xml.push_str("</CORSRule>");
    }
    xml.push_str("</CORSConfiguration>");
    xml
}

/// Render `<PolicyStatus>` XML response (`GET /{b}?policyStatus`).
pub fn render_policy_status_xml(is_public: bool) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PolicyStatus xmlns=\"{S3_XML_NS}\"><IsPublic>{is_public}</IsPublic></PolicyStatus>"
    )
}

/// Parse `<PublicAccessBlockConfiguration>` XML body (`PUT /{b}?publicAccessBlock`).
pub fn parse_public_access_block_xml(body: &[u8]) -> StoreResult<PublicAccessBlockConfig> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut cur_tag: Option<String> = None;
    let mut cfg = PublicAccessBlockConfig::default();

    let parse_bool = |s: &str| -> StoreResult<bool> {
        if s.eq_ignore_ascii_case("true") {
            Ok(true)
        } else if s.eq_ignore_ascii_case("false") {
            Ok(false)
        } else {
            Err(malformed_xml())
        }
    };

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "PublicAccessBlockConfiguration" if !saw_root => saw_root = true,
                    "BlockPublicAcls"
                    | "IgnorePublicAcls"
                    | "BlockPublicPolicy"
                    | "RestrictPublicBuckets"
                        if saw_root && cur_tag.is_none() =>
                    {
                        cur_tag = Some(local.to_string());
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Empty(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                if local == "PublicAccessBlockConfiguration" && !saw_root {
                    saw_root = true;
                } else {
                    return Err(malformed_xml());
                }
            }
            Ok(Event::Text(t)) => {
                let val = t.unescape().map_err(|_| malformed_xml())?;
                match cur_tag.as_deref() {
                    Some("BlockPublicAcls") => cfg.block_public_acls = parse_bool(&val)?,
                    Some("IgnorePublicAcls") => cfg.ignore_public_acls = parse_bool(&val)?,
                    Some("BlockPublicPolicy") => cfg.block_public_policy = parse_bool(&val)?,
                    Some("RestrictPublicBuckets") => {
                        cfg.restrict_public_buckets = parse_bool(&val)?
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::End(e)) => {
                let local_bytes = e.local_name();
                let local = std::str::from_utf8(local_bytes.as_ref()).unwrap_or("");
                match local {
                    "BlockPublicAcls"
                    | "IgnorePublicAcls"
                    | "BlockPublicPolicy"
                    | "RestrictPublicBuckets" => {
                        cur_tag = None;
                    }
                    "PublicAccessBlockConfiguration" => {}
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(malformed_xml()),
        }
        buf.clear();
    }

    if !saw_root {
        return Err(malformed_xml());
    }
    Ok(cfg)
}

/// Render `<PublicAccessBlockConfiguration>` XML response (`GET /{b}?publicAccessBlock`).
pub fn render_public_access_block_xml(cfg: &PublicAccessBlockConfig) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PublicAccessBlockConfiguration xmlns=\"{S3_XML_NS}\"><BlockPublicAcls>{}</BlockPublicAcls><IgnorePublicAcls>{}</IgnorePublicAcls><BlockPublicPolicy>{}</BlockPublicPolicy><RestrictPublicBuckets>{}</RestrictPublicBuckets></PublicAccessBlockConfiguration>",
        cfg.block_public_acls,
        cfg.ignore_public_acls,
        cfg.block_public_policy,
        cfg.restrict_public_buckets,
    )
}

/// Render `<PostResponse>` XML (`PostObject` with `success_action_status = 201`; no `xmlns`).
pub fn render_post_response_xml(location: &str, bucket: &str, key: &str, etag: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PostResponse><Location>{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></PostResponse>",
        xml_escape(location),
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(etag),
    )
}

fn malformed_xml() -> S3Error {
    S3Error::new(
        S3ErrorCode::MalformedXML,
        "The XML you provided was not well-formed or did not validate against our published schema",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxe_and_dtd_rejected_nfr8() {
        let xxe = br#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><CreateBucketConfiguration>&xxe;</CreateBucketConfiguration>"#;
        assert_eq!(
            parse_create_bucket_xml(xxe).unwrap_err().code,
            S3ErrorCode::MalformedXML
        );
    }
}
