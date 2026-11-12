use quick_xml::events::Event;
use quick_xml::Reader;
use s3d_types::*;

use crate::sigv4::format_iso8601_millis;
use crate::uri::aws_uri_encode;

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
            encode_field(d, url_encode, true)
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
            encode_field(d, url_encode, true)
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
            encode_field(d, url_encode, true)
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
        let tag = match csum.algorithm {
            ChecksumAlgorithm::Crc32 => "ChecksumCRC32",
            ChecksumAlgorithm::Crc32c => "ChecksumCRC32C",
            ChecksumAlgorithm::Crc64Nvme => "ChecksumCRC64NVME",
            ChecksumAlgorithm::Sha1 => "ChecksumSHA1",
            ChecksumAlgorithm::Sha256 => "ChecksumSHA256",
        };
        xml.push_str(&format!("<{tag}>{}</{tag}>", xml_escape(&csum.value_b64)));
    }
    xml.push_str("</CopyObjectResult>");
    xml
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
