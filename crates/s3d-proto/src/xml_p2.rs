use std::collections::HashSet;

use quick_xml::events::Event;
use quick_xml::Reader;
use s3d_types::*;

use crate::xml::{
    check_no_dtd_or_entity, is_valid_acl_group_uri, malformed_xml, xml_escape, S3_XML_NS,
};

// ============================================================================
// 1. Object Lock XML (`?object-lock`, `?retention`, `?legal-hold`)
// ============================================================================

pub fn parse_object_lock_configuration_xml(body: &[u8]) -> StoreResult<ObjectLockConfiguration> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut saw_enabled = false;
    let mut enabled_val: Option<String> = None;
    let mut saw_rule = false;
    let mut in_rule = false;
    let mut saw_default_ret = false;
    let mut in_default_ret = false;
    let mut cur_tag: Option<String> = None;

    let mut mode_str: Option<String> = None;
    let mut days_str: Option<String> = None;
    let mut years_str: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match local {
                    "ObjectLockConfiguration" if !saw_root => saw_root = true,
                    "ObjectLockEnabled" if saw_root && !in_rule && !saw_enabled && cur_tag.is_none() => {
                        saw_enabled = true;
                        cur_tag = Some("ObjectLockEnabled".to_string());
                    }
                    "Rule" if saw_root && !saw_rule && !in_rule && cur_tag.is_none() => {
                        saw_rule = true;
                        in_rule = true;
                    }
                    "DefaultRetention" if in_rule && !saw_default_ret && !in_default_ret && cur_tag.is_none() => {
                        saw_default_ret = true;
                        in_default_ret = true;
                    }
                    "Mode" if in_default_ret && cur_tag.is_none() && mode_str.is_none() => {
                        cur_tag = Some("Mode".to_string());
                    }
                    "Days" if in_default_ret && cur_tag.is_none() && days_str.is_none() => {
                        cur_tag = Some("Days".to_string());
                    }
                    "Years" if in_default_ret && cur_tag.is_none() && years_str.is_none() => {
                        cur_tag = Some("Years".to_string());
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Empty(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                if local == "Rule" && saw_root && !saw_rule && !in_rule {
                    saw_rule = true;
                } else {
                    return Err(malformed_xml());
                }
            }
            Ok(Event::Text(t)) => {
                let val = t.unescape().map_err(|_| malformed_xml())?.into_owned();
                match cur_tag.as_deref() {
                    Some("ObjectLockEnabled") => enabled_val = Some(val),
                    Some("Mode") => mode_str = Some(val),
                    Some("Days") => days_str = Some(val),
                    Some("Years") => years_str = Some(val),
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::End(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match local {
                    "ObjectLockEnabled" | "Mode" | "Days" | "Years" => cur_tag = None,
                    "DefaultRetention" if in_default_ret => in_default_ret = false,
                    "Rule" if in_rule => in_rule = false,
                    "ObjectLockConfiguration" => {}
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(malformed_xml()),
        }
        buf.clear();
    }

    if !saw_root || enabled_val.as_deref() != Some("Enabled") {
        return Err(malformed_xml());
    }

    let default_retention = if saw_rule {
        if !saw_default_ret {
            None
        } else {
            let m_raw = mode_str.ok_or_else(malformed_xml)?;
            let mode = ObjectLockMode::from_aws_str_exact(&m_raw).ok_or_else(malformed_xml)?;
            let period = match (days_str, years_str) {
                (Some(d_s), None) => {
                    let n = d_s.parse::<i64>().map_err(|_| malformed_xml())?;
                    if n <= 0 || n > i64::from(i32::MAX) {
                        return Err(S3Error::new(
                            S3ErrorCode::InvalidRetentionPeriod,
                            "Default retention period must be a positive integer value",
                        ));
                    }
                    DefaultRetentionPeriod::Days(n as u32)
                }
                (None, Some(y_s)) => {
                    let n = y_s.parse::<i64>().map_err(|_| malformed_xml())?;
                    if n <= 0 || n > 100 {
                        return Err(S3Error::new(
                            S3ErrorCode::InvalidRetentionPeriod,
                            "Default retention period must be a positive integer value",
                        ));
                    }
                    DefaultRetentionPeriod::Years(n as u32)
                }
                _ => return Err(malformed_xml()),
            };
            Some(DefaultRetention { mode, period })
        }
    } else {
        None
    };

    Ok(ObjectLockConfiguration { default_retention })
}

pub fn render_object_lock_configuration_xml(cfg: &ObjectLockConfiguration) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ObjectLockConfiguration xmlns=\"{S3_XML_NS}\"><ObjectLockEnabled>Enabled</ObjectLockEnabled>"
    );
    if let Some(def) = cfg.default_retention {
        xml.push_str("<Rule><DefaultRetention>");
        xml.push_str(&format!("<Mode>{}</Mode>", def.mode.as_aws_str()));
        match def.period {
            DefaultRetentionPeriod::Days(d) => xml.push_str(&format!("<Days>{d}</Days>")),
            DefaultRetentionPeriod::Years(y) => xml.push_str(&format!("<Years>{y}</Years>")),
        }
        xml.push_str("</DefaultRetention></Rule>");
    }
    xml.push_str("</ObjectLockConfiguration>");
    xml
}

pub fn parse_object_retention_xml(body: &[u8]) -> StoreResult<ObjectRetention> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut cur_tag: Option<String> = None;
    let mut mode_str: Option<String> = None;
    let mut date_str: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match local {
                    "Retention" if !saw_root => saw_root = true,
                    "Mode" if saw_root && cur_tag.is_none() && mode_str.is_none() => {
                        cur_tag = Some("Mode".to_string());
                    }
                    "RetainUntilDate" if saw_root && cur_tag.is_none() && date_str.is_none() => {
                        cur_tag = Some("RetainUntilDate".to_string());
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Empty(_)) => return Err(malformed_xml()),
            Ok(Event::Text(t)) => {
                let val = t.unescape().map_err(|_| malformed_xml())?.into_owned();
                match cur_tag.as_deref() {
                    Some("Mode") => mode_str = Some(val),
                    Some("RetainUntilDate") => date_str = Some(val),
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::End(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match local {
                    "Mode" | "RetainUntilDate" => cur_tag = None,
                    "Retention" => {}
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
    let mode = ObjectLockMode::from_aws_str_exact(mode_str.as_deref().unwrap_or(""))
        .ok_or_else(malformed_xml)?;
    let retain_until_us =
        parse_iso8601_utc_us(date_str.as_deref().unwrap_or("")).ok_or_else(malformed_xml)?;

    Ok(ObjectRetention {
        mode,
        retain_until_us,
    })
}

pub fn render_object_retention_xml(ret: &ObjectRetention) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Retention xmlns=\"{S3_XML_NS}\"><Mode>{}</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>",
        ret.mode.as_aws_str(),
        format_iso8601_utc_us(ret.retain_until_us),
    )
}

pub fn parse_object_legal_hold_xml(body: &[u8]) -> StoreResult<LegalHoldStatus> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut cur_tag: Option<String> = None;
    let mut status_str: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match local {
                    "LegalHold" if !saw_root => saw_root = true,
                    "Status" if saw_root && cur_tag.is_none() && status_str.is_none() => {
                        cur_tag = Some("Status".to_string());
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Empty(_)) => return Err(malformed_xml()),
            Ok(Event::Text(t)) => {
                let val = t.unescape().map_err(|_| malformed_xml())?.into_owned();
                if cur_tag.as_deref() == Some("Status") {
                    status_str = Some(val);
                } else {
                    return Err(malformed_xml());
                }
            }
            Ok(Event::End(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match local {
                    "Status" => cur_tag = None,
                    "LegalHold" => {}
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
    LegalHoldStatus::from_aws_str_exact(status_str.as_deref().unwrap_or(""))
        .ok_or_else(malformed_xml)
}

pub fn render_object_legal_hold_xml(status: LegalHoldStatus) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LegalHold xmlns=\"{S3_XML_NS}\"><Status>{}</Status></LegalHold>",
        status.as_aws_str(),
    )
}

// ============================================================================
// 2. Lifecycle XML (`?lifecycle`)
// ============================================================================

#[derive(Default)]
struct RawFilterAcc {
    saw_prefix: Option<String>,
    saw_tag: Option<(String, String)>,
    saw_size_gt: Option<u64>,
    saw_size_lt: Option<u64>,
    saw_and: bool,
    and_prefix: Option<String>,
    and_tags: Vec<(String, String)>,
    and_size_gt: Option<u64>,
    and_size_lt: Option<u64>,
    direct_children: usize,
}

#[derive(Default)]
struct RawRuleAcc {
    id: Option<String>,
    status: Option<String>,
    legacy_prefix: Option<String>,
    has_filter: bool,
    filter: RawFilterAcc,
    has_exp: bool,
    exp_days: Option<i64>,
    exp_date_raw: Option<String>,
    exp_dm: Option<bool>,
    has_noncurrent: bool,
    noncurrent_days: Option<i64>,
    newer_noncurrent: Option<i64>,
    has_abort_mpu: bool,
    abort_days: Option<i64>,
}

pub fn parse_lifecycle_configuration_xml(body: &[u8]) -> StoreResult<LifecycleConfiguration> {
    if body.is_empty() || body.len() > 2 * 1024 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut stack: Vec<String> = Vec::new();
    let mut saw_root = false;
    let mut cur_rule = RawRuleAcc::default();
    let mut cur_tag_k: Option<String> = None;
    let mut cur_tag_v: Option<String> = None;
    let mut text_acc = String::new();
    let mut raw_rules: Vec<RawRuleAcc> = Vec::new();

    let parse_bool = |s: &str| -> StoreResult<bool> {
        match s.trim() {
            "true" | "True" | "TRUE" => Ok(true),
            "false" | "False" | "FALSE" => Ok(false),
            _ => Err(malformed_xml()),
        }
    };

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("").to_string();
                text_acc.clear();
                match (stack.as_slice(), local.as_str()) {
                    ([], "LifecycleConfiguration") | ([], "LifecycleConfigurationV2") if !saw_root => {
                        saw_root = true;
                    }
                    ([root], "Rule") if root == "LifecycleConfiguration" || root == "LifecycleConfigurationV2" => {
                        cur_rule = RawRuleAcc::default();
                    }
                    ([_, r], "ID" | "Status" | "Prefix") if r == "Rule" => {}
                    ([_, r], "Filter") if r == "Rule" && !cur_rule.has_filter => {
                        cur_rule.has_filter = true;
                    }
                    ([_, r, f], "Prefix" | "ObjectSizeGreaterThan" | "ObjectSizeLessThan")
                        if r == "Rule" && f == "Filter" =>
                    {
                        cur_rule.filter.direct_children += 1;
                    }
                    ([_, r, f], "Tag") if r == "Rule" && f == "Filter" => {
                        cur_rule.filter.direct_children += 1;
                        cur_tag_k = None;
                        cur_tag_v = None;
                    }
                    ([_, r, f], "And") if r == "Rule" && f == "Filter" && !cur_rule.filter.saw_and => {
                        cur_rule.filter.direct_children += 1;
                        cur_rule.filter.saw_and = true;
                    }
                    ([_, r, f, t], "Key" | "Value") if r == "Rule" && f == "Filter" && t == "Tag" => {}
                    ([_, r, f, a], "Prefix" | "ObjectSizeGreaterThan" | "ObjectSizeLessThan")
                        if r == "Rule" && f == "Filter" && a == "And" => {}
                    ([_, r, f, a], "Tag") if r == "Rule" && f == "Filter" && a == "And" => {
                        cur_tag_k = None;
                        cur_tag_v = None;
                    }
                    ([_, r, f, a, t], "Key" | "Value")
                        if r == "Rule" && f == "Filter" && a == "And" && t == "Tag" => {}
                    ([_, r], "Expiration") if r == "Rule" && !cur_rule.has_exp => {
                        cur_rule.has_exp = true;
                    }
                    ([_, r, ex], "Days" | "Date" | "ExpiredObjectDeleteMarker")
                        if r == "Rule" && ex == "Expiration" => {}
                    ([_, r], "NoncurrentVersionExpiration") if r == "Rule" && !cur_rule.has_noncurrent => {
                        cur_rule.has_noncurrent = true;
                    }
                    ([_, r, nc], "NoncurrentDays" | "NewerNoncurrentVersions")
                        if r == "Rule" && nc == "NoncurrentVersionExpiration" => {}
                    ([_, r], "AbortIncompleteMultipartUpload") if r == "Rule" && !cur_rule.has_abort_mpu => {
                        cur_rule.has_abort_mpu = true;
                    }
                    ([_, r, ab], "DaysAfterInitiation")
                        if r == "Rule" && ab == "AbortIncompleteMultipartUpload" => {}
                    _ => return Err(malformed_xml()),
                }
                stack.push(local);
            }
            Ok(Event::Empty(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match (stack.as_slice(), local) {
                    ([_, r], "ID") if r == "Rule" => cur_rule.id = Some(String::new()),
                    ([_, r], "Prefix") if r == "Rule" => cur_rule.legacy_prefix = Some(String::new()),
                    ([_, r], "Filter") if r == "Rule" && !cur_rule.has_filter => {
                        cur_rule.has_filter = true;
                    }
                    ([_, r, f], "Prefix") if r == "Rule" && f == "Filter" => {
                        cur_rule.filter.direct_children += 1;
                        cur_rule.filter.saw_prefix = Some(String::new());
                    }
                    ([_, r, f, a], "Prefix") if r == "Rule" && f == "Filter" && a == "And" => {
                        cur_rule.filter.and_prefix = Some(String::new());
                    }
                    ([_, r, f, t], "Key") if r == "Rule" && f == "Filter" && t == "Tag" => {
                        cur_tag_k = Some(String::new());
                    }
                    ([_, r, f, t], "Value") if r == "Rule" && f == "Filter" && t == "Tag" => {
                        cur_tag_v = Some(String::new());
                    }
                    ([_, r, f, a, t], "Key")
                        if r == "Rule" && f == "Filter" && a == "And" && t == "Tag" =>
                    {
                        cur_tag_k = Some(String::new());
                    }
                    ([_, r, f, a, t], "Value")
                        if r == "Rule" && f == "Filter" && a == "And" && t == "Tag" =>
                    {
                        cur_tag_v = Some(String::new());
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Text(t)) => {
                let txt = t.unescape().map_err(|_| malformed_xml())?;
                text_acc.push_str(&txt);
            }
            Ok(Event::End(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                let popped = stack.pop().ok_or_else(malformed_xml)?;
                if popped != local {
                    return Err(malformed_xml());
                }
                let val_raw = std::mem::take(&mut text_acc);
                let val_trim = val_raw.trim();

                match (stack.as_slice(), local) {
                    ([_], "Rule") => {
                        raw_rules.push(std::mem::take(&mut cur_rule));
                    }
                    ([_, r], "ID") if r == "Rule" => cur_rule.id = Some(val_raw),
                    ([_, r], "Status") if r == "Rule" => cur_rule.status = Some(val_trim.to_string()),
                    ([_, r], "Prefix") if r == "Rule" => cur_rule.legacy_prefix = Some(val_raw),
                    ([_, r, f], "Prefix") if r == "Rule" && f == "Filter" => {
                        cur_rule.filter.saw_prefix = Some(val_raw);
                    }
                    ([_, r, f], "ObjectSizeGreaterThan") if r == "Rule" && f == "Filter" => {
                        let sz = val_trim.parse::<u64>().map_err(|_| malformed_xml())?;
                        cur_rule.filter.saw_size_gt = Some(sz);
                    }
                    ([_, r, f], "ObjectSizeLessThan") if r == "Rule" && f == "Filter" => {
                        let sz = val_trim.parse::<u64>().map_err(|_| malformed_xml())?;
                        cur_rule.filter.saw_size_lt = Some(sz);
                    }
                    ([_, r, f, t], "Key") if r == "Rule" && f == "Filter" && t == "Tag" => {
                        cur_tag_k = Some(val_raw);
                    }
                    ([_, r, f, t], "Value") if r == "Rule" && f == "Filter" && t == "Tag" => {
                        cur_tag_v = Some(val_raw);
                    }
                    ([_, r, f], "Tag") if r == "Rule" && f == "Filter" => {
                        let k = cur_tag_k.take().ok_or_else(malformed_xml)?;
                        let v = cur_tag_v.take().ok_or_else(malformed_xml)?;
                        cur_rule.filter.saw_tag = Some((k, v));
                    }
                    ([_, r, f, a], "Prefix") if r == "Rule" && f == "Filter" && a == "And" => {
                        if cur_rule.filter.and_prefix.is_some() {
                            return Err(malformed_xml());
                        }
                        cur_rule.filter.and_prefix = Some(val_raw);
                    }
                    ([_, r, f, a], "ObjectSizeGreaterThan")
                        if r == "Rule" && f == "Filter" && a == "And" =>
                    {
                        if cur_rule.filter.and_size_gt.is_some() {
                            return Err(malformed_xml());
                        }
                        let sz = val_trim.parse::<u64>().map_err(|_| malformed_xml())?;
                        cur_rule.filter.and_size_gt = Some(sz);
                    }
                    ([_, r, f, a], "ObjectSizeLessThan")
                        if r == "Rule" && f == "Filter" && a == "And" =>
                    {
                        if cur_rule.filter.and_size_lt.is_some() {
                            return Err(malformed_xml());
                        }
                        let sz = val_trim.parse::<u64>().map_err(|_| malformed_xml())?;
                        cur_rule.filter.and_size_lt = Some(sz);
                    }
                    ([_, r, f, a, t], "Key")
                        if r == "Rule" && f == "Filter" && a == "And" && t == "Tag" =>
                    {
                        cur_tag_k = Some(val_raw);
                    }
                    ([_, r, f, a, t], "Value")
                        if r == "Rule" && f == "Filter" && a == "And" && t == "Tag" =>
                    {
                        cur_tag_v = Some(val_raw);
                    }
                    ([_, r, f, a], "Tag") if r == "Rule" && f == "Filter" && a == "And" => {
                        let k = cur_tag_k.take().ok_or_else(malformed_xml)?;
                        let v = cur_tag_v.take().ok_or_else(malformed_xml)?;
                        cur_rule.filter.and_tags.push((k, v));
                    }
                    ([_, r, ex], "Days") if r == "Rule" && ex == "Expiration" => {
                        let d = val_trim.parse::<i64>().map_err(|_| malformed_xml())?;
                        cur_rule.exp_days = Some(d);
                    }
                    ([_, r, ex], "Date") if r == "Rule" && ex == "Expiration" => {
                        cur_rule.exp_date_raw = Some(val_trim.to_string());
                    }
                    ([_, r, ex], "ExpiredObjectDeleteMarker")
                        if r == "Rule" && ex == "Expiration" =>
                    {
                        cur_rule.exp_dm = Some(parse_bool(val_trim)?);
                    }
                    ([_, r, nc], "NoncurrentDays")
                        if r == "Rule" && nc == "NoncurrentVersionExpiration" =>
                    {
                        let d = val_trim.parse::<i64>().map_err(|_| malformed_xml())?;
                        cur_rule.noncurrent_days = Some(d);
                    }
                    ([_, r, nc], "NewerNoncurrentVersions")
                        if r == "Rule" && nc == "NoncurrentVersionExpiration" =>
                    {
                        let n = val_trim.parse::<i64>().map_err(|_| malformed_xml())?;
                        cur_rule.newer_noncurrent = Some(n);
                    }
                    ([_, r, ab], "DaysAfterInitiation")
                        if r == "Rule" && ab == "AbortIncompleteMultipartUpload" =>
                    {
                        let d = val_trim.parse::<i64>().map_err(|_| malformed_xml())?;
                        cur_rule.abort_days = Some(d);
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(malformed_xml()),
        }
        buf.clear();
    }

    if !saw_root || !stack.is_empty() || raw_rules.is_empty() || raw_rules.len() > 1000 {
        return Err(malformed_xml());
    }

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut auto_seq = 1usize;
    let mut rules = Vec::with_capacity(raw_rules.len());

    // Pre-collect explicit IDs so auto-generated IDs never collide
    let explicit_ids: HashSet<String> = raw_rules
        .iter()
        .filter_map(|r| r.id.as_ref().filter(|s| !s.is_empty()).cloned())
        .collect();

    for r in raw_rules {
        let id = match r.id {
            Some(s) if !s.is_empty() => {
                if s.len() > 255 {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "ID length should not exceed allowed limit of 255",
                    ));
                }
                if !seen_ids.insert(s.clone()) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Rule ID must be unique. Found same ID for more than one rule",
                    ));
                }
                s
            }
            _ => {
                loop {
                    let cand = format!("rule-{auto_seq}");
                    auto_seq += 1;
                    if !explicit_ids.contains(&cand) && seen_ids.insert(cand.clone()) {
                        break cand;
                    }
                }
            }
        };

        let status = match r.status.as_deref() {
            Some("Enabled") => LifecycleRuleStatus::Enabled,
            Some("Disabled") => LifecycleRuleStatus::Disabled,
            _ => return Err(malformed_xml()),
        };

        let scope = match (r.legacy_prefix, r.has_filter) {
            (Some(_), true) | (None, false) => return Err(malformed_xml()),
            (Some(pfx), false) => LifecycleRuleScope::LegacyPrefix(pfx),
            (None, true) => {
                let flt = r.filter;
                if flt.direct_children > 1 {
                    return Err(malformed_xml());
                }
                let parsed_flt = if flt.direct_children == 0 {
                    LifecycleFilter::Empty
                } else if let Some(pfx) = flt.saw_prefix {
                    LifecycleFilter::Prefix(pfx)
                } else if let Some((k, v)) = flt.saw_tag {
                    validate_tags(&[(k.clone(), v.clone())], 10)?;
                    LifecycleFilter::Tag { key: k, value: v }
                } else if let Some(gt) = flt.saw_size_gt {
                    LifecycleFilter::ObjectSizeGreaterThan(gt)
                } else if let Some(lt) = flt.saw_size_lt {
                    LifecycleFilter::ObjectSizeLessThan(lt)
                } else if flt.saw_and {
                    validate_tags(&flt.and_tags, 10)?;
                    let pred_count = usize::from(flt.and_prefix.is_some())
                        + flt.and_tags.len()
                        + usize::from(flt.and_size_gt.is_some())
                        + usize::from(flt.and_size_lt.is_some());
                    if pred_count == 0 {
                        return Err(malformed_xml());
                    }
                    if let (Some(gt), Some(lt)) = (flt.and_size_gt, flt.and_size_lt)
                        && lt <= gt
                    {
                        return Err(S3Error::new(
                            S3ErrorCode::InvalidArgument,
                            "ObjectSizeLessThan must be greater than ObjectSizeGreaterThan",
                        ));
                    }
                    LifecycleFilter::And {
                        prefix: flt.and_prefix,
                        tags: flt.and_tags,
                        object_size_greater_than: flt.and_size_gt,
                        object_size_less_than: flt.and_size_lt,
                    }
                } else {
                    return Err(malformed_xml());
                };
                LifecycleRuleScope::Filter(parsed_flt)
            }
        };

        if !r.has_exp && !r.has_noncurrent && !r.has_abort_mpu {
            return Err(malformed_xml());
        }

        let has_tag_filter = matches!(
            &scope,
            LifecycleRuleScope::Filter(LifecycleFilter::Tag { .. })
        ) || matches!(
            &scope,
            LifecycleRuleScope::Filter(LifecycleFilter::And { tags, .. }) if !tags.is_empty()
        );

        let expiration = if r.has_exp {
            let set_count = usize::from(r.exp_days.is_some())
                + usize::from(r.exp_date_raw.is_some())
                + usize::from(r.exp_dm.is_some());
            if set_count != 1 {
                return Err(malformed_xml());
            }
            let days = if let Some(d) = r.exp_days {
                if d <= 0 || d > i64::from(i32::MAX) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "'Days' in Expiration action must be a positive integer",
                    ));
                }
                Some(d as u32)
            } else {
                None
            };
            let date_us = if let Some(ds) = &r.exp_date_raw {
                let us = parse_iso8601_utc_us(ds).ok_or_else(malformed_xml)?;
                if !is_exact_utc_midnight_us(us) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "'Date' must be at midnight GMT",
                    ));
                }
                Some(us)
            } else {
                None
            };
            if r.exp_dm.is_some() && has_tag_filter {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "ExpiredObjectDeleteMarker cannot be specified with Tags",
                ));
            }
            Some(LifecycleExpiration {
                days,
                date_us,
                expired_object_delete_marker: r.exp_dm,
            })
        } else {
            None
        };

        let noncurrent_version_expiration = if r.has_noncurrent {
            let Some(nd) = r.noncurrent_days else {
                return Err(malformed_xml());
            };
            if nd <= 0 || nd > i64::from(i32::MAX) {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "'NoncurrentDays' in NoncurrentVersionExpiration action must be a positive integer",
                ));
            }
            let newer = match r.newer_noncurrent {
                Some(n) if n <= 0 || n > i64::from(i32::MAX) => {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "'NewerNoncurrentVersions' must be a positive integer",
                    ));
                }
                Some(n) => Some(n as u32),
                None => None,
            };
            Some(NoncurrentVersionExpiration {
                noncurrent_days: nd as u32,
                newer_noncurrent_versions: newer,
            })
        } else {
            None
        };

        let abort_incomplete_multipart_upload = if r.has_abort_mpu {
            if has_tag_filter {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "AbortIncompleteMultipartUpload cannot be specified with Tags",
                ));
            }
            let Some(ad) = r.abort_days else {
                return Err(malformed_xml());
            };
            if ad <= 0 || ad > i64::from(i32::MAX) {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "'DaysAfterInitiation' in AbortIncompleteMultipartUpload action must be a positive integer",
                ));
            }
            Some(AbortIncompleteMultipartUpload {
                days_after_initiation: ad as u32,
            })
        } else {
            None
        };

        rules.push(LifecycleRule {
            id,
            status,
            scope,
            expiration,
            noncurrent_version_expiration,
            abort_incomplete_multipart_upload,
        });
    }

    Ok(LifecycleConfiguration { rules })
}

pub fn render_lifecycle_configuration_xml(cfg: &LifecycleConfiguration) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LifecycleConfiguration xmlns=\"{S3_XML_NS}\">"
    );
    for rule in &cfg.rules {
        xml.push_str("<Rule>");
        xml.push_str(&format!("<ID>{}</ID>", xml_escape(&rule.id)));
        match &rule.scope {
            LifecycleRuleScope::LegacyPrefix(pfx) => {
                xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(pfx)));
            }
            LifecycleRuleScope::Filter(flt) => {
                xml.push_str("<Filter>");
                match flt {
                    LifecycleFilter::Empty => {}
                    LifecycleFilter::Prefix(pfx) => {
                        xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(pfx)));
                    }
                    LifecycleFilter::Tag { key, value } => {
                        xml.push_str(&format!(
                            "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
                            xml_escape(key),
                            xml_escape(value)
                        ));
                    }
                    LifecycleFilter::ObjectSizeGreaterThan(gt) => {
                        xml.push_str(&format!("<ObjectSizeGreaterThan>{gt}</ObjectSizeGreaterThan>"));
                    }
                    LifecycleFilter::ObjectSizeLessThan(lt) => {
                        xml.push_str(&format!("<ObjectSizeLessThan>{lt}</ObjectSizeLessThan>"));
                    }
                    LifecycleFilter::And {
                        prefix,
                        tags,
                        object_size_greater_than,
                        object_size_less_than,
                    } => {
                        xml.push_str("<And>");
                        if let Some(pfx) = prefix {
                            xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(pfx)));
                        }
                        for (k, v) in tags {
                            xml.push_str(&format!(
                                "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
                                xml_escape(k),
                                xml_escape(v)
                            ));
                        }
                        if let Some(gt) = object_size_greater_than {
                            xml.push_str(&format!(
                                "<ObjectSizeGreaterThan>{gt}</ObjectSizeGreaterThan>"
                            ));
                        }
                        if let Some(lt) = object_size_less_than {
                            xml.push_str(&format!("<ObjectSizeLessThan>{lt}</ObjectSizeLessThan>"));
                        }
                        xml.push_str("</And>");
                    }
                }
                xml.push_str("</Filter>");
            }
        }
        xml.push_str(&format!("<Status>{}</Status>", rule.status.as_aws_str()));
        if let Some(exp) = &rule.expiration {
            xml.push_str("<Expiration>");
            if let Some(d) = exp.days {
                xml.push_str(&format!("<Days>{d}</Days>"));
            }
            if let Some(us) = exp.date_us {
                xml.push_str(&format!("<Date>{}</Date>", format_iso8601_utc_us(us)));
            }
            if let Some(dm) = exp.expired_object_delete_marker {
                xml.push_str(&format!(
                    "<ExpiredObjectDeleteMarker>{dm}</ExpiredObjectDeleteMarker>"
                ));
            }
            xml.push_str("</Expiration>");
        }
        if let Some(nc) = &rule.noncurrent_version_expiration {
            xml.push_str("<NoncurrentVersionExpiration>");
            xml.push_str(&format!("<NoncurrentDays>{}</NoncurrentDays>", nc.noncurrent_days));
            if let Some(n) = nc.newer_noncurrent_versions {
                xml.push_str(&format!(
                    "<NewerNoncurrentVersions>{n}</NewerNoncurrentVersions>"
                ));
            }
            xml.push_str("</NoncurrentVersionExpiration>");
        }
        if let Some(ab) = &rule.abort_incomplete_multipart_upload {
            xml.push_str(&format!(
                "<AbortIncompleteMultipartUpload><DaysAfterInitiation>{}</DaysAfterInitiation></AbortIncompleteMultipartUpload>",
                ab.days_after_initiation
            ));
        }
        xml.push_str("</Rule>");
    }
    xml.push_str("</LifecycleConfiguration>");
    xml
}

// ============================================================================
// 3. Bucket Encryption XML (`?encryption`)
// ============================================================================

pub fn parse_bucket_encryption_xml(body: &[u8]) -> StoreResult<BucketEncryptionConfig> {
    if body.is_empty() || body.len() > 64 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut saw_root = false;
    let mut in_rule = false;
    let mut rule_count = 0usize;
    let mut in_default = false;
    let mut saw_default = false;
    let mut cur_tag: Option<String> = None;

    let mut sse_algo: Option<String> = None;
    let mut kms_key_id: Option<String> = None;
    let mut bucket_key_enabled: Option<bool> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match local {
                    "ServerSideEncryptionConfiguration" if !saw_root => saw_root = true,
                    "Rule" if saw_root && !in_rule => {
                        in_rule = true;
                        rule_count += 1;
                    }
                    "ApplyServerSideEncryptionByDefault" if in_rule && !in_default => {
                        in_default = true;
                        saw_default = true;
                    }
                    "SSEAlgorithm" if in_default && cur_tag.is_none() => {
                        cur_tag = Some("SSEAlgorithm".to_string());
                    }
                    "KMSMasterKeyID" if in_default && cur_tag.is_none() => {
                        cur_tag = Some("KMSMasterKeyID".to_string());
                    }
                    "BucketKeyEnabled" if in_rule && !in_default && cur_tag.is_none() => {
                        cur_tag = Some("BucketKeyEnabled".to_string());
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Empty(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                if local == "KMSMasterKeyID" && in_default {
                    kms_key_id = Some(String::new());
                } else {
                    return Err(malformed_xml());
                }
            }
            Ok(Event::Text(t)) => {
                let val = t.unescape().map_err(|_| malformed_xml())?.into_owned();
                match cur_tag.as_deref() {
                    Some("SSEAlgorithm") => sse_algo = Some(val),
                    Some("KMSMasterKeyID") => kms_key_id = Some(val),
                    Some("BucketKeyEnabled") => {
                        let b = if val.eq_ignore_ascii_case("true") {
                            true
                        } else if val.eq_ignore_ascii_case("false") {
                            false
                        } else {
                            return Err(malformed_xml());
                        };
                        bucket_key_enabled = Some(b);
                    }
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::End(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match local {
                    "SSEAlgorithm" | "KMSMasterKeyID" | "BucketKeyEnabled" => cur_tag = None,
                    "ApplyServerSideEncryptionByDefault" if in_default => in_default = false,
                    "Rule" if in_rule => in_rule = false,
                    "ServerSideEncryptionConfiguration" => {}
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(malformed_xml()),
        }
        buf.clear();
    }

    if !saw_root || rule_count != 1 || !saw_default {
        return Err(malformed_xml());
    }
    let Some(alg) = sse_algo else {
        return Err(malformed_xml());
    };
    if alg != "AES256" {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "The encryption method specified is not supported",
        ));
    }
    if kms_key_id.is_some() {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "KMSMasterKeyID is not applicable to AES256",
        ));
    }

    Ok(BucketEncryptionConfig {
        sse_algorithm: "AES256".to_string(),
        bucket_key_enabled,
    })
}

pub fn render_bucket_encryption_xml(cfg: &BucketEncryptionConfig) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ServerSideEncryptionConfiguration xmlns=\"{S3_XML_NS}\"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>{}</SSEAlgorithm></ApplyServerSideEncryptionByDefault>",
        xml_escape(&cfg.sse_algorithm)
    );
    if let Some(bke) = cfg.bucket_key_enabled {
        xml.push_str(&format!("<BucketKeyEnabled>{bke}</BucketKeyEnabled>"));
    }
    xml.push_str("</Rule></ServerSideEncryptionConfiguration>");
    xml
}

// ============================================================================
// 4. Bucket Logging XML (`?logging`)
// ============================================================================

pub fn parse_bucket_logging_xml<FId, FEmail>(
    body: &[u8],
    resolve_id: FId,
    resolve_email: FEmail,
) -> StoreResult<BucketLoggingStatus>
where
    FId: Fn(&str) -> Option<OwnerInfo>,
    FEmail: Fn(&str) -> Option<OwnerInfo>,
{
    if body.is_empty() || body.len() > 256 * 1024 {
        return Err(malformed_xml());
    }
    check_no_dtd_or_entity(body)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut stack: Vec<String> = Vec::new();
    let mut saw_root = false;
    let mut saw_logging_enabled = false;
    let mut target_bucket: Option<String> = None;
    let mut target_prefix: Option<String> = None;
    let mut key_format: Option<TargetObjectKeyFormat> = None;
    let mut saw_partitioned = false;
    let mut partition_source_raw: Option<String> = None;

    let mut cur_grantee_type: Option<String> = None;
    let mut cur_grantee_id: Option<String> = None;
    let mut cur_grantee_email: Option<String> = None;
    let mut cur_grantee_uri: Option<String> = None;
    let mut cur_grant_perm: Option<String> = None;
    type RawGrant = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut raw_grants: Vec<RawGrant> = Vec::new();
    let mut text_acc = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("").to_string();
                text_acc.clear();
                match (stack.as_slice(), local.as_str()) {
                    ([], "BucketLoggingStatus") if !saw_root => saw_root = true,
                    ([r], "LoggingEnabled") if r == "BucketLoggingStatus" && !saw_logging_enabled => {
                        saw_logging_enabled = true;
                    }
                    ([_, le], "TargetBucket" | "TargetPrefix" | "TargetGrants" | "TargetObjectKeyFormat")
                        if le == "LoggingEnabled" => {}
                    ([_, le, tg], "Grant") if le == "LoggingEnabled" && tg == "TargetGrants" => {
                        cur_grantee_type = None;
                        cur_grantee_id = None;
                        cur_grantee_email = None;
                        cur_grantee_uri = None;
                        cur_grant_perm = None;
                    }
                    ([_, le, tg, g], "Grantee")
                        if le == "LoggingEnabled" && tg == "TargetGrants" && g == "Grant" =>
                    {
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            if (key == "type" || key.ends_with(":type"))
                                && let Ok(v) = attr.unescape_value()
                            {
                                cur_grantee_type = Some(v.into_owned());
                            }
                        }
                    }
                    ([_, le, tg, g], "Permission")
                        if le == "LoggingEnabled" && tg == "TargetGrants" && g == "Grant" => {}
                    ([_, le, tg, g, gr], "ID" | "DisplayName" | "EmailAddress" | "URI")
                        if le == "LoggingEnabled"
                            && tg == "TargetGrants"
                            && g == "Grant"
                            && gr == "Grantee" => {}
                    ([_, le, kf], "SimplePrefix")
                        if le == "LoggingEnabled"
                            && kf == "TargetObjectKeyFormat"
                            && key_format.is_none()
                            && !saw_partitioned =>
                    {
                        key_format = Some(TargetObjectKeyFormat::SimplePrefix);
                    }
                    ([_, le, kf], "PartitionedPrefix")
                        if le == "LoggingEnabled"
                            && kf == "TargetObjectKeyFormat"
                            && key_format.is_none()
                            && !saw_partitioned =>
                    {
                        saw_partitioned = true;
                    }
                    ([_, le, kf, pp], "PartitionDateSource")
                        if le == "LoggingEnabled"
                            && kf == "TargetObjectKeyFormat"
                            && pp == "PartitionedPrefix" => {}
                    _ => return Err(malformed_xml()),
                }
                stack.push(local);
            }
            Ok(Event::Empty(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                match (stack.as_slice(), local) {
                    ([], "BucketLoggingStatus") if !saw_root => saw_root = true,
                    ([_, le], "TargetPrefix") if le == "LoggingEnabled" => {
                        target_prefix = Some(String::new());
                    }
                    ([_, le], "TargetGrants") if le == "LoggingEnabled" => {}
                    ([_, le, kf], "SimplePrefix")
                        if le == "LoggingEnabled"
                            && kf == "TargetObjectKeyFormat"
                            && key_format.is_none()
                            && !saw_partitioned =>
                    {
                        key_format = Some(TargetObjectKeyFormat::SimplePrefix);
                    }
                    ([_, le, kf], "PartitionedPrefix")
                        if le == "LoggingEnabled"
                            && kf == "TargetObjectKeyFormat"
                            && key_format.is_none()
                            && !saw_partitioned =>
                    {
                        saw_partitioned = true;
                    }
                    ([_, le, tg, g, gr], "DisplayName")
                        if le == "LoggingEnabled"
                            && tg == "TargetGrants"
                            && g == "Grant"
                            && gr == "Grantee" => {}
                    _ => return Err(malformed_xml()),
                }
            }
            Ok(Event::Text(t)) => {
                let txt = t.unescape().map_err(|_| malformed_xml())?;
                text_acc.push_str(&txt);
            }
            Ok(Event::End(e)) => {
                let lb = e.local_name();
                let local = std::str::from_utf8(lb.as_ref()).unwrap_or("");
                let popped = stack.pop().ok_or_else(malformed_xml)?;
                if popped != local {
                    return Err(malformed_xml());
                }
                let val_raw = std::mem::take(&mut text_acc);
                let val_trim = val_raw.trim();

                match (stack.as_slice(), local) {
                    ([_, le], "TargetBucket") if le == "LoggingEnabled" => {
                        target_bucket = Some(val_trim.to_string());
                    }
                    ([_, le], "TargetPrefix") if le == "LoggingEnabled" => {
                        target_prefix = Some(val_raw);
                    }
                    ([_, le, kf, pp], "PartitionDateSource")
                        if le == "LoggingEnabled"
                            && kf == "TargetObjectKeyFormat"
                            && pp == "PartitionedPrefix" =>
                    {
                        partition_source_raw = Some(val_trim.to_string());
                    }
                    ([_, le, tg, g, gr], "ID")
                        if le == "LoggingEnabled"
                            && tg == "TargetGrants"
                            && g == "Grant"
                            && gr == "Grantee" =>
                    {
                        cur_grantee_id = Some(val_trim.to_string());
                    }
                    ([_, le, tg, g, gr], "EmailAddress")
                        if le == "LoggingEnabled"
                            && tg == "TargetGrants"
                            && g == "Grant"
                            && gr == "Grantee" =>
                    {
                        cur_grantee_email = Some(val_trim.to_string());
                    }
                    ([_, le, tg, g, gr], "URI")
                        if le == "LoggingEnabled"
                            && tg == "TargetGrants"
                            && g == "Grant"
                            && gr == "Grantee" =>
                    {
                        cur_grantee_uri = Some(val_trim.to_string());
                    }
                    ([_, le, tg, g], "Permission")
                        if le == "LoggingEnabled" && tg == "TargetGrants" && g == "Grant" =>
                    {
                        cur_grant_perm = Some(val_trim.to_string());
                    }
                    ([_, le, tg], "Grant") if le == "LoggingEnabled" && tg == "TargetGrants" => {
                        raw_grants.push((
                            cur_grantee_type.take(),
                            cur_grantee_id.take(),
                            cur_grantee_email.take(),
                            cur_grantee_uri.take(),
                            cur_grant_perm.take(),
                        ));
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(malformed_xml()),
        }
        buf.clear();
    }

    if !saw_root || !stack.is_empty() {
        return Err(malformed_xml());
    }
    if !saw_logging_enabled {
        return Ok(BucketLoggingStatus {
            logging_enabled: None,
        });
    }

    let tb = target_bucket
        .filter(|s| !s.is_empty())
        .ok_or_else(malformed_xml)?;
    let tp = target_prefix.ok_or_else(malformed_xml)?;

    let target_object_key_format = if saw_partitioned {
        let src = match partition_source_raw.as_deref() {
            None => PartitionDateSource::DeliveryTime,
            Some(s) => PartitionDateSource::from_aws_str_exact(s).ok_or_else(malformed_xml)?,
        };
        Some(TargetObjectKeyFormat::PartitionedPrefix(src))
    } else {
        key_format
    };

    let mut target_grants = Vec::with_capacity(raw_grants.len());
    for (g_type, g_id, g_email, g_uri, g_perm) in raw_grants {
        let perm_str = g_perm.ok_or_else(malformed_xml)?;
        let permission = AclPermission::from_aws_str(&perm_str).ok_or_else(malformed_xml)?;
        if !matches!(
            permission,
            AclPermission::FullControl | AclPermission::Read | AclPermission::Write
        ) {
            return Err(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid logging target grant permission",
            ));
        }

        let effective_type = match g_type.as_deref() {
            Some(t) => t,
            None if g_id.is_some() => "CanonicalUser",
            None if g_email.is_some() => "AmazonCustomerByEmail",
            None if g_uri.is_some() => "Group",
            None => return Err(malformed_xml()),
        };

        let grantee = match effective_type {
            "CanonicalUser" => {
                let uid = g_id.filter(|s| !s.is_empty()).ok_or_else(malformed_xml)?;
                let user = resolve_id(&uid)
                    .ok_or_else(|| S3Error::new(S3ErrorCode::InvalidArgument, "Invalid id"))?;
                AclGrantee::CanonicalUser(user)
            }
            "AmazonCustomerByEmail" => {
                let email = g_email
                    .filter(|s| !s.is_empty())
                    .ok_or_else(malformed_xml)?;
                let user = resolve_email(&email).ok_or_else(|| {
                    S3Error::new(
                        S3ErrorCode::UnresolvableGrantByEmailAddress,
                        "The e-mail address you provided does not match any account on record.",
                    )
                })?;
                AclGrantee::CanonicalUser(user)
            }
            "Group" => {
                let uri = g_uri.filter(|s| !s.is_empty()).ok_or_else(malformed_xml)?;
                if !is_valid_acl_group_uri(&uri) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Invalid group uri",
                    ));
                }
                AclGrantee::Group(uri)
            }
            _ => return Err(malformed_xml()),
        };

        target_grants.push(AclGrant {
            grantee,
            permission,
        });
    }

    Ok(BucketLoggingStatus {
        logging_enabled: Some(LoggingEnabled {
            target_bucket: tb,
            target_prefix: tp,
            target_grants,
            target_object_key_format,
        }),
    })
}

pub fn render_bucket_logging_xml(status: &BucketLoggingStatus) -> String {
    let Some(le) = &status.logging_enabled else {
        return format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<BucketLoggingStatus xmlns=\"{S3_XML_NS}\"/>"
        );
    };

    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<BucketLoggingStatus xmlns=\"{S3_XML_NS}\"><LoggingEnabled>"
    );
    xml.push_str(&format!(
        "<TargetBucket>{}</TargetBucket><TargetPrefix>{}</TargetPrefix>",
        xml_escape(&le.target_bucket),
        xml_escape(&le.target_prefix)
    ));
    if !le.target_grants.is_empty() {
        xml.push_str("<TargetGrants>");
        for grant in &le.target_grants {
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
        xml.push_str("</TargetGrants>");
    }

    xml.push_str("<TargetObjectKeyFormat>");
    match le
        .target_object_key_format
        .unwrap_or(TargetObjectKeyFormat::SimplePrefix)
    {
        TargetObjectKeyFormat::SimplePrefix => xml.push_str("<SimplePrefix/>"),
        TargetObjectKeyFormat::PartitionedPrefix(src) => {
            xml.push_str(&format!(
                "<PartitionedPrefix><PartitionDateSource>{}</PartitionDateSource></PartitionedPrefix>",
                src.as_aws_str()
            ));
        }
    }
    xml.push_str("</TargetObjectKeyFormat>");
    xml.push_str("</LoggingEnabled></BucketLoggingStatus>");
    xml
}
