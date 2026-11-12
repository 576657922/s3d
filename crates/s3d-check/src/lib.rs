//! `VR-4` §3.3 Single-Key WGL Linearizability Checker & 16-Client / 8-Key HTTP Workload Driver.
//!
//! Implements:
//! 1. Deterministic self-describing object payloads (`(client_id: u16, op_id: u64, total_len: u32)`)
//!    with full byte-level integrity & MD5 `ETag` verification on every `GET`.
//! 2. Exact single-key S3 state-machine specification covering `PutObject`,
//!    `PutObject(If-None-Match: *)`, `PutObject(If-Match)`, `GetObject`, `HeadObject`,
//!    `DeleteObject`, and `DeleteObject(If-Match)`.
//! 3. Wing & Gong / Lowe (WGL) backtracking linearizability checker with `BitSet` state
//!    memoization and sound & complete confluent pure-observation reduction.
//! 4. Live 16-client / 8-key async HTTP/1.1 campaign runner over `s3d-server` + `s3d-engine`
//!    (`OsDisk`) with concurrent background GC (`compact()`) and checkpointing (`write_checkpoint()`).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use md5::{Digest as _, Md5};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use s3d_disk::OsDisk;
use s3d_engine::{run_fsck, Engine, EngineConfig};
use s3d_proto::SigV4Verifier;
use s3d_server::config::ServerConfig;
use s3d_server::metrics::ServerMetrics;
use s3d_server::run_listeners_with_telemetry;
use s3d_types::{AccountRecord, ObjectOwnership, OwnerInfo, SecretKey};
use sha2::Sha256;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Barrier, Mutex};

type HmacSha256 = Hmac<Sha256>;

const AK: &str = "AKIAIOSFODNN7EXAMPLE";
const SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";

/// Deterministic 64-bit unique write token derived from `(client_id, op_id)` (`!= 0`).
pub fn make_write_token(client_id: u16, op_id: u64) -> u64 {
    let low = (op_id & 0x0000_FFFF_FFFF_FFFF).max(1);
    ((client_id as u64) << 48) | low
}

fn fill_byte(token: u64, idx: usize) -> u8 {
    let mixed = token
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(idx as u64)
        .rotate_left(((idx & 7) * 8) as u32);
    (mixed ^ (mixed >> 32)) as u8
}

/// Encode a deterministic self-describing payload (`len >= 16`) and return `(Bytes, token, quoted_etag)`.
pub fn encode_self_describing_payload(
    client_id: u16,
    op_id: u64,
    total_len: usize,
) -> (Bytes, u64, String) {
    let len = total_len.max(16);
    let token = make_write_token(client_id, op_id);
    let mut buf = Vec::with_capacity(len);
    buf.extend_from_slice(&client_id.to_be_bytes());
    buf.extend_from_slice(&op_id.to_be_bytes());
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    for i in 14..len {
        buf.push(fill_byte(token, i));
    }
    let etag = format!("\"{}\"", hex::encode(Md5::digest(&buf)));
    (Bytes::from(buf), token, etag)
}

/// Verify a `GET` payload byte-for-byte against its self-describing header and `ETag` header.
pub fn decode_and_verify_payload(body: &[u8], resp_etag: &str) -> Result<u64, String> {
    if body.len() < 16 {
        return Err(format!("GET body too short: {} bytes", body.len()));
    }
    let client_id = u16::from_be_bytes([body[0], body[1]]);
    let op_id = u64::from_be_bytes(body[2..10].try_into().unwrap());
    let declared_len = u32::from_be_bytes(body[10..14].try_into().unwrap()) as usize;
    if declared_len != body.len() {
        return Err(format!(
            "torn/truncated GET payload: header len={declared_len}, actual len={}",
            body.len()
        ));
    }
    let token = make_write_token(client_id, op_id);
    for (offset, &b) in body[14..].iter().enumerate() {
        let expected = fill_byte(token, 14 + offset);
        if b != expected {
            return Err(format!(
                "corrupted byte at offset {}: got 0x{b:02x}, expected 0x{expected:02x}",
                14 + offset
            ));
        }
    }
    let computed_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));
    if resp_etag != computed_etag {
        return Err(format!(
            "GET ETag mismatch: header={resp_etag}, body_md5={computed_etag}"
        ));
    }
    Ok(token)
}

/// Single-key S3 operation issued by a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinOp {
    Put {
        token: u64,
        expected_etag: String,
    },
    PutIfNoneMatchStar {
        token: u64,
        expected_etag: String,
    },
    PutIfMatch {
        match_etag: String,
        token: u64,
        expected_etag: String,
    },
    Get,
    Head,
    Delete,
    DeleteIfMatch {
        match_etag: String,
    },
}

/// Observed HTTP outcome of a `LinOp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinOutcome {
    PutOk { etag: String },
    GetOk { token: u64, etag: String },
    HeadOk { etag: String },
    DeleteOk,
    NotFound,
    PreconditionFailed,
}

/// Recorded client invocation/completion interval on a single key.
#[derive(Debug, Clone)]
pub struct HistoryEvent {
    pub client_id: u16,
    pub client_seq: u64,
    pub invoke_ns: u64,
    pub return_ns: u64,
    pub op: LinOp,
    pub outcome: LinOutcome,
}

/// Abstract single-key state on an unversioned bucket: `None` = absent, `Some((token, etag))` = present.
pub type KeyModelState = Option<(u64, String)>;

/// Sequential S3 single-key specification transition function.
/// Returns `Some(next_state)` iff `outcome` is legal when executing `op` in `state`.
pub fn step_single_key_spec(
    state: &KeyModelState,
    op: &LinOp,
    outcome: &LinOutcome,
) -> Option<KeyModelState> {
    match op {
        LinOp::Put {
            token,
            expected_etag,
        } => match outcome {
            LinOutcome::PutOk { etag } if etag == expected_etag => {
                Some(Some((*token, etag.clone())))
            }
            _ => None,
        },
        LinOp::PutIfNoneMatchStar {
            token,
            expected_etag,
        } => match state {
            None => match outcome {
                LinOutcome::PutOk { etag } if etag == expected_etag => {
                    Some(Some((*token, etag.clone())))
                }
                _ => None,
            },
            Some(_) => match outcome {
                LinOutcome::PreconditionFailed => Some(state.clone()),
                _ => None,
            },
        },
        LinOp::PutIfMatch {
            match_etag,
            token,
            expected_etag,
        } => match state {
            None => match outcome {
                LinOutcome::NotFound => Some(None),
                _ => None,
            },
            Some((_, cur_etag)) => {
                if cur_etag == match_etag {
                    match outcome {
                        LinOutcome::PutOk { etag } if etag == expected_etag => {
                            Some(Some((*token, etag.clone())))
                        }
                        _ => None,
                    }
                } else {
                    match outcome {
                        LinOutcome::PreconditionFailed => Some(state.clone()),
                        _ => None,
                    }
                }
            }
        },
        LinOp::Get => match state {
            None => match outcome {
                LinOutcome::NotFound => Some(None),
                _ => None,
            },
            Some((tok, cur_etag)) => match outcome {
                LinOutcome::GetOk { token, etag } if token == tok && etag == cur_etag => {
                    Some(state.clone())
                }
                _ => None,
            },
        },
        LinOp::Head => match state {
            None => match outcome {
                LinOutcome::NotFound => Some(None),
                _ => None,
            },
            Some((_, cur_etag)) => match outcome {
                LinOutcome::HeadOk { etag } if etag == cur_etag => Some(state.clone()),
                _ => None,
            },
        },
        LinOp::Delete => match outcome {
            LinOutcome::DeleteOk => Some(None),
            _ => None,
        },
        LinOp::DeleteIfMatch { match_etag } => match state {
            None => match outcome {
                LinOutcome::NotFound => Some(None),
                _ => None,
            },
            Some((_, cur_etag)) => {
                if cur_etag == match_etag {
                    match outcome {
                        LinOutcome::DeleteOk => Some(None),
                        _ => None,
                    }
                } else {
                    match outcome {
                        LinOutcome::PreconditionFailed => Some(state.clone()),
                        _ => None,
                    }
                }
            }
        },
    }
}

/// Returns `true` iff `(op, outcome)` is a pure observation that NEVER mutates ANY state `S'`
/// in which it is enabled (`forall S': step(S', op, outcome) == Some(S_next) ==> S_next == S'`).
fn is_pure_observation(op: &LinOp, outcome: &LinOutcome) -> bool {
    matches!(op, LinOp::Get | LinOp::Head)
        || matches!(
            outcome,
            LinOutcome::NotFound | LinOutcome::PreconditionFailed
        )
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct WordBitSet {
    words: Box<[u64]>,
}

impl WordBitSet {
    fn full(n: usize) -> Self {
        let num_words = n.div_ceil(64);
        let mut words = vec![!0u64; num_words].into_boxed_slice();
        let rem = n % 64;
        if rem != 0 && num_words > 0 {
            words[num_words - 1] = (1u64 << rem) - 1;
        }
        Self { words }
    }

    #[inline]
    fn contains(&self, idx: usize) -> bool {
        (self.words[idx / 64] & (1u64 << (idx % 64))) != 0
    }

    #[inline]
    fn remove(&mut self, idx: usize) {
        self.words[idx / 64] &= !(1u64 << (idx % 64));
    }

    #[inline]
    fn first_set(&self) -> Option<usize> {
        for (wi, &w) in self.words.iter().enumerate() {
            if w != 0 {
                return Some(wi * 64 + w.trailing_zeros() as usize);
            }
        }
        None
    }
}

struct StateInterner {
    to_id: HashMap<(u64, String), u32>,
    from_id: Vec<KeyModelState>,
}

impl StateInterner {
    fn new() -> Self {
        Self {
            to_id: HashMap::new(),
            from_id: vec![None], // id 0 == None
        }
    }

    fn intern(&mut self, st: &KeyModelState) -> u32 {
        let Some((tok, etag)) = st else {
            return 0;
        };
        if let Some(&id) = self.to_id.get(&(*tok, etag.clone())) {
            return id;
        }
        let id = self.from_id.len() as u32;
        self.from_id.push(Some((*tok, etag.clone())));
        self.to_id.insert((*tok, etag.clone()), id);
        id
    }

    fn get(&self, id: u32) -> &KeyModelState {
        &self.from_id[id as usize]
    }
}

/// Verify single-key linearizability via Wing & Gong / Lowe (WGL) backtracking search
/// with `(WordBitSet, state_id)` memoization and confluent pure-observation peeling.
pub fn check_single_key_linearizable(events: &[HistoryEvent]) -> Result<(), String> {
    check_single_key_linearizable_from(&None, events)
}

pub fn check_single_key_linearizable_from(
    initial_state: &KeyModelState,
    events: &[HistoryEvent],
) -> Result<(), String> {
    if events.is_empty() {
        return Ok(());
    }
    for (idx, ev) in events.iter().enumerate() {
        if ev.return_ns < ev.invoke_ns {
            return Err(format!(
                "event {idx} has return_ns ({}) < invoke_ns ({})",
                ev.return_ns, ev.invoke_ns
            ));
        }
    }

    // Sort events by ascending `(return_ns, invoke_ns, client_id, client_seq)`.
    // Then `min_return` among unlinearized events is simply `sorted[unlin.first_set()].return_ns`!
    let mut sorted: Vec<HistoryEvent> = events.to_vec();
    sorted.sort_by_key(|e| (e.return_ns, e.invoke_ns, e.client_id, e.client_seq));

    // Precompute immediate program-order predecessor index on the same client.
    let n = sorted.len();
    let mut prev_same_client: Vec<Option<usize>> = vec![None; n];
    let mut per_client: HashMap<u16, Vec<(u64, usize)>> = HashMap::new();
    for (i, e) in sorted.iter().enumerate() {
        per_client
            .entry(e.client_id)
            .or_default()
            .push((e.client_seq, i));
    }
    for list in per_client.values_mut() {
        list.sort_by_key(|(seq, _)| *seq);
        for w in list.windows(2) {
            prev_same_client[w[1].1] = Some(w[0].1);
        }
    }

    let mut interner = StateInterner::new();
    let init_id = interner.intern(initial_state);
    for e in &sorted {
        if let LinOp::Put {
            token,
            expected_etag,
        }
        | LinOp::PutIfNoneMatchStar {
            token,
            expected_etag,
        }
        | LinOp::PutIfMatch {
            token,
            expected_etag,
            ..
        } = &e.op
        {
            interner.intern(&Some((*token, expected_etag.clone())));
        }
    }

    let mut visited: HashSet<(WordBitSet, u32)> = HashSet::new();
    let unlin = WordBitSet::full(n);

    if wgl_dfs(
        unlin,
        init_id,
        &sorted,
        &prev_same_client,
        &mut interner,
        &mut visited,
    ) {
        Ok(())
    } else {
        Err(format!(
            "NON-LINEARIZABLE single-key history ({n} events, {} distinct memoized search states explored)",
            visited.len()
        ))
    }
}

fn wgl_dfs(
    mut unlin: WordBitSet,
    state_id: u32,
    ops: &[HistoryEvent],
    prev_same_client: &[Option<usize>],
    interner: &mut StateInterner,
    visited: &mut HashSet<(WordBitSet, u32)>,
) -> bool {
    // 1. Confluent pure-observation reduction: greedily linearize any minimal operation
    //    that is enabled in `state_id` and preserves EVERY state in which it is enabled.
    loop {
        let Some(first_idx) = unlin.first_set() else {
            return true;
        };
        let min_ret = ops[first_idx].return_ns;
        let state_ref = interner.get(state_id);
        let mut peeled_any = false;

        for wi in 0..unlin.words.len() {
            let mut w = unlin.words[wi];
            while w != 0 {
                let bit = w.trailing_zeros() as usize;
                w &= w - 1;
                let k = wi * 64 + bit;
                let ev = &ops[k];
                if ev.invoke_ns <= min_ret
                    && prev_same_client[k].is_none_or(|p| !unlin.contains(p))
                    && is_pure_observation(&ev.op, &ev.outcome)
                    && step_single_key_spec(state_ref, &ev.op, &ev.outcome).is_some()
                {
                    unlin.remove(k);
                    peeled_any = true;
                }
            }
        }
        if !peeled_any {
            break;
        }
    }

    let Some(first_idx) = unlin.first_set() else {
        return true;
    };

    if !visited.insert((unlin.clone(), state_id)) {
        return false;
    }

    let min_ret = ops[first_idx].return_ns;
    let mut candidates: Vec<(usize, u32)> = Vec::new();
    for wi in 0..unlin.words.len() {
        let mut w = unlin.words[wi];
        while w != 0 {
            let bit = w.trailing_zeros() as usize;
            w &= w - 1;
            let k = wi * 64 + bit;
            let ev = &ops[k];
            if ev.invoke_ns <= min_ret && prev_same_client[k].is_none_or(|p| !unlin.contains(p)) {
                let next_opt = {
                    let state_ref = interner.get(state_id);
                    step_single_key_spec(state_ref, &ev.op, &ev.outcome)
                };
                if let Some(next_st) = next_opt {
                    let next_id = interner.intern(&next_st);
                    candidates.push((k, next_id));
                }
            }
        }
    }

    for (k, next_id) in candidates {
        let mut next_unlin = unlin.clone();
        next_unlin.remove(k);
        if wgl_dfs(
            next_unlin,
            next_id,
            ops,
            prev_same_client,
            interner,
            visited,
        ) {
            return true;
        }
    }

    false
}

// ============================================================================
// HTTP 16-Client / 8-Key Live Campaign Runner (`VR-4` §3.3)
// ============================================================================

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn derive_signing_key(secret: &str, date_ymd: &str, region: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date_ymd.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    hmac_sha256(&k_service, b"aws4_request")
}

fn now_amz_date() -> (String, String) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    let ymd = format!("{year:04}{m:02}{d:02}");
    let full = format!("{ymd}T{hh:02}{mm:02}{ss:02}Z");
    (ymd, full)
}

fn build_signed_s3_req(
    method: &str,
    host: &str,
    path: &str,
    extra_header: Option<(&str, &str)>,
    body: Bytes,
) -> Request<Full<Bytes>> {
    let (ymd, amz_date) = now_amz_date();
    let payload_hash = sha256_hex(&body);

    let mut hdrs: Vec<(&str, String)> = vec![
        ("host", host.to_string()),
        ("x-amz-content-sha256", payload_hash.clone()),
        ("x-amz-date", amz_date.clone()),
    ];
    if let Some((k, v)) = extra_header {
        hdrs.push((k, v.to_string()));
    }
    hdrs.sort_by_key(|(k, _)| *k);

    let mut canonical_headers = String::new();
    let mut signed_names = Vec::with_capacity(hdrs.len());
    for (k, v) in &hdrs {
        canonical_headers.push_str(k);
        canonical_headers.push(':');
        canonical_headers.push_str(v.trim());
        canonical_headers.push('\n');
        signed_names.push(*k);
    }
    let signed_headers = signed_names.join(";");

    let canonical_req =
        format!("{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let scope = format!("{ymd}/{REGION}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_req.as_bytes())
    );
    let signing_key = derive_signing_key(SK, &ymd, REGION);
    let sig = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let auth =
        format!("AWS4-HMAC-SHA256 Credential={AK}/{scope}, SignedHeaders={signed_headers}, Signature={sig}");

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", host)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("Authorization", auth);
    if let Some((k, v)) = extra_header {
        builder = builder.header(k, v);
    }
    if method == "PUT" {
        builder = builder.header("Content-Length", body.len().to_string());
    }
    builder.body(Full::new(body)).unwrap()
}

struct PersistentHttpClient {
    addr: String,
    sender: Option<http1::SendRequest<Full<Bytes>>>,
}

impl PersistentHttpClient {
    fn new(addr: String) -> Self {
        Self { addr, sender: None }
    }

    async fn send(&mut self, req: Request<Full<Bytes>>) -> Result<(u16, Option<String>, Bytes), String> {
        if self.sender.is_none() {
            let stream = TcpStream::connect(&self.addr)
                .await
                .map_err(|e| format!("connect {} failed: {e}", self.addr))?;
            stream.set_nodelay(true).ok();
            let (sender, conn) = http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| format!("http1 handshake failed: {e}"))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            self.sender = Some(sender);
        }

        let sender = self.sender.as_mut().unwrap();
        if sender.ready().await.is_err() {
            self.sender = None;
            let stream = TcpStream::connect(&self.addr)
                .await
                .map_err(|e| format!("reconnect {} failed: {e}", self.addr))?;
            stream.set_nodelay(true).ok();
            let (new_sender, conn) = http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| format!("http1 handshake failed: {e}"))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            self.sender = Some(new_sender);
        }

        let resp = self
            .sender
            .as_mut()
            .unwrap()
            .send_request(req)
            .await
            .map_err(|e| {
                self.sender = None;
                format!("HTTP request failed: {e}")
            })?;
        let status = resp.status().as_u16();
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("HTTP body read failed: {e}"))?
            .to_bytes();
        Ok((status, etag, body))
    }
}

#[derive(Debug, Clone)]
pub struct WglCampaignSummary {
    pub rounds: usize,
    pub num_keys: usize,
    pub total_histories_verified: usize,
    pub total_http_ops: usize,
    pub elapsed_secs: f64,
}

/// Run a live 16-client / 8-key HTTP/1.1 linearizability campaign against `s3d` on `OsDisk`,
/// including background `compact()` + `write_checkpoint()` and a final offline `run_fsck` check.
pub async fn run_http_wgl_campaign(
    data_dir: &std::path::Path,
    rounds: usize,
    ops_per_client_per_round: usize,
    seed: u64,
) -> Result<WglCampaignSummary, String> {
    const NUM_CLIENTS: usize = 16;
    const NUM_KEYS: usize = 8;
    const BUCKET: &str = "wgl-lin-bkt";

    let t0 = Instant::now();
    let disk = OsDisk::new(data_dir).map_err(|e| format!("OsDisk::new failed: {e}"))?;
    let engine_cfg = EngineConfig {
        segment_size: 256 * 1024, // 256 KiB segments so rollover + GC trigger frequently!
        wal_file_size: 512 * 1024,
        max_block_payload: 4096,
        gc_live_ratio: 0.8,
        group_commit_window_ms: 1,
        group_commit_max_batch: 64,
        reserved_disk_bytes: 0,
        default_object_ownership: ObjectOwnership::BucketOwnerEnforced,
        ..EngineConfig::default()
    };
    let engine = Engine::open(disk, engine_cfg).map_err(|e| format!("Engine::open failed: {e}"))?;

    let accounts = vec![AccountRecord {
        access_key: AK.to_string(),
        secret_key: SecretKey::new(SK.to_string()),
        owner: OwnerInfo {
            user_id: "0123456789abcdef".to_string(),
            display_name: "wgl".to_string(),
            email: "wgl@example.com".to_string(),
        },
    }];
    let auth = Arc::new(SigV4Verifier::new(REGION.to_string(), accounts));
    let metrics = Arc::new(ServerMetrics::default());

    let s3_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_addr = s3_listener.local_addr().unwrap().to_string();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let srv_cfg = ServerConfig {
        max_connections: 256,
        ..ServerConfig::default()
    };
    let eng_poison = Arc::clone(&engine);
    let eng_metrics = Arc::clone(&engine);
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let srv_handle = tokio::spawn(run_listeners_with_telemetry(
        s3_listener,
        admin_listener,
        Arc::clone(&engine),
        auth,
        srv_cfg,
        metrics,
        move || eng_poison.is_read_only_poisoned(),
        move || Some(eng_metrics.metrics_snapshot()),
        async move {
            let _ = stop_rx.await;
        },
    ));

    // Create bucket via HTTP
    {
        let mut init_cli = PersistentHttpClient::new(s3_addr.clone());
        let (st, _, body) = init_cli
            .send(build_signed_s3_req(
                "PUT",
                &s3_addr,
                &format!("/{BUCKET}"),
                None,
                Bytes::new(),
            ))
            .await?;
        if st != 200 {
            return Err(format!(
                "CreateBucket returned {st}: {}",
                String::from_utf8_lossy(&body)
            ));
        }
    }

    // Background maintenance task running `compact()` + `write_checkpoint()` concurrently with HTTP traffic!
    let bg_stop = Arc::new(AtomicBool::new(false));
    let bg_stop_c = Arc::clone(&bg_stop);
    let bg_eng = Arc::clone(&engine);
    let bg_task = tokio::spawn(async move {
        while !bg_stop_c.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(25)).await;
            if bg_stop_c.load(Ordering::Relaxed) {
                break;
            }
            let _ = bg_eng.compact().await;
            let _ = bg_eng.write_checkpoint().await;
        }
    });

    // Shared per-round event collector & known-ETag hint slots (for high-contention If-Match CAS races!)
    let round_events: Arc<Mutex<Vec<Vec<HistoryEvent>>>> =
        Arc::new(Mutex::new((0..NUM_KEYS).map(|_| Vec::new()).collect()));
    let etag_hints: Arc<Vec<Mutex<Option<String>>>> =
        Arc::new((0..NUM_KEYS).map(|_| Mutex::new(None)).collect());
    let start_barrier = Arc::new(Barrier::new(NUM_CLIENTS));
    let end_barrier = Arc::new(Barrier::new(NUM_CLIENTS));
    let verify_barrier = Arc::new(Barrier::new(NUM_CLIENTS));
    let global_op_counter = Arc::new(AtomicU64::new(1));
    let violation_err: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let mut handles = tokio::task::JoinSet::new();
    for cid in 0..NUM_CLIENTS {
        let addr = s3_addr.clone();
        let rev = Arc::clone(&round_events);
        let hints = Arc::clone(&etag_hints);
        let sb = Arc::clone(&start_barrier);
        let eb = Arc::clone(&end_barrier);
        let vb = Arc::clone(&verify_barrier);
        let op_cnt = Arc::clone(&global_op_counter);
        let verr = Arc::clone(&violation_err);

        handles.spawn(async move {
            let mut cli = PersistentHttpClient::new(addr.clone());
            let mut rng = StdRng::seed_from_u64(
                seed ^ (cid as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15),
            );
            let mut client_seq = 0u64;

            for _round in 0..rounds {
                // Clients 0..8 clean-reset k0..k7 to `None` before the round starts
                if cid < NUM_KEYS {
                    let path = format!("/{BUCKET}/k{cid}");
                    let (st, _, _) = cli
                        .send(build_signed_s3_req("DELETE", &addr, &path, None, Bytes::new()))
                        .await?;
                    if st != 204 {
                        return Err(format!("pre-round reset DELETE {path} returned {st}"));
                    }
                    *hints[cid].lock().await = None;
                }

                sb.wait().await;
                if verr.lock().await.is_some() {
                    break;
                }

                let mut local_by_key: Vec<Vec<HistoryEvent>> =
                    (0..NUM_KEYS).map(|_| Vec::new()).collect();

                for _ in 0..ops_per_client_per_round {
                    client_seq += 1;
                    let key_idx = rng.gen_range(0..NUM_KEYS);
                    let path = format!("/{BUCKET}/k{key_idx}");
                    let op_id = op_cnt.fetch_add(1, Ordering::Relaxed);
                    let payload_len = match rng.gen_range(0..4u8) {
                        0 => 16,
                        1 => 64,
                        2 => 256,
                        _ => 512,
                    };
                    let hint_etag = hints[key_idx].lock().await.clone();

                    // Biased mix across all 7 operations (heavy conditional CAS + GET/HEAD + PUT/DELETE)
                    let choice = rng.gen_range(0..100u32);
                    let op = if choice < 22 {
                        let (_, tok, et) =
                            encode_self_describing_payload(cid as u16, op_id, payload_len);
                        LinOp::Put {
                            token: tok,
                            expected_etag: et,
                        }
                    } else if choice < 36 {
                        let (_, tok, et) =
                            encode_self_describing_payload(cid as u16, op_id, payload_len);
                        LinOp::PutIfNoneMatchStar {
                            token: tok,
                            expected_etag: et,
                        }
                    } else if choice < 52 {
                        let match_et =
                            hint_etag.unwrap_or_else(|| "\"00000000000000000000000000000000\"".into());
                        let (_, tok, et) =
                            encode_self_describing_payload(cid as u16, op_id, payload_len);
                        LinOp::PutIfMatch {
                            match_etag: match_et,
                            token: tok,
                            expected_etag: et,
                        }
                    } else if choice < 72 {
                        LinOp::Get
                    } else if choice < 84 {
                        LinOp::Head
                    } else if choice < 92 {
                        LinOp::Delete
                    } else {
                        let match_et =
                            hint_etag.unwrap_or_else(|| "\"00000000000000000000000000000000\"".into());
                        LinOp::DeleteIfMatch {
                            match_etag: match_et,
                        }
                    };

                    let req = match &op {
                        LinOp::Put { .. } => {
                            let (body, _, _) =
                                encode_self_describing_payload(cid as u16, op_id, payload_len);
                            build_signed_s3_req("PUT", &addr, &path, None, body)
                        }
                        LinOp::PutIfNoneMatchStar { .. } => {
                            let (body, _, _) =
                                encode_self_describing_payload(cid as u16, op_id, payload_len);
                            build_signed_s3_req(
                                "PUT",
                                &addr,
                                &path,
                                Some(("if-none-match", "*")),
                                body,
                            )
                        }
                        LinOp::PutIfMatch { match_etag, .. } => {
                            let (body, _, _) =
                                encode_self_describing_payload(cid as u16, op_id, payload_len);
                            build_signed_s3_req(
                                "PUT",
                                &addr,
                                &path,
                                Some(("if-match", match_etag.as_str())),
                                body,
                            )
                        }
                        LinOp::Get => build_signed_s3_req("GET", &addr, &path, None, Bytes::new()),
                        LinOp::Head => build_signed_s3_req("HEAD", &addr, &path, None, Bytes::new()),
                        LinOp::Delete => {
                            build_signed_s3_req("DELETE", &addr, &path, None, Bytes::new())
                        }
                        LinOp::DeleteIfMatch { match_etag } => build_signed_s3_req(
                            "DELETE",
                            &addr,
                            &path,
                            Some(("if-match", match_etag.as_str())),
                            Bytes::new(),
                        ),
                    };

                    let invoke_ns = t0.elapsed().as_nanos() as u64;
                    let (status, resp_etag, resp_body) = cli.send(req).await?;
                    let return_ns = (t0.elapsed().as_nanos() as u64).max(invoke_ns);

                    let outcome = match (&op, status) {
                        (
                            LinOp::Put { .. }
                            | LinOp::PutIfNoneMatchStar { .. }
                            | LinOp::PutIfMatch { .. },
                            200,
                        ) => {
                            let et = resp_etag
                                .ok_or_else(|| "PUT 200 missing ETag header".to_string())?;
                            *hints[key_idx].lock().await = Some(et.clone());
                            LinOutcome::PutOk { etag: et }
                        }
                        (LinOp::Get, 200) => {
                            let et = resp_etag
                                .ok_or_else(|| "GET 200 missing ETag header".to_string())?;
                            let tok = decode_and_verify_payload(&resp_body, &et)?;
                            *hints[key_idx].lock().await = Some(et.clone());
                            LinOutcome::GetOk {
                                token: tok,
                                etag: et,
                            }
                        }
                        (LinOp::Head, 200) => {
                            let et = resp_etag
                                .ok_or_else(|| "HEAD 200 missing ETag header".to_string())?;
                            *hints[key_idx].lock().await = Some(et.clone());
                            LinOutcome::HeadOk { etag: et }
                        }
                        (LinOp::Delete | LinOp::DeleteIfMatch { .. }, 204) => {
                            *hints[key_idx].lock().await = None;
                            LinOutcome::DeleteOk
                        }
                        (_, 404) => LinOutcome::NotFound,
                        (_, 412) => LinOutcome::PreconditionFailed,
                        (_, other) => {
                            return Err(format!(
                                "unexpected HTTP status {other} on {op:?}: {}",
                                String::from_utf8_lossy(&resp_body)
                            ));
                        }
                    };

                    local_by_key[key_idx].push(HistoryEvent {
                        client_id: cid as u16,
                        client_seq,
                        invoke_ns,
                        return_ns,
                        op,
                        outcome,
                    });
                }

                {
                    let mut guard = rev.lock().await;
                    for k in 0..NUM_KEYS {
                        guard[k].append(&mut local_by_key[k]);
                    }
                }

                eb.wait().await;

                // Clients 0..8 each verify linearizability of key `cid` in parallel!
                if cid < NUM_KEYS {
                    let history = {
                        let mut guard = rev.lock().await;
                        std::mem::take(&mut guard[cid])
                    };
                    if let Err(msg) = check_single_key_linearizable(&history) {
                        *verr.lock().await = Some(format!("key k{cid}: {msg}"));
                    }
                }

                vb.wait().await;
            }

            Ok::<(), String>(())
        });
    }

    while let Some(res) = handles.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                handles.abort_all();
                return Err(e);
            }
            Err(e) => {
                handles.abort_all();
                return Err(format!("client task panicked: {e}"));
            }
        }
    }

    bg_stop.store(true, Ordering::Relaxed);
    let _ = bg_task.await;
    let _ = stop_tx.send(());
    srv_handle
        .await
        .map_err(|e| format!("server task panicked: {e}"))??;

    if let Some(err) = violation_err.lock().await.take() {
        return Err(err);
    }

    drop(engine);
    let fsck_disk = OsDisk::new(data_dir).map_err(|e| format!("fsck OsDisk::new failed: {e}"))?;
    let rep = run_fsck(fsck_disk);
    if rep.status != "ok" {
        return Err(format!(
            "post-campaign fsck failed: {:?}",
            rep.errors
        ));
    }

    Ok(WglCampaignSummary {
        rounds,
        num_keys: NUM_KEYS,
        total_histories_verified: rounds * NUM_KEYS,
        total_http_ops: rounds * NUM_CLIENTS * ops_per_client_per_round,
        elapsed_secs: t0.elapsed().as_secs_f64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_wgl_accepts_valid_overlapping_concurrent_histories() {
        // 2 concurrent writers W1 (t=10..50) and W2 (t=20..60), overlapping GETs observing W1 then W2,
        // plus concurrent If-None-Match:* where W1 wins and W2 gets 412!
        let events = vec![
            HistoryEvent {
                client_id: 1,
                client_seq: 1,
                invoke_ns: 10,
                return_ns: 50,
                op: LinOp::PutIfNoneMatchStar {
                    token: 101,
                    expected_etag: "\"e1\"".into(),
                },
                outcome: LinOutcome::PutOk {
                    etag: "\"e1\"".into(),
                },
            },
            HistoryEvent {
                client_id: 2,
                client_seq: 1,
                invoke_ns: 15,
                return_ns: 55,
                op: LinOp::PutIfNoneMatchStar {
                    token: 202,
                    expected_etag: "\"e2\"".into(),
                },
                outcome: LinOutcome::PreconditionFailed,
            },
            HistoryEvent {
                client_id: 3,
                client_seq: 1,
                invoke_ns: 20,
                return_ns: 45,
                op: LinOp::Get,
                outcome: LinOutcome::NotFound,
            },
            HistoryEvent {
                client_id: 4,
                client_seq: 1,
                invoke_ns: 30,
                return_ns: 70,
                op: LinOp::Get,
                outcome: LinOutcome::GetOk {
                    token: 101,
                    etag: "\"e1\"".into(),
                },
            },
            HistoryEvent {
                client_id: 1,
                client_seq: 2,
                invoke_ns: 60,
                return_ns: 90,
                op: LinOp::PutIfMatch {
                    match_etag: "\"e1\"".into(),
                    token: 103,
                    expected_etag: "\"e3\"".into(),
                },
                outcome: LinOutcome::PutOk {
                    etag: "\"e3\"".into(),
                },
            },
            HistoryEvent {
                client_id: 2,
                client_seq: 2,
                invoke_ns: 65,
                return_ns: 95,
                op: LinOp::DeleteIfMatch {
                    match_etag: "\"e1\"".into(),
                },
                outcome: LinOutcome::PreconditionFailed,
            },
        ];
        check_single_key_linearizable(&events).expect("valid history must be linearizable");
    }

    #[test]
    fn unit_wgl_rejects_stale_read_and_double_cas_violations() {
        // Violation 1: Stale read after strictly-preceding overwrite (`return_ns < invoke_ns`)
        let stale_read = vec![
            HistoryEvent {
                client_id: 1,
                client_seq: 1,
                invoke_ns: 10,
                return_ns: 20,
                op: LinOp::Put {
                    token: 1,
                    expected_etag: "\"e1\"".into(),
                },
                outcome: LinOutcome::PutOk {
                    etag: "\"e1\"".into(),
                },
            },
            HistoryEvent {
                client_id: 1,
                client_seq: 2,
                invoke_ns: 30,
                return_ns: 40,
                op: LinOp::Put {
                    token: 2,
                    expected_etag: "\"e2\"".into(),
                },
                outcome: LinOutcome::PutOk {
                    etag: "\"e2\"".into(),
                },
            },
            HistoryEvent {
                client_id: 2,
                client_seq: 1,
                invoke_ns: 50,
                return_ns: 60,
                op: LinOp::Get,
                outcome: LinOutcome::GetOk {
                    token: 1,
                    etag: "\"e1\"".into(),
                },
            },
        ];
        assert!(
            check_single_key_linearizable(&stale_read).is_err(),
            "WGL must reject stale read after overwrite"
        );

        // Violation 2: Two concurrent `PutIfNoneMatchStar` calls both claiming 200 OK without an intervening Delete!
        let double_create = vec![
            HistoryEvent {
                client_id: 1,
                client_seq: 1,
                invoke_ns: 10,
                return_ns: 50,
                op: LinOp::PutIfNoneMatchStar {
                    token: 1,
                    expected_etag: "\"e1\"".into(),
                },
                outcome: LinOutcome::PutOk {
                    etag: "\"e1\"".into(),
                },
            },
            HistoryEvent {
                client_id: 2,
                client_seq: 1,
                invoke_ns: 12,
                return_ns: 52,
                op: LinOp::PutIfNoneMatchStar {
                    token: 2,
                    expected_etag: "\"e2\"".into(),
                },
                outcome: LinOutcome::PutOk {
                    etag: "\"e2\"".into(),
                },
            },
        ];
        assert!(
            check_single_key_linearizable(&double_create).is_err(),
            "WGL must reject two concurrent If-None-Match:* winners"
        );

        // Violation 3: Read-after-delete seeing deleted object after Delete strictly completed
        let ghost_read = vec![
            HistoryEvent {
                client_id: 1,
                client_seq: 1,
                invoke_ns: 10,
                return_ns: 20,
                op: LinOp::Put {
                    token: 1,
                    expected_etag: "\"e1\"".into(),
                },
                outcome: LinOutcome::PutOk {
                    etag: "\"e1\"".into(),
                },
            },
            HistoryEvent {
                client_id: 2,
                client_seq: 1,
                invoke_ns: 30,
                return_ns: 40,
                op: LinOp::Delete,
                outcome: LinOutcome::DeleteOk,
            },
            HistoryEvent {
                client_id: 3,
                client_seq: 1,
                invoke_ns: 50,
                return_ns: 60,
                op: LinOp::Get,
                outcome: LinOutcome::GetOk {
                    token: 1,
                    etag: "\"e1\"".into(),
                },
            },
        ];
        assert!(
            check_single_key_linearizable(&ghost_read).is_err(),
            "WGL must reject ghost read after confirmed Delete"
        );
    }
}
