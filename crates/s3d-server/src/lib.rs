//! HTTP/1.1 S3 server, connection rate-limiter, admin `/health` & `/metrics` endpoints, and graceful shutdown.

pub mod body;
pub mod config;
pub mod metrics;
pub mod router;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use s3d_disk::OsDisk;
use s3d_engine::{Engine, EngineConfig, EngineMetricsSnapshot};
use s3d_proto::{render_error_xml, SigV4Verifier};
use s3d_types::{ObjectStore, S3Error, S3ErrorCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{Instant, Sleep};
use tracing::{error, info, warn};

use crate::body::S3ResponseBody;
use crate::config::{load_credentials_file, parse_duration_ms, ServerConfig};
use crate::metrics::ServerMetrics;
use crate::router::{handle_s3_request, AppState};

/// Wrapper around an async transport enforcing `NFR-9` idle keep-alive disconnect (`60s` default).
struct IdleTimeoutIo<I> {
    inner: I,
    idle_timeout: Duration,
    last_activity: Instant,
    sleep: Pin<Box<Sleep>>,
}

impl<I> IdleTimeoutIo<I> {
    fn new(inner: I, idle_timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            inner,
            idle_timeout,
            last_activity: now,
            sleep: Box::pin(tokio::time::sleep_until(now + idle_timeout)),
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for IdleTimeoutIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    self.last_activity = Instant::now();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => loop {
                let deadline = self.last_activity + self.idle_timeout;
                if self.sleep.deadline() != deadline {
                    self.sleep.as_mut().reset(deadline);
                }
                match self.sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        if Instant::now() >= self.last_activity + self.idle_timeout {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "connection idle timeout",
                            )));
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                }
            },
        }
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res
            && *n > 0 {
                self.last_activity = Instant::now();
            }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Start `s3d` with `OsDisk` + `Engine<OsDisk>` until `shutdown` resolves (`NFR-14`).
pub async fn run_production_server(
    cfg: ServerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    cfg.validate()?;
    let accounts = load_credentials_file(&cfg.credentials_file)?;
    let ownership = cfg.parsed_object_ownership()?;
    let retention_ms = cfg.completed_upload_retention_ms()?;
    let ckpt_interval_ms = parse_duration_ms(&cfg.checkpoint_interval)? as u64;

    let disk = OsDisk::new(&cfg.data_dir)
        .map_err(|e| format!("failed to initialize data_dir {}: {e}", cfg.data_dir.display()))?;

    let engine_cfg = EngineConfig {
        region: cfg.region.clone(),
        segment_size: cfg.segment_size,
        wal_file_size: cfg.wal_file_size,
        checkpoint_wal_bytes: cfg.checkpoint_wal_bytes,
        checkpoint_interval_ms: ckpt_interval_ms,
        reserved_disk_bytes: cfg.reserved_disk_bytes,
        max_buckets_per_account: cfg.max_buckets_per_account,
        max_object_size: cfg.max_object_size,
        completed_upload_retention_ms: retention_ms,
        default_object_ownership: ownership,
        gc_live_ratio: cfg.gc_live_ratio,
        group_commit_window_ms: cfg.group_commit_window_ms,
        group_commit_max_batch: cfg.group_commit_max_batch,
        ..EngineConfig::default()
    };

    let engine = Engine::open(disk, engine_cfg)
        .map_err(|e| format!("storage engine open/recovery failed: {e}"))?;

    let auth = Arc::new(SigV4Verifier::new(cfg.region.clone(), accounts));
    let metrics = Arc::new(ServerMetrics::default());

    let s3_listener = TcpListener::bind(&cfg.listen)
        .await
        .map_err(|e| format!("failed to bind S3 listener {}: {e}", cfg.listen))?;
    let admin_listener = TcpListener::bind(&cfg.admin_listen)
        .await
        .map_err(|e| format!("failed to bind admin listener {}: {e}", cfg.admin_listen))?;

    info!(
        s3_addr = %s3_listener.local_addr().unwrap(),
        admin_addr = %admin_listener.local_addr().unwrap(),
        data_dir = %cfg.data_dir.display(),
        region = %cfg.region,
        "s3d started and ready"
    );

    // Background periodic lifecycle, checkpoint & compaction loop (§8.5, §8.7, PR-39..40)
    let (maint_stop_tx, mut maint_stop_rx) = watch::channel(false);
    let maint_engine = Arc::clone(&engine);
    let ckpt_interval_dur = Duration::from_millis(ckpt_interval_ms.max(1_000));
    let lc_debug_interval_secs = cfg.lc_debug_interval_secs;
    let maint_handle = tokio::spawn(async move {
        let mut last_ckpt = Instant::now();
        let mut ticks = 0u64;
        loop {
            tokio::select! {
                _ = maint_stop_rx.changed() => break,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    if maint_engine.is_read_only_poisoned() {
                        continue;
                    }
                    ticks += 1;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64;
                    if let Err(e) = maint_engine.run_lifecycle_tick(now_ms, lc_debug_interval_secs).await {
                        warn!(%e, "background lifecycle tick failed");
                    }
                    if maint_engine.should_checkpoint() || last_ckpt.elapsed() >= ckpt_interval_dur {
                        if let Err(e) = maint_engine.write_checkpoint().await {
                            warn!(%e, "background checkpoint failed");
                        } else {
                            last_ckpt = Instant::now();
                        }
                    }
                    if ticks.is_multiple_of(5)
                        && let Err(e) = maint_engine.compact().await {
                            warn!(%e, "background GC compaction failed");
                        }
                }
            }
        }
    });

    let engine_health = Arc::clone(&engine);
    let engine_metrics = Arc::clone(&engine);
    let res = run_listeners_with_telemetry(
        s3_listener,
        admin_listener,
        Arc::clone(&engine),
        auth,
        cfg,
        metrics,
        move || engine_health.is_read_only_poisoned(),
        move || Some(engine_metrics.metrics_snapshot()),
        shutdown,
    )
    .await;

    let _ = maint_stop_tx.send(true);
    let _ = maint_handle.await;

    // [NFR-14] Write a clean checkpoint before exiting after draining in-flight requests
    if !engine.is_read_only_poisoned() {
        match engine.write_checkpoint().await {
            Ok(lsn) => info!(lsn, "final shutdown checkpoint written"),
            Err(e) => error!(%e, "failed to write final shutdown checkpoint"),
        }
    }

    res
}

#[allow(clippy::too_many_arguments)]
pub async fn run_listeners_with_store<S, F>(
    s3_listener: TcpListener,
    admin_listener: TcpListener,
    store: Arc<S>,
    auth: Arc<SigV4Verifier>,
    cfg: ServerConfig,
    metrics: Arc<ServerMetrics>,
    is_poisoned_fn: F,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String>
where
    S: ObjectStore,
    F: Fn() -> bool + Send + Sync + 'static,
{
    run_listeners_with_telemetry(
        s3_listener,
        admin_listener,
        store,
        auth,
        cfg,
        metrics,
        is_poisoned_fn,
        || None,
        shutdown,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_listeners_with_telemetry<S, F, M>(
    s3_listener: TcpListener,
    admin_listener: TcpListener,
    store: Arc<S>,
    auth: Arc<SigV4Verifier>,
    cfg: ServerConfig,
    metrics: Arc<ServerMetrics>,
    is_poisoned_fn: F,
    engine_metrics_fn: M,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String>
where
    S: ObjectStore,
    F: Fn() -> bool + Send + Sync + 'static,
    M: Fn() -> Option<EngineMetricsSnapshot> + Send + Sync + 'static,
{
    let max_conns = cfg.max_connections;
    let header_timeout = cfg.header_read_timeout;
    let idle_timeout = cfg.idle_timeout;
    let conn_sem = Arc::new(Semaphore::new(max_conns));
    let state = Arc::new(AppState {
        store,
        auth,
        cfg,
        metrics: Arc::clone(&metrics),
    });

    let (stop_tx, mut stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = stop_tx.send(true);
    });

    let admin_stop_rx = stop_rx.clone();
    let (admin_kill_tx, mut admin_kill_rx) = watch::channel(false);
    let admin_metrics = Arc::clone(&metrics);
    let is_poisoned = Arc::new(is_poisoned_fn);
    let admin_is_poisoned = Arc::clone(&is_poisoned);
    let eng_metrics = Arc::new(engine_metrics_fn);
    let admin_eng_metrics = Arc::clone(&eng_metrics);
    let admin_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = admin_kill_rx.changed() => break,
                accepted = admin_listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue; };
                    let m = Arc::clone(&admin_metrics);
                    let p = Arc::clone(&admin_is_poisoned);
                    let em = Arc::clone(&admin_eng_metrics);
                    let draining_rx = admin_stop_rx.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let m = Arc::clone(&m);
                            let p = Arc::clone(&p);
                            let em = Arc::clone(&em);
                            let draining = *draining_rx.borrow();
                            async move {
                                let snap = em();
                                Ok::<_, Infallible>(handle_admin_request(
                                    req,
                                    &m,
                                    p(),
                                    draining,
                                    snap.as_ref(),
                                ))
                            }
                        });
                        let _ = http1::Builder::new()
                            .timer(TokioTimer::new())
                            .header_read_timeout(Duration::from_secs(10))
                            .serve_connection(io, svc)
                            .await;
                    });
                }
            }
        }
    });

    let mut conn_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                info!("shutdown signal received; stopping new connections and draining in-flight requests (<=30s)");
                break;
            }
            Some(_) = conn_tasks.join_next(), if !conn_tasks.is_empty() => {}
            accepted = s3_listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(?e, "accept error on S3 listener");
                        continue;
                    }
                };
                let peer_ip = Some(peer_addr.ip());
                let _ = stream.set_nodelay(true);

                match Arc::clone(&conn_sem).try_acquire_owned() {
                    Ok(permit) => {
                        let st = Arc::clone(&state);
                        let mut conn_stop_rx = stop_rx.clone();
                        st.metrics.active_connections.fetch_add(1, Ordering::Relaxed);
                        conn_tasks.spawn(async move {
                            let _permit = permit;
                            let io = TokioIo::new(IdleTimeoutIo::new(stream, idle_timeout));
                            let st_svc = Arc::clone(&st);
                            let svc = service_fn(move |req: Request<Incoming>| {
                                let st_req = Arc::clone(&st_svc);
                                async move {
                                    Ok::<_, Infallible>(handle_s3_request(st_req, req, peer_ip).await)
                                }
                            });
                            let conn = http1::Builder::new()
                                .timer(TokioTimer::new())
                                .header_read_timeout(header_timeout)
                                .max_buf_size(512 * 1024)
                                .keep_alive(true)
                                .serve_connection(io, svc);
                            tokio::pin!(conn);
                            if *conn_stop_rx.borrow() {
                                conn.as_mut().graceful_shutdown();
                                let _ = conn.as_mut().await;
                            } else {
                                tokio::select! {
                                    res = conn.as_mut() => {
                                        let _ = res;
                                    }
                                    _ = conn_stop_rx.changed() => {
                                        conn.as_mut().graceful_shutdown();
                                        let _ = conn.as_mut().await;
                                    }
                                }
                            }
                            st.metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(_) => {
                        // Over `max_connections` -> return 503 SlowDown (`NFR-9`, `Appendix C`)
                        metrics.errors_5xx_total.fetch_add(1, Ordering::Relaxed);
                        conn_tasks.spawn(async move {
                            let io = TokioIo::new(IdleTimeoutIo::new(stream, header_timeout));
                            let svc = service_fn(|_req: Request<Incoming>| async move {
                                let err = S3Error::new(
                                    S3ErrorCode::SlowDown,
                                    "Please reduce your request rate.",
                                );
                                let xml = render_error_xml(&err, "0000000000000000", "s3d");
                                let resp = Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .header("Content-Type", "application/xml")
                                    .header("Connection", "close")
                                    .body(S3ResponseBody::<s3d_types::MemoryByteReader>::from_bytes(xml))
                                    .unwrap();
                                Ok::<_, Infallible>(resp)
                            });
                            let _ = http1::Builder::new()
                                .timer(TokioTimer::new())
                                .header_read_timeout(header_timeout)
                                .keep_alive(false)
                                .serve_connection(io, svc)
                                .await;
                        });
                    }
                }
            }
        }
    }

    // Drain in-flight S3 connections for up to 30 seconds (`NFR-14`)
    let drain_deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(drain_deadline);
    while !conn_tasks.is_empty() {
        tokio::select! {
            _ = &mut drain_deadline => {
                warn!(remaining = conn_tasks.len(), "graceful drain deadline (30s) reached; aborting remaining connections");
                conn_tasks.abort_all();
                break;
            }
            res = conn_tasks.join_next() => {
                if res.is_none() {
                    break;
                }
            }
        }
    }

    let _ = admin_kill_tx.send(true);
    let _ = admin_task.await;
    if is_poisoned() {
        error!("shutting down while engine was in ReadOnlyPoisoned state");
    } else {
        info!("s3d graceful shutdown complete");
    }
    Ok(())
}

fn handle_admin_request(
    req: Request<Incoming>,
    metrics: &ServerMetrics,
    read_only_poisoned: bool,
    draining: bool,
    engine_metrics: Option<&EngineMetricsSnapshot>,
) -> Response<Full<Bytes>> {
    match (req.method().as_str(), req.uri().path()) {
        ("GET", "/health") => {
            if read_only_poisoned {
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from_static(
                        b"{\"status\":\"read_only_failed\"}\n",
                    )))
                    .unwrap()
            } else if draining {
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from_static(
                        b"{\"status\":\"draining\"}\n",
                    )))
                    .unwrap()
            } else {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from_static(b"{\"status\":\"ok\"}\n")))
                    .unwrap()
            }
        }
        ("GET", "/metrics") => {
            let body = metrics.render_prometheus(read_only_poisoned, engine_metrics);
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found\n")))
            .unwrap(),
    }
}
