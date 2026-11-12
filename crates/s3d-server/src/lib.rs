//! HTTP/1.1 S3 server, connection rate-limiter, admin `/health` & `/metrics` endpoints, and graceful shutdown.

pub mod body;
pub mod config;
pub mod metrics;
pub mod router;

use std::convert::Infallible;
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use s3d_disk::OsDisk;
use s3d_engine::{Engine, EngineConfig};
use s3d_proto::{render_error_xml, SigV4Verifier};
use s3d_types::{ObjectStore, S3Error, S3ErrorCode};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::body::S3ResponseBody;
use crate::config::{load_credentials_file, ServerConfig};
use crate::metrics::ServerMetrics;
use crate::router::{handle_s3_request, AppState};

/// Start `s3d` with `OsDisk` + `Engine<OsDisk>` until `shutdown` resolves (`NFR-14`).
pub async fn run_production_server(
    cfg: ServerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    cfg.validate()?;
    let accounts = load_credentials_file(&cfg.credentials_file)?;
    let ownership = cfg.parsed_object_ownership()?;

    let disk = OsDisk::new(&cfg.data_dir)
        .map_err(|e| format!("failed to initialize data_dir {}: {e}", cfg.data_dir.display()))?;

    let retention_ms = cfg.completed_upload_retention_ms()?;
    let engine_cfg = EngineConfig {
        region: cfg.region.clone(),
        segment_size: cfg.segment_size,
        wal_file_size: cfg.wal_file_size,
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

    let engine_health = Arc::clone(&engine);
    run_listeners_with_store(
        s3_listener,
        admin_listener,
        engine,
        auth,
        cfg,
        metrics,
        move || engine_health.is_read_only_poisoned(),
        shutdown,
    )
    .await
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
    let max_conns = cfg.max_connections;
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

    let mut admin_stop_rx = stop_rx.clone();
    let admin_metrics = Arc::clone(&metrics);
    let is_poisoned = Arc::new(is_poisoned_fn);
    let admin_is_poisoned = Arc::clone(&is_poisoned);
    let admin_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = admin_stop_rx.changed() => break,
                accepted = admin_listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue; };
                    let m = Arc::clone(&admin_metrics);
                    let p = Arc::clone(&admin_is_poisoned);
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let m = Arc::clone(&m);
                            let p = Arc::clone(&p);
                            async move { Ok::<_, Infallible>(handle_admin_request(req, &m, p())) }
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
                            let io = TokioIo::new(stream);
                            let st_svc = Arc::clone(&st);
                            let svc = service_fn(move |req: Request<Incoming>| {
                                let st_req = Arc::clone(&st_svc);
                                async move {
                                    Ok::<_, Infallible>(handle_s3_request(st_req, req, peer_ip).await)
                                }
                            });
                            let conn = http1::Builder::new()
                                .timer(TokioTimer::new())
                                .header_read_timeout(Duration::from_secs(30))
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
                        // Over `max_connections` -> return 503 SlowDown (`Appendix C`)
                        conn_tasks.spawn(async move {
                            let io = TokioIo::new(stream);
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

    admin_task.abort();
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
            } else {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from_static(b"{\"status\":\"ok\"}\n")))
                    .unwrap()
            }
        }
        ("GET", "/metrics") => {
            let body = metrics.render_prometheus(read_only_poisoned);
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
