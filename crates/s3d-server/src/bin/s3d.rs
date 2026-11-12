use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use s3d_disk::OsDisk;
use s3d_engine::{run_fsck, Engine, EngineConfig};
use s3d_server::config::ServerConfig;
use s3d_server::run_production_server;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "s3d", version, about = "Single-node crash-safe S3-compatible object storage")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the S3 HTTP and admin servers
    Serve(Box<ServeArgs>),
    /// Run offline full-dataset integrity check (`NFR-13`)
    Fsck {
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,
    },
    /// Trigger manual segment compaction (`NFR-14`)
    Compact {
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,
        #[arg(long, default_value_t = 0.5)]
        gc_live_ratio: f64,
    },
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    admin_listen: Option<String>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long)]
    credentials_file: Option<PathBuf>,
    #[arg(long)]
    base_domain: Option<String>,
    #[arg(long)]
    default_object_ownership: Option<String>,
    #[arg(long)]
    max_connections: Option<usize>,
    #[arg(long)]
    log_format: Option<String>,
}

fn init_tracing(log_format: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if log_format == "json" {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .compact()
            .init();
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => {
            let mut cfg = match &args.config {
                Some(path) => match ServerConfig::load_file(path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("error: {e}");
                        return ExitCode::from(1);
                    }
                },
                None => ServerConfig::default(),
            };

            if let Some(v) = args.listen {
                cfg.listen = v;
            }
            if let Some(v) = args.admin_listen {
                cfg.admin_listen = v;
            }
            if let Some(v) = args.data_dir {
                cfg.data_dir = v;
            }
            if let Some(v) = args.region {
                cfg.region = v;
            }
            if let Some(v) = args.credentials_file {
                cfg.credentials_file = v;
            }
            if let Some(v) = args.base_domain {
                cfg.base_domain = v;
            }
            if let Some(v) = args.default_object_ownership {
                cfg.default_object_ownership = v;
            }
            if let Some(v) = args.max_connections {
                cfg.max_connections = v;
            }
            if let Some(v) = args.log_format {
                cfg.log_format = v;
            }

            if let Err(e) = cfg.validate() {
                eprintln!("error: {e}");
                return ExitCode::from(1);
            }

            init_tracing(&cfg.log_format);

            if let Err(e) = run_production_server(cfg, wait_for_shutdown_signal()).await {
                eprintln!("error: {e}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Commands::Fsck { data_dir } => {
            let disk = match OsDisk::new(&data_dir) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: failed to open data_dir {}: {e}", data_dir.display());
                    return ExitCode::from(1);
                }
            };
            let report = run_fsck(disk);
            let json = serde_json::to_string_pretty(&report).unwrap();
            println!("{json}");
            if report.errors.is_empty() && report.status == "ok" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Commands::Compact {
            data_dir,
            gc_live_ratio,
        } => {
            init_tracing("compact");
            let disk = match OsDisk::new(&data_dir) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: failed to open data_dir {}: {e}", data_dir.display());
                    return ExitCode::from(1);
                }
            };
            let cfg = EngineConfig {
                gc_live_ratio,
                ..EngineConfig::default()
            };
            let engine = match Engine::open(disk, cfg) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("error: engine recovery failed: {e}");
                    return ExitCode::from(1);
                }
            };
            match engine.compact().await {
                Ok(reclaimed_segs) => {
                    println!(
                        "{{\"status\":\"ok\",\"compacted_segments\":{reclaimed_segs}}}"
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: compaction failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
    }
}
