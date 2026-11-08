use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing_subscriber::EnvFilter;

use namae::config::LoadedConfig;

#[derive(Debug, Parser)]
#[command(name = "namae", version, about = "decentralized DNS service")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Daemon {
        #[arg(long, default_value = "/etc/namae.toml")]
        config: PathBuf,
        #[arg(long, default_value = "/etc/namae.d")]
        config_dir: PathBuf,
        #[arg(long, default_value = "/run/namae/ctl.sock")]
        ctl_path: PathBuf,
    },
    Ctl {
        #[arg(long, default_value = "/run/namae/ctl.sock")]
        socket: PathBuf,
        #[command(subcommand)]
        command: CtlCommand,
    },
    Check {
        #[arg(long, default_value = "/etc/namae.toml")]
        config: PathBuf,
        #[arg(long, default_value = "/etc/namae.d")]
        config_dir: PathBuf,
    },
    GenSecret,
}

#[derive(Debug, Subcommand)]
enum CtlCommand {
    Stats,
    Records {
        filter: Option<String>,
    },
    Peers,
    Conflicts,
    Resolve {
        name: String,
        #[arg(long = "type", default_value = "A")]
        rtype: String,
    },
    Reload,
    Sync,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info,namae=info,hickory_server=warn,hickory_proto=warn")
        }))
        .init();

    let args = Args::parse();
    let command = args.command.unwrap_or_else(default_daemon);
    match command {
        Command::Daemon {
            config,
            config_dir,
            ctl_path,
        } => namae::daemon::run(config, config_dir, ctl_path).await,
        Command::Check { config, config_dir } => {
            let loaded = LoadedConfig::load(&config, &config_dir)?;
            println!(
                "ok: zone={} records={} dns={:?} port={} node_id={:X}",
                loaded.zone,
                loaded.records.len(),
                loaded.dns_listen(),
                loaded.raw.port,
                loaded.node_id()
            );
            Ok(())
        }
        Command::GenSecret => {
            let secret: [u8; 32] = rand::random();
            println!("{}", hex(&secret));
            Ok(())
        }
        Command::Ctl { socket, command } => {
            let request = match command {
                CtlCommand::Stats => json!({"cmd": "stats"}),
                CtlCommand::Records { filter } => json!({"cmd": "records", "filter": filter}),
                CtlCommand::Peers => json!({"cmd": "peers"}),
                CtlCommand::Conflicts => json!({"cmd": "conflicts"}),
                CtlCommand::Resolve { name, rtype } => {
                    json!({"cmd": "resolve", "name": name, "rtype": rtype})
                }
                CtlCommand::Reload => json!({"cmd": "reload"}),
                CtlCommand::Sync => json!({"cmd": "sync"}),
            };
            let mut stream = namae::control::connect(&socket).await?;
            let mut encoded = serde_json::to_vec(&request)?;
            encoded.push(b'\n');
            stream.write_all(&encoded).await?;
            stream.flush().await?;
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            let value: serde_json::Value =
                serde_json::from_str(line.trim()).context("invalid control response")?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
    }
}

fn default_daemon() -> Command {
    Command::Daemon {
        config: PathBuf::from("/etc/namae.toml"),
        config_dir: PathBuf::from("/etc/namae.d"),
        ctl_path: PathBuf::from("/run/namae/ctl.sock"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
