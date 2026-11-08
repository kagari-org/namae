use std::{path::Path, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use hickory_proto::rr::{Name, RecordType};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{RwLock, mpsc},
};
use tracing::debug;

use crate::{
    config::normalize_name,
    gossip::GossipHandle,
    store::{NameEntry, ResolveOutcome, Store},
};

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    Stats,
    Records {
        filter: Option<String>,
    },
    Peers,
    Conflicts,
    Resolve {
        name: String,
        #[serde(default = "default_rtype")]
        rtype: String,
    },
    Reload,
    Sync,
    Ping,
}

fn default_rtype() -> String {
    "A".to_owned()
}

#[derive(Clone)]
pub struct ControlState {
    pub store: Arc<RwLock<Store>>,
    pub gossip: GossipHandle,
    pub reload_tx: mpsc::Sender<()>,
    pub started: Instant,
}

pub async fn serve(path: &Path, state: ControlState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await.ok();
    }
    let _ = fs::remove_file(path).await;
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding control socket {}", path.display()))?;
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accepting control client")?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_client(stream, state).await {
                debug!("control client disconnected: {error:?}");
            }
        });
    }
}

async fn handle_client(stream: UnixStream, state: ControlState) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle_request(request, &state).await,
            Err(error) => json!({"ok": false, "error": format!("invalid request: {error}")}),
        };
        let mut encoded = serde_json::to_vec(&response)?;
        encoded.push(b'\n');
        writer.write_all(&encoded).await?;
        writer.flush().await?;
    }
    Ok(())
}

async fn handle_request(request: Request, state: &ControlState) -> Value {
    match request {
        Request::Ping => json!({"ok": true, "pong": true}),
        Request::Stats => {
            let (local_seq, record_count) = {
                let store = state.store.read().await;
                (store.local_seq(), store.resolved_entries().len())
            };
            let peer_count = state.gossip.peer_infos().await.len();
            let stats = state.gossip.stats();
            json!({
                "ok": true,
                "node_id": state.gossip.local_id(),
                "zone": state.gossip.zone().to_string(),
                "local_seq": local_seq,
                "local_session": state.gossip.session(),
                "records": record_count,
                "peers": peer_count,
                "uptime_ms": state.started.elapsed().as_millis() as u64,
                "gossip": {
                    "frames_in": stats.frames_in.load(std::sync::atomic::Ordering::Relaxed),
                    "frames_out": stats.frames_out.load(std::sync::atomic::Ordering::Relaxed),
                    "snapshots_in": stats.snapshots_in.load(std::sync::atomic::Ordering::Relaxed),
                    "deltas_in": stats.deltas_in.load(std::sync::atomic::Ordering::Relaxed),
                    "heartbeats_in": stats.heartbeats_in.load(std::sync::atomic::Ordering::Relaxed),
                    "errors": stats.errors.load(std::sync::atomic::Ordering::Relaxed),
                }
            })
        }
        Request::Records { filter } => {
            let store = state.store.read().await;
            let mut records = store
                .resolved_entries()
                .into_iter()
                .filter(|(name, _)| {
                    filter
                        .as_ref()
                        .is_none_or(|filter| name.to_string().contains(filter))
                })
                .map(|(name, entry)| entry_json(&name, &entry))
                .collect::<Vec<_>>();
            records.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            json!({"ok": true, "records": records})
        }
        Request::Peers => {
            let peers = state
                .gossip
                .peer_infos()
                .await
                .into_iter()
                .map(|peer| {
                    json!({
                        "node_id": peer.node_id,
                        "addr": peer.addr.to_string(),
                        "conn_id": peer.conn_id,
                    })
                })
                .collect::<Vec<_>>();
            json!({"ok": true, "peers": peers})
        }
        Request::Conflicts => {
            let store = state.store.read().await;
            let conflicts = store
                .conflicts()
                .into_iter()
                .map(|conflict| {
                    json!({
                        "name": conflict.name.to_string(),
                        "candidates": conflict.candidates.iter().map(|entry| entry_json(&conflict.name, entry)).collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>();
            json!({"ok": true, "conflicts": conflicts})
        }
        Request::Resolve { name, rtype } => {
            let store = state.store.read().await;
            let zone = store.zone().clone();
            let name = match normalize_name(&name, &zone) {
                Ok(name) => name,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let rtype = match parse_type(&rtype) {
                Some(rtype) => rtype,
                None => return json!({"ok": false, "error": "unsupported record type"}),
            };
            match store.resolve_type(&name, rtype) {
                ResolveOutcome::Found(entry) => {
                    json!({"ok": true, "name": name.to_string(), "found": true, "entry": entry_json(&name, &entry)})
                }
                ResolveOutcome::NoData => {
                    json!({"ok": true, "name": name.to_string(), "found": false, "nodata": true})
                }
                ResolveOutcome::NxDomain => {
                    json!({"ok": true, "name": name.to_string(), "found": false, "nxdomain": true})
                }
            }
        }
        Request::Reload => match state.reload_tx.send(()).await {
            Ok(()) => json!({"ok": true}),
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        },
        Request::Sync => {
            state.gossip.sync().await;
            json!({"ok": true})
        }
    }
}

fn entry_json(name: &Name, entry: &NameEntry) -> Value {
    json!({
        "name": name.to_string(),
        "owner": entry.owner,
        "priority": entry.priority,
        "version": entry.version,
        "ttl": entry.ttl,
        "records": entry.records.iter().map(|record| {
            json!({
                "type": record.rtype.to_string(),
                "value": match &record.data {
                    crate::store::RecordData::A(ip) => ip.to_string(),
                    crate::store::RecordData::Aaaa(ip) => ip.to_string(),
                    crate::store::RecordData::Cname(name) => name.to_string(),
                    crate::store::RecordData::Txt(text) => text.clone(),
                }
            })
        }).collect::<Vec<_>>(),
    })
}

fn parse_type(input: &str) -> Option<RecordType> {
    match input.trim().to_ascii_uppercase().as_str() {
        "A" => Some(RecordType::A),
        "AAAA" => Some(RecordType::AAAA),
        "CNAME" => Some(RecordType::CNAME),
        "TXT" => Some(RecordType::TXT),
        "ANY" => Some(RecordType::ANY),
        _ => None,
    }
}

pub async fn connect(path: &Path) -> Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to {}", path.display()))
}
