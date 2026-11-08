use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use hickory_proto::rr::{Name, RecordType};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock, broadcast, mpsc, watch},
    task::JoinHandle,
    time::{interval, timeout},
};
use tracing::{debug, error, info, warn};

use crate::{
    config::{LoadedConfig, normalize_name},
    netlink::Peer,
    store::{ApplyResult, LocalDiff, NameEntry, NodeId, RecordData, RrData, Store},
    wire::{Frame, FrameKind, MAX_FRAME, SecureStream, client_handshake, server_handshake},
};

const HOP_LIMIT: u8 = 6;
const FANOUT: usize = 4;
const SNAPSHOT_CHUNK: usize = 128;
const MAX_SNAPSHOT_CHUNKS: u32 = 1024;

#[derive(Default)]
pub struct GossipStats {
    pub frames_in: AtomicU64,
    pub frames_out: AtomicU64,
    pub peer_count: AtomicU64,
    pub snapshots_in: AtomicU64,
    pub deltas_in: AtomicU64,
    pub heartbeats_in: AtomicU64,
    pub errors: AtomicU64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WireRecord {
    rtype: String,
    value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WireEntry {
    name: String,
    priority: u16,
    version: u64,
    ttl: u32,
    records: Vec<WireRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WireTombstone {
    name: String,
    version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SnapshotMessage {
    origin: NodeId,
    session: u64,
    seq: u64,
    chunk: u32,
    total: u32,
    entries: Vec<WireEntry>,
    tombstones: Vec<WireTombstone>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeltaMessage {
    origin: NodeId,
    session: u64,
    seq: u64,
    upserts: Vec<WireEntry>,
    deletes: Vec<WireTombstone>,
    hops: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HeartbeatMessage {
    origin: NodeId,
    session: u64,
    seq: u64,
    digest: [u8; 16],
    hops: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WireDigest {
    origin: NodeId,
    session: u64,
    seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DigestMessage {
    entries: Vec<WireDigest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SyncRequestMessage {
    origins: Vec<NodeId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PingMessage {
    nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PongMessage {
    nonce: u64,
}

pub struct PeerInfo {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub conn_id: u64,
}

struct PeerSender {
    conn_id: u64,
    addr: SocketAddr,
    preferred: bool,
    tx: mpsc::Sender<Frame>,
    shutdown: watch::Sender<bool>,
}

struct SnapshotAssembly {
    total: u32,
    chunks: Vec<Option<SnapshotMessage>>,
}

struct Shared {
    store: Arc<RwLock<Store>>,
    zone: Name,
    local_id: NodeId,
    session: u64,
    secret: ArcSwap<Vec<u8>>,
    port: u16,
    announce_interval: Duration,
    origin_timeout: Duration,
    tombstone_ttl: Duration,
    peers: RwLock<HashMap<NodeId, PeerSender>>,
    change_tx: broadcast::Sender<()>,
    stats: Arc<GossipStats>,
    snapshots: Mutex<HashMap<(NodeId, u64, u64), SnapshotAssembly>>,
}

#[derive(Debug)]
enum PeerCommand {
    Add(SocketAddr),
    Remove(SocketAddr),
    ReconnectAll,
}

#[derive(Debug)]
enum ConnectEvent {
    Connected(SocketAddr),
    Disconnected(SocketAddr),
}

#[derive(Clone)]
pub struct GossipHandle {
    shared: Arc<Shared>,
    command_tx: mpsc::Sender<PeerCommand>,
}

impl GossipHandle {
    pub fn add_peer(&self, peer: Peer) {
        let _ = self.command_tx.try_send(PeerCommand::Add(peer.addr));
    }

    pub fn remove_peer(&self, peer: Peer) {
        let _ = self.command_tx.try_send(PeerCommand::Remove(peer.addr));
    }

    pub async fn publish(&self, diff: LocalDiff) -> Result<()> {
        if diff.is_empty() {
            return Ok(());
        }
        let seq = self.shared.store.read().await.local_seq();
        let message = DeltaMessage {
            origin: self.shared.local_id,
            session: self.shared.session,
            seq,
            upserts: diff
                .upserts
                .iter()
                .map(|(name, entry)| wire_entry(name, entry, &self.shared.zone))
                .collect(),
            deletes: diff
                .deletes
                .iter()
                .map(|(name, version)| WireTombstone {
                    name: name.to_string(),
                    version: *version,
                })
                .collect(),
            hops: HOP_LIMIT,
        };
        self.shared
            .broadcast(encode(FrameKind::Delta, &message)?, None)
            .await;
        Ok(())
    }

    pub async fn set_secret(&self, secret: Vec<u8>) {
        self.shared.secret.store(Arc::new(secret));
        {
            let peers = self.shared.peers.write().await;
            for peer in peers.values() {
                let _ = peer.shutdown.send(true);
            }
        }
        self.shared.peers.write().await.clear();
        self.shared.stats.peer_count.store(0, Ordering::Relaxed);
        let _ = self.command_tx.try_send(PeerCommand::ReconnectAll);
    }

    pub async fn sync(&self) {
        let shared = self.shared.clone();
        if let Ok(digest) = shared.digest_message().await {
            shared
                .broadcast(encode(FrameKind::Digest, &digest).unwrap_or_default(), None)
                .await;
        }
    }

    pub fn stats(&self) -> Arc<GossipStats> {
        self.shared.stats.clone()
    }

    pub fn local_id(&self) -> NodeId {
        self.shared.local_id
    }

    pub fn session(&self) -> u64 {
        self.shared.session
    }

    pub fn zone(&self) -> &Name {
        &self.shared.zone
    }

    pub async fn peer_infos(&self) -> Vec<PeerInfo> {
        self.shared
            .peers
            .read()
            .await
            .iter()
            .map(|(node_id, peer)| PeerInfo {
                node_id: *node_id,
                addr: peer.addr,
                conn_id: peer.conn_id,
            })
            .collect()
    }

    pub async fn peer_count(&self) -> u64 {
        self.shared.stats.peer_count.load(Ordering::Relaxed)
    }
}

pub async fn start(
    store: Arc<RwLock<Store>>,
    config: Arc<LoadedConfig>,
    initial_peers: Vec<Peer>,
) -> Result<GossipHandle> {
    let (change_tx, _) = broadcast::channel(64);
    let shared = Arc::new(Shared {
        zone: config.zone.clone(),
        local_id: config.node_id(),
        session: rand::random(),
        secret: ArcSwap::from_pointee(config.secret.clone()),
        port: config.raw.port,
        announce_interval: config.raw.announce_interval,
        origin_timeout: config.raw.origin_timeout,
        tombstone_ttl: config.raw.tombstone_ttl,
        store,
        peers: RwLock::new(HashMap::new()),
        change_tx,
        stats: Arc::new(GossipStats::default()),
        snapshots: Mutex::new(HashMap::new()),
    });
    let mut listeners = Vec::new();

    match TcpListener::bind(("0.0.0.0", shared.port)).await {
        Ok(listener) => listeners.push(listener),
        Err(error) => bail!("binding gossip port {}: {error}", shared.port),
    }
    match bind_v6(shared.port) {
        Ok(listener) => listeners.push(listener),
        Err(error) => warn!(
            "IPv6 gossip listener unavailable on port {}: {error}",
            shared.port
        ),
    }
    for listener in listeners {
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(error) = accept_loop(shared, listener).await {
                error!("gossip accept loop failed: {error:?}");
            }
        });
    }

    let (command_tx, command_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(256);
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            connector(shared, command_rx, event_rx, event_tx).await;
        });
    }

    {
        let shared = shared.clone();
        tokio::spawn(async move {
            heartbeat_loop(shared).await;
        });
    }
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            anti_entropy_loop(shared).await;
        });
    }
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            gc_loop(shared).await;
        });
    }

    let handle = GossipHandle {
        shared: shared.clone(),
        command_tx,
    };
    for peer in initial_peers {
        handle.add_peer(peer);
    }
    Ok(handle)
}

pub fn subscribe_changes(handle: &GossipHandle) -> broadcast::Receiver<()> {
    handle.shared.change_tx.subscribe()
}

fn bind_v6(port: u16) -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(TcpListener::from_std(socket.into())?)
}

async fn accept_loop(shared: Arc<Shared>, listener: TcpListener) -> Result<()> {
    loop {
        let (stream, addr) = listener.accept().await.context("accepting peer")?;
        let _ = stream.set_nodelay(true);
        let shared = shared.clone();
        tokio::spawn(async move {
            let secret = shared.secret.load_full();
            let result = timeout(
                Duration::from_secs(5),
                server_handshake(stream, &secret, shared.local_id),
            )
            .await;
            match result {
                Ok(Ok((stream, peer))) => {
                    if let Err(error) = run_peer(shared, stream, peer.node_id, addr, false).await {
                        debug!("peer {addr} disconnected: {error:?}");
                    }
                }
                Ok(Err(error)) => {
                    shared.stats.errors.fetch_add(1, Ordering::Relaxed);
                    warn!("handshake with {addr} failed: {error:?}");
                }
                Err(_) => {
                    shared.stats.errors.fetch_add(1, Ordering::Relaxed);
                    warn!("handshake with {addr} timed out");
                }
            }
        });
    }
}

async fn connector(
    shared: Arc<Shared>,
    mut commands: mpsc::Receiver<PeerCommand>,
    mut events: mpsc::Receiver<ConnectEvent>,
    event_tx: mpsc::Sender<ConnectEvent>,
) {
    let mut desired: HashMap<SocketAddr, ()> = HashMap::new();
    let mut connecting: HashMap<SocketAddr, JoinHandle<()>> = HashMap::new();
    let mut connected: HashMap<SocketAddr, ()> = HashMap::new();
    let mut ticker = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            Some(command) = commands.recv() => {
                match command {
                    PeerCommand::Add(addr) => {
                        desired.insert(addr, ());
                    }
                    PeerCommand::ReconnectAll => {
                        for (_, task) in connecting.drain() {
                            task.abort();
                        }
                        connected.clear();
                    }
                    PeerCommand::Remove(addr) => {
                        desired.remove(&addr);
                        if let Some(task) = connecting.remove(&addr) {
                            task.abort();
                        }
                        connected.remove(&addr);
                        let mut peers = shared.peers.write().await;
                        let node = peers
                            .iter()
                            .find(|(_, peer)| peer.addr == addr)
                            .map(|(node, _)| *node);
                        if let Some(node) = node
                            && let Some(peer) = peers.remove(&node)
                        {
                            let _ = peer.shutdown.send(true);
                        }
                    }
                }
            }
            Some(event) = events.recv() => {
                match event {
                    ConnectEvent::Connected(addr) => {
                        connecting.remove(&addr);
                        connected.insert(addr, ());
                    }
                    ConnectEvent::Disconnected(addr) => {
                        connecting.remove(&addr);
                        connected.remove(&addr);
                    }
                }
            }
            _ = ticker.tick() => {
                for addr in desired.keys().copied() {
                    if connected.contains_key(&addr)
                        || connecting.contains_key(&addr)
                        || shared.has_peer_addr(addr).await
                    {
                        continue;
                    }
                    let shared = shared.clone();
                    let events = event_tx.clone();
                    let task = tokio::spawn(async move {
                        if let Err(error) = connect_peer(shared, addr, events.clone()).await {
                            debug!("connect {addr} failed: {error:?}");
                        }
                        let _ = events.send(ConnectEvent::Disconnected(addr)).await;
                    });
                    connecting.insert(addr, task);
                }
            }
        }
    }
}

async fn connect_peer(
    shared: Arc<Shared>,
    addr: SocketAddr,
    events: mpsc::Sender<ConnectEvent>,
) -> Result<()> {
    let stream = timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .context("connect timeout")?
        .context("connect")?;
    let _ = stream.set_nodelay(true);
    let secret = shared.secret.load_full();
    let (stream, peer) = timeout(
        Duration::from_secs(5),
        client_handshake(stream, &secret, shared.local_id),
    )
    .await
    .context("handshake timeout")??;
    let _ = events.send(ConnectEvent::Connected(addr)).await;
    run_peer(shared, stream, peer.node_id, addr, true).await
}

async fn run_peer(
    shared: Arc<Shared>,
    stream: SecureStream<TcpStream>,
    peer_id: NodeId,
    addr: SocketAddr,
    initiator: bool,
) -> Result<()> {
    if peer_id == shared.local_id {
        return Ok(());
    }
    let preferred = initiator == (shared.local_id < peer_id);
    let conn_id = rand::random::<u64>();
    let (tx, mut rx) = mpsc::channel::<Frame>(256);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    {
        let mut peers = shared.peers.write().await;
        if let Some(existing) = peers.get(&peer_id) {
            if preferred && !existing.preferred {
                let _ = existing.shutdown.send(true);
                peers.remove(&peer_id);
            } else {
                debug!("duplicate connection for node {peer_id:X}; closing {addr}");
                return Ok(());
            }
        }
        peers.insert(
            peer_id,
            PeerSender {
                conn_id,
                addr,
                preferred,
                tx: tx.clone(),
                shutdown: shutdown_tx,
            },
        );
    }
    shared
        .stats
        .peer_count
        .store(shared.peers.read().await.len() as u64, Ordering::Relaxed);
    info!("peer {peer_id:X} connected at {addr}");

    let (reader, mut writer) = stream.split();
    let mut writer_shutdown = shutdown_rx.clone();
    let writer_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(frame) = rx.recv() => {
                    if let Err(error) = writer.send(frame.kind, &frame.body).await {
                        debug!("writer for {peer_id:X} stopped: {error:?}");
                        break;
                    }
                }
                _ = writer_shutdown.changed() => break,
            }
        }
    });

    let _ = send_own_snapshot(&shared, &tx).await;
    if let Ok(digest) = shared.digest_message().await {
        let _ = send_message(&tx, FrameKind::Digest, &digest).await;
    }

    let mut reader = reader;
    let result = loop {
        tokio::select! {
            frame = reader.recv() => {
                match frame {
                    Ok(frame) => {
                        shared.stats.frames_in.fetch_add(1, Ordering::Relaxed);
                        if let Err(error) = handle_frame(&shared, peer_id, frame, &tx).await {
                            shared.stats.errors.fetch_add(1, Ordering::Relaxed);
                            debug!("frame from {peer_id:X} failed: {error:?}");
                        }
                    }
                    Err(error) => break Err(error.into()),
                }
            }
            _ = shutdown_rx.changed() => break Ok(()),
        }
    };

    writer_task.abort();
    let mut peers = shared.peers.write().await;
    if peers
        .get(&peer_id)
        .is_some_and(|peer| peer.conn_id == conn_id)
    {
        peers.remove(&peer_id);
    }
    shared
        .stats
        .peer_count
        .store(peers.len() as u64, Ordering::Relaxed);
    info!("peer {peer_id:X} disconnected");
    result
}

impl Shared {
    async fn broadcast(&self, encoded: Vec<u8>, exclude: Option<NodeId>) {
        if encoded.is_empty() {
            return;
        }
        let peers = self.peers.read().await;
        let mut targets = peers
            .iter()
            .filter(|(id, _)| Some(**id) != exclude)
            .map(|(_, peer)| peer.tx.clone())
            .collect::<Vec<_>>();
        drop(peers);
        if targets.len() > FANOUT {
            use rand::seq::SliceRandom;
            targets.shuffle(&mut rand::rng());
            targets.truncate(FANOUT);
        }
        for tx in targets {
            let frame = Frame {
                kind: encoded[0].into(),
                seq: 0,
                body: encoded[1..].to_vec(),
            };
            if tx.try_send(frame).is_ok() {
                self.stats.frames_out.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn has_peer_addr(&self, addr: SocketAddr) -> bool {
        self.peers
            .read()
            .await
            .values()
            .any(|peer| peer.addr == addr)
    }

    async fn digest_message(&self) -> Result<DigestMessage> {
        let store = self.store.read().await;
        let mut entries = store
            .origin_digests()
            .into_iter()
            .map(|digest| WireDigest {
                origin: digest.origin,
                session: digest.session,
                seq: digest.seq,
            })
            .collect::<Vec<_>>();
        entries.push(WireDigest {
            origin: self.local_id,
            session: self.session,
            seq: store.local_seq(),
        });
        entries.sort_by_key(|entry| entry.origin);
        Ok(DigestMessage { entries })
    }
}

fn encode<T: Serialize>(kind: FrameKind, value: &T) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_FRAME {
        bail!("encoded frame too large: {}", body.len());
    }
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(kind as u8);
    out.extend_from_slice(&body);
    Ok(out)
}

impl From<u8> for FrameKind {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Snapshot,
            2 => Self::Delta,
            3 => Self::Heartbeat,
            4 => Self::Digest,
            5 => Self::SyncRequest,
            6 => Self::Ping,
            _ => Self::Pong,
        }
    }
}

async fn send_message<T: Serialize>(
    tx: &mpsc::Sender<Frame>,
    kind: FrameKind,
    value: &T,
) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_FRAME {
        bail!("frame too large");
    }
    tx.send(Frame { kind, seq: 0, body })
        .await
        .context("peer channel closed")?;
    Ok(())
}

async fn send_own_snapshot(shared: &Shared, tx: &mpsc::Sender<Frame>) -> Result<()> {
    let store = shared.store.read().await;
    let entries = store
        .local_published()
        .into_iter()
        .map(|(name, entry)| wire_entry(&name, &entry, &shared.zone))
        .collect::<Vec<_>>();
    let seq = store.local_seq();
    drop(store);
    send_snapshot_chunks(
        tx,
        shared.local_id,
        shared.session,
        seq,
        entries,
        Vec::new(),
    )
    .await
}

async fn send_snapshot_for(
    shared: &Shared,
    origin: NodeId,
    tx: &mpsc::Sender<Frame>,
) -> Result<()> {
    if origin == shared.local_id {
        return send_own_snapshot(shared, tx).await;
    }
    let store = shared.store.read().await;
    let Some((session, seq, entries, tombstones)) = store.snapshot_for(origin) else {
        bail!("unknown origin {origin:X}");
    };
    let entries = entries
        .into_iter()
        .map(|(name, entry)| wire_entry(&name, &entry, &shared.zone))
        .collect::<Vec<_>>();
    let tombstones = tombstones
        .into_iter()
        .map(|(name, version)| WireTombstone {
            name: name.to_string(),
            version,
        })
        .collect::<Vec<_>>();
    drop(store);
    send_snapshot_chunks(tx, origin, session, seq, entries, tombstones).await
}

async fn send_snapshot_chunks(
    tx: &mpsc::Sender<Frame>,
    origin: NodeId,
    session: u64,
    seq: u64,
    entries: Vec<WireEntry>,
    tombstones: Vec<WireTombstone>,
) -> Result<()> {
    let total = entries.len().div_ceil(SNAPSHOT_CHUNK).max(1) as u32;
    if total > MAX_SNAPSHOT_CHUNKS {
        bail!("snapshot too large: {total} chunks");
    }
    for chunk in 0..total {
        let start = chunk as usize * SNAPSHOT_CHUNK;
        let end = (start + SNAPSHOT_CHUNK).min(entries.len());
        let message = SnapshotMessage {
            origin,
            session,
            seq,
            chunk,
            total,
            entries: entries[start..end].to_vec(),
            tombstones: if chunk + 1 == total {
                tombstones.clone()
            } else {
                Vec::new()
            },
        };
        send_message(tx, FrameKind::Snapshot, &message).await?;
    }
    Ok(())
}

async fn handle_frame(
    shared: &Shared,
    peer_id: NodeId,
    frame: Frame,
    tx: &mpsc::Sender<Frame>,
) -> Result<()> {
    match frame.kind {
        FrameKind::Snapshot => {
            let message: SnapshotMessage = serde_json::from_slice(&frame.body)?;
            handle_snapshot(shared, peer_id, message).await?;
        }
        FrameKind::Delta => {
            let message: DeltaMessage = serde_json::from_slice(&frame.body)?;
            handle_delta(shared, peer_id, message).await?;
        }
        FrameKind::Heartbeat => {
            let message: HeartbeatMessage = serde_json::from_slice(&frame.body)?;
            handle_heartbeat(shared, peer_id, message).await?;
        }
        FrameKind::Digest => {
            let message: DigestMessage = serde_json::from_slice(&frame.body)?;
            handle_digest(shared, message, tx, peer_id).await?;
        }
        FrameKind::SyncRequest => {
            let message: SyncRequestMessage = serde_json::from_slice(&frame.body)?;
            for origin in message.origins {
                if let Err(error) = send_snapshot_for(shared, origin, tx).await {
                    debug!("sending snapshot for {origin:X} failed: {error:?}");
                }
            }
        }
        FrameKind::Ping => {
            let message: PingMessage = serde_json::from_slice(&frame.body)?;
            send_message(
                tx,
                FrameKind::Pong,
                &PongMessage {
                    nonce: message.nonce,
                },
            )
            .await?;
        }
        FrameKind::Pong => {
            let _: PongMessage = serde_json::from_slice(&frame.body)?;
        }
    }
    Ok(())
}

async fn handle_snapshot(shared: &Shared, peer_id: NodeId, message: SnapshotMessage) -> Result<()> {
    if message.origin == shared.local_id {
        return Ok(());
    }
    if message.total == 0 || message.chunk >= message.total || message.total > MAX_SNAPSHOT_CHUNKS {
        bail!("invalid snapshot chunk");
    }
    let origin = message.origin;
    let session = message.session;
    let seq = message.seq;
    if message.total > 1 {
        let mut snapshots = shared.snapshots.lock().await;
        let key = (origin, session, seq);
        let assembly = snapshots.entry(key).or_insert_with(|| SnapshotAssembly {
            total: message.total,
            chunks: vec![None; message.total as usize],
        });
        if assembly.total != message.total {
            *assembly = SnapshotAssembly {
                total: message.total,
                chunks: vec![None; message.total as usize],
            };
        }
        let chunk_index = message.chunk as usize;
        assembly.chunks[chunk_index] = Some(message);
        if assembly.chunks.iter().any(Option::is_none) {
            return Ok(());
        }
        let assembly = snapshots.remove(&key).unwrap();
        let mut entries = Vec::new();
        let mut tombstones = Vec::new();
        for chunk in assembly.chunks.into_iter().flatten() {
            entries.extend(chunk.entries);
            tombstones.extend(chunk.tombstones);
        }
        drop(snapshots);
        let forward_entries = entries.clone();
        let forward_tombstones = tombstones.clone();
        if apply_snapshot(shared, origin, session, seq, entries, tombstones).await? {
            broadcast_snapshot(
                shared,
                peer_id,
                origin,
                session,
                seq,
                forward_entries,
                forward_tombstones,
            )
            .await;
        }
    } else {
        let forward_entries = message.entries.clone();
        let forward_tombstones = message.tombstones.clone();
        if apply_snapshot(
            shared,
            origin,
            session,
            seq,
            message.entries,
            message.tombstones,
        )
        .await?
        {
            broadcast_snapshot(
                shared,
                peer_id,
                origin,
                session,
                seq,
                forward_entries,
                forward_tombstones,
            )
            .await;
        }
    }
    Ok(())
}

async fn broadcast_snapshot(
    shared: &Shared,
    peer_id: NodeId,
    origin: NodeId,
    session: u64,
    seq: u64,
    entries: Vec<WireEntry>,
    tombstones: Vec<WireTombstone>,
) {
    let message = SnapshotMessage {
        origin,
        session,
        seq,
        chunk: 0,
        total: 1,
        entries,
        tombstones,
    };
    if let Ok(encoded) = encode(FrameKind::Snapshot, &message) {
        shared.broadcast(encoded, Some(peer_id)).await;
    }
}

async fn apply_snapshot(
    shared: &Shared,
    origin: NodeId,
    session: u64,
    seq: u64,
    entries: Vec<WireEntry>,
    tombstones: Vec<WireTombstone>,
) -> Result<bool> {
    let entries = entries
        .iter()
        .filter_map(|entry| entry_from_wire(&shared.zone, origin, entry))
        .collect::<Vec<_>>();
    let tombstones = tombstones
        .iter()
        .filter_map(|tombstone| {
            normalize_name(&tombstone.name, &shared.zone)
                .ok()
                .map(|name| (name, tombstone.version))
        })
        .collect::<Vec<_>>();
    let result = shared
        .store
        .write()
        .await
        .apply_snapshot(origin, session, seq, entries, tombstones);
    shared.stats.snapshots_in.fetch_add(1, Ordering::Relaxed);
    let changed = matches!(result, ApplyResult::Applied { changed: true });
    if changed {
        notify(shared);
    }
    Ok(changed)
}

async fn handle_delta(shared: &Shared, peer_id: NodeId, message: DeltaMessage) -> Result<()> {
    if message.origin == shared.local_id {
        return Ok(());
    }
    let upserts = message
        .upserts
        .iter()
        .filter_map(|entry| entry_from_wire(&shared.zone, message.origin, entry))
        .collect::<Vec<_>>();
    let deletes = message
        .deletes
        .iter()
        .filter_map(|tombstone| {
            normalize_name(&tombstone.name, &shared.zone)
                .ok()
                .map(|name| (name, tombstone.version))
        })
        .collect::<Vec<_>>();
    let result = shared.store.write().await.apply_delta(
        message.origin,
        message.session,
        message.seq,
        upserts,
        deletes,
    );
    shared.stats.deltas_in.fetch_add(1, Ordering::Relaxed);
    match result {
        ApplyResult::Applied { changed } => {
            if changed {
                notify(shared);
                if message.hops > 0 {
                    let forwarded = DeltaMessage {
                        hops: message.hops - 1,
                        ..message
                    };
                    if let Ok(encoded) = encode(FrameKind::Delta, &forwarded) {
                        shared.broadcast(encoded, Some(peer_id)).await;
                    }
                }
            }
        }
        ApplyResult::Gap => {
            let request = SyncRequestMessage {
                origins: vec![message.origin],
            };
            let peers = shared.peers.read().await;
            if let Some(peer) = peers.get(&peer_id) {
                let _ = send_message(&peer.tx, FrameKind::SyncRequest, &request).await;
            }
        }
        ApplyResult::Stale => {}
    }
    Ok(())
}

async fn handle_heartbeat(
    shared: &Shared,
    peer_id: NodeId,
    message: HeartbeatMessage,
) -> Result<()> {
    if message.origin == shared.local_id {
        return Ok(());
    }
    let outcome = shared.store.write().await.heartbeat(
        message.origin,
        message.session,
        message.seq,
        message.digest,
    );
    shared.stats.heartbeats_in.fetch_add(1, Ordering::Relaxed);
    if outcome.needs_sync {
        let request = SyncRequestMessage {
            origins: vec![message.origin],
        };
        let peers = shared.peers.read().await;
        if let Some(peer) = peers.get(&peer_id) {
            let _ = send_message(&peer.tx, FrameKind::SyncRequest, &request).await;
        }
    }
    if outcome.updated && message.hops > 0 {
        let forwarded = HeartbeatMessage {
            hops: message.hops - 1,
            ..message
        };
        if let Ok(encoded) = encode(FrameKind::Heartbeat, &forwarded) {
            shared.broadcast(encoded, Some(peer_id)).await;
        }
    }
    Ok(())
}

async fn handle_digest(
    shared: &Shared,
    message: DigestMessage,
    tx: &mpsc::Sender<Frame>,
    peer_id: NodeId,
) -> Result<()> {
    let (local, local_seq) = {
        let store = shared.store.read().await;
        (store.origin_digests(), store.local_seq())
    };
    let mut request = Vec::new();
    for entry in message.entries {
        if entry.origin == shared.local_id {
            if entry.session != shared.session || entry.seq < local_seq {
                let _ = send_snapshot_for(shared, shared.local_id, tx).await;
            }
            continue;
        }
        match local.iter().find(|digest| digest.origin == entry.origin) {
            None => request.push(entry.origin),
            Some(digest) if digest.session != entry.session || digest.seq < entry.seq => {
                request.push(entry.origin)
            }
            Some(digest) if digest.session == entry.session && digest.seq > entry.seq => {
                let _ = send_snapshot_for(shared, entry.origin, tx).await;
            }
            _ => {}
        }
    }
    if !request.is_empty() {
        send_message(
            tx,
            FrameKind::SyncRequest,
            &SyncRequestMessage { origins: request },
        )
        .await?;
    }
    let _ = peer_id;
    Ok(())
}

async fn anti_entropy_loop(shared: Arc<Shared>) {
    let mut ticker = interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let peer = {
            let peers = shared.peers.read().await;
            if peers.is_empty() {
                continue;
            }
            let index = rand::random_range(0..peers.len());
            peers.values().nth(index).map(|peer| peer.tx.clone())
        };
        let Some(peer) = peer else { continue };
        if let Ok(digest) = shared.digest_message().await {
            let _ = send_message(&peer, FrameKind::Digest, &digest).await;
        }
    }
}

async fn heartbeat_loop(shared: Arc<Shared>) {
    let mut ticker = interval(shared.announce_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let (seq, digest) = {
            let mut store = shared.store.write().await;
            let seq = store.bump_local_seq();
            (seq, store.local_digest())
        };
        let message = HeartbeatMessage {
            origin: shared.local_id,
            session: shared.session,
            seq,
            digest,
            hops: HOP_LIMIT,
        };
        if let Ok(encoded) = encode(FrameKind::Heartbeat, &message) {
            shared.broadcast(encoded, None).await;
        }
    }
}

async fn gc_loop(shared: Arc<Shared>) {
    let mut ticker = interval(Duration::from_secs(10));
    loop {
        ticker.tick().await;
        let changed = shared
            .store
            .write()
            .await
            .expire(shared.origin_timeout, shared.tombstone_ttl);
        if changed {
            notify(&shared);
        }
    }
}

fn notify(shared: &Shared) {
    let _ = shared.change_tx.send(());
}

fn wire_entry(name: &Name, entry: &NameEntry, _zone: &Name) -> WireEntry {
    WireEntry {
        name: name.to_string(),
        priority: entry.priority,
        version: entry.version,
        ttl: entry.ttl,
        records: entry
            .records
            .iter()
            .map(|record| WireRecord {
                rtype: record_type_name(record.rtype).to_owned(),
                value: match &record.data {
                    RecordData::A(ip) => ip.to_string(),
                    RecordData::Aaaa(ip) => ip.to_string(),
                    RecordData::Cname(name) => name.to_string(),
                    RecordData::Txt(text) => text.clone(),
                },
            })
            .collect(),
    }
}

fn entry_from_wire(zone: &Name, owner: NodeId, entry: &WireEntry) -> Option<(Name, NameEntry)> {
    let name = normalize_name(&entry.name, zone).ok()?;
    let mut records = Vec::new();
    for record in &entry.records {
        let rtype = match record.rtype.to_ascii_uppercase().as_str() {
            "A" => RecordType::A,
            "AAAA" => RecordType::AAAA,
            "CNAME" => RecordType::CNAME,
            "TXT" => RecordType::TXT,
            _ => continue,
        };
        let data = match rtype {
            RecordType::A => RecordData::A(record.value.parse().ok()?),
            RecordType::AAAA => RecordData::Aaaa(record.value.parse().ok()?),
            RecordType::CNAME => {
                RecordData::Cname(Name::from_str(&record.value).ok()?.to_lowercase())
            }
            RecordType::TXT => RecordData::Txt(record.value.clone()),
            _ => continue,
        };
        records.push(RrData { rtype, data });
    }
    Some((
        name,
        NameEntry {
            owner,
            priority: entry.priority,
            version: entry.version,
            ttl: entry.ttl.clamp(5, 3600),
            records,
        },
    ))
}

fn record_type_name(rtype: RecordType) -> &'static str {
    match rtype {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::TXT => "TXT",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{RecordTarget, ResolvedRecord};

    fn entry(owner: NodeId, version: u64, ip: &str) -> NameEntry {
        NameEntry {
            owner,
            priority: 100,
            version,
            ttl: 60,
            records: vec![RrData {
                rtype: RecordType::A,
                data: RecordData::A(ip.parse().unwrap()),
            }],
        }
    }

    #[test]
    fn wire_roundtrip() {
        let zone = Name::from_str("namae.").unwrap();
        let name = Name::from_str("a.namae.").unwrap();
        let entry = entry(7, 3, "10.0.0.1");
        let wire = wire_entry(&name, &entry, &zone);
        let (decoded_name, decoded) = entry_from_wire(&zone, 7, &wire).unwrap();
        assert_eq!(decoded_name, name);
        assert_eq!(decoded, entry);
    }

    #[tokio::test]
    async fn local_records_publish() {
        let zone = Name::from_str("namae.").unwrap();
        let mut store = Store::new(zone, 1, 1);
        let name = Name::from_str("a.namae.").unwrap();
        let diff = store
            .set_local_records(
                &[ResolvedRecord {
                    name,
                    rtype: RecordType::A,
                    target: RecordTarget::Value(RecordData::A("10.0.0.1".parse().unwrap())),
                    ttl: Some(60),
                    priority: 100,
                    publish: true,
                }],
                &HashMap::new(),
                60,
            )
            .unwrap();
        assert_eq!(diff.upserts.len(), 1);
        assert_eq!(store.local_seq(), 1);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::{
        config::LoadedConfig,
        netlink::Peer,
        store::{RecordTarget, ResolvedRecord},
    };
    use std::{fs, net::TcpListener, path::Path, sync::Arc, time::Instant};

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn config(dir: &Path, port: u16) -> Arc<LoadedConfig> {
        let path = dir.join(format!("namae-{port}.toml"));
        fs::write(
            &path,
            format!("zone = \"namae.\"\nsecret = \"test-secret\"\nport = {port}\n"),
        )
        .unwrap();
        Arc::new(LoadedConfig::load(&path, &dir.join("does-not-exist")).unwrap())
    }

    fn peer(port: u16) -> Peer {
        Peer {
            addr: format!("127.0.0.1:{port}").parse().unwrap(),
            ifindex: 0,
            ifname: None,
        }
    }

    #[tokio::test]
    async fn two_nodes_share_records() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let port1 = free_port();
        let mut port2 = free_port();
        while port2 == port1 {
            port2 = free_port();
        }
        let config1 = config(dir1.path(), port1);
        let config2 = config(dir2.path(), port2);

        let name = Name::from_str("a.namae.").unwrap();
        let store1 = Arc::new(RwLock::new(Store::new(
            config1.zone.clone(),
            config1.node_id(),
            rand::random(),
        )));
        store1
            .write()
            .await
            .set_local_records(
                &[ResolvedRecord {
                    name: name.clone(),
                    rtype: RecordType::A,
                    target: RecordTarget::Value(RecordData::A("10.0.0.1".parse().unwrap())),
                    ttl: Some(60),
                    priority: 100,
                    publish: true,
                }],
                &HashMap::new(),
                60,
            )
            .unwrap();
        let store2 = Arc::new(RwLock::new(Store::new(
            config2.zone.clone(),
            config2.node_id(),
            rand::random(),
        )));

        let _gossip1 = start(store1, config1, vec![peer(port2)]).await.unwrap();
        let _gossip2 = start(store2.clone(), config2, vec![peer(port1)])
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if store2.read().await.resolve(&name).is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "record did not propagate");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let entry = store2.read().await.resolve(&name).unwrap();
        assert!(entry.records.iter().any(|record| {
            matches!(&record.data, RecordData::A(ip) if ip.to_string() == "10.0.0.1")
        }));
    }
}

#[cfg(test)]
mod partial_mesh_tests {
    use super::*;
    use crate::{
        config::LoadedConfig,
        netlink::Peer,
        store::{RecordTarget, ResolvedRecord},
    };
    use std::{fs, net::TcpListener, path::Path, sync::Arc, time::Instant};

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn config(dir: &Path, port: u16) -> Arc<LoadedConfig> {
        let path = dir.join(format!("namae-{port}.toml"));
        fs::write(
            &path,
            format!("zone = \"namae.\"\nsecret = \"test-secret\"\nport = {port}\n"),
        )
        .unwrap();
        Arc::new(LoadedConfig::load(&path, &dir.join("does-not-exist")).unwrap())
    }

    fn peer(port: u16) -> Peer {
        Peer {
            addr: format!("127.0.0.1:{port}").parse().unwrap(),
            ifindex: 0,
            ifname: None,
        }
    }

    #[tokio::test]
    async fn record_reaches_two_hops() {
        let dirs = [
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        ];
        let port_a = free_port();
        let mut port_b = free_port();
        while port_b == port_a {
            port_b = free_port();
        }
        let mut port_c = free_port();
        while port_c == port_a || port_c == port_b {
            port_c = free_port();
        }
        let config_a = config(dirs[0].path(), port_a);
        let config_b = config(dirs[1].path(), port_b);
        let config_c = config(dirs[2].path(), port_c);

        let name = Name::from_str("a.namae.").unwrap();
        let store_a = Arc::new(RwLock::new(Store::new(
            config_a.zone.clone(),
            config_a.node_id(),
            rand::random(),
        )));
        store_a
            .write()
            .await
            .set_local_records(
                &[ResolvedRecord {
                    name: name.clone(),
                    rtype: RecordType::A,
                    target: RecordTarget::Value(RecordData::A("10.0.0.1".parse().unwrap())),
                    ttl: Some(60),
                    priority: 100,
                    publish: true,
                }],
                &HashMap::new(),
                60,
            )
            .unwrap();
        let store_b = Arc::new(RwLock::new(Store::new(
            config_b.zone.clone(),
            config_b.node_id(),
            rand::random(),
        )));
        let store_c = Arc::new(RwLock::new(Store::new(
            config_c.zone.clone(),
            config_c.node_id(),
            rand::random(),
        )));

        let _gossip_a = start(store_a, config_a, vec![peer(port_b)]).await.unwrap();
        let _gossip_b = start(store_b.clone(), config_b, vec![]).await.unwrap();
        let _gossip_c = start(store_c.clone(), config_c, vec![peer(port_b)])
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if store_c.read().await.resolve(&name).is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "record did not cross two hops");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(store_b.read().await.resolve(&name).is_some());
    }
}
