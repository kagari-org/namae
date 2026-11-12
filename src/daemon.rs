use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::{RwLock, mpsc},
};
use tracing::{error, info, warn};

use crate::{
    config::LoadedConfig,
    control::{self, ControlState},
    dns::DnsService,
    gossip::{self, GossipHandle},
    netlink::{self, NetlinkEvent},
    store::Store,
};

pub async fn run(config_path: PathBuf, config_dir: PathBuf, ctl_path: PathBuf) -> Result<()> {
    fs::create_dir_all(&config_dir)
        .with_context(|| format!("creating {}", config_dir.display()))?;
    let loaded = Arc::new(
        LoadedConfig::load(&config_path, &config_dir)
            .with_context(|| format!("loading {}", config_path.display()))?,
    );
    let node_id = loaded.node_id();
    let session = rand::random();
    let snapshot = netlink::snapshot(loaded.raw.proto, loaded.raw.port).await?;
    let interfaces = Arc::new(RwLock::new(snapshot.interfaces.clone()));
    let store = Arc::new(RwLock::new(Store::new(
        loaded.zone.clone(),
        node_id,
        session,
    )));

    {
        let mut store = store.write().await;
        store.set_local_records(
            &loaded.records,
            &snapshot.interfaces,
            loaded.raw.default_ttl,
        )?;
    }

    let dns = Arc::new(DnsService::new(
        loaded.zone.clone(),
        &*store.read().await,
        loaded.raw.negative_ttl,
    )?);
    let config = Arc::new(ArcSwap::from(loaded.clone()));
    let initial_peer_count = snapshot.peers.len();
    let gossip = gossip::start(store.clone(), loaded.clone(), snapshot.peers).await?;

    let mut dns_task = {
        let dns = dns.clone();
        let listen = loaded.dns_listen().to_vec();
        tokio::spawn(async move { dns.serve(&listen).await })
    };

    let (reload_tx, mut reload_rx) = mpsc::channel(8);
    let control_task = {
        let state = ControlState {
            store: store.clone(),
            gossip: gossip.clone(),
            reload_tx,
            started: Instant::now(),
        };
        let path = ctl_path.clone();
        tokio::spawn(async move { control::serve(&path, state).await })
    };

    let (mut monitor_task, mut netlink_rx) =
        netlink::monitor(loaded.raw.proto, loaded.raw.port).context("starting netlink monitor")?;
    let netlink_loop = {
        let store = store.clone();
        let interfaces = interfaces.clone();
        let config = config.clone();
        let dns = dns.clone();
        let gossip = gossip.clone();
        tokio::spawn(async move {
            netlink_loop(store, interfaces, config, dns, gossip, &mut netlink_rx).await;
        })
    };

    let mut change_rx = gossip::subscribe_changes(&gossip);
    let dns_changes = {
        let store = store.clone();
        let dns = dns.clone();
        tokio::spawn(async move {
            while change_rx.recv().await.is_ok() {
                let store = store.read().await;
                if let Err(error) = dns.update(&store) {
                    error!("updating DNS catalog: {error:?}");
                }
            }
        })
    };

    let mut sighup = signal(SignalKind::hangup()).context("SIGHUP")?;
    let mut sigterm = signal(SignalKind::terminate()).context("SIGTERM")?;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    info!(
        "namae {} node={:X} zone={} dns={:?} port={} peers={}",
        env!("CARGO_PKG_VERSION"),
        node_id,
        loaded.zone,
        loaded.dns_listen(),
        loaded.raw.port,
        initial_peer_count
    );

    let result = loop {
        tokio::select! {
            _ = sighup.recv() => {
                if let Err(error) = reload(&config_path, &config_dir, &config, &store, &interfaces, &dns, &gossip).await {
                    warn!("reload failed: {error:#}");
                }
            }
            Some(()) = reload_rx.recv() => {
                if let Err(error) = reload(&config_path, &config_dir, &config, &store, &interfaces, &dns, &gossip).await {
                    warn!("reload failed: {error:#}");
                }
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received");
                break Ok(());
            }
            _ = &mut ctrl_c => {
                info!("SIGINT received");
                break Ok(());
            }
            result = &mut monitor_task => {
                match result {
                    Ok(Ok(())) => break Err(anyhow::anyhow!("netlink monitor stopped")),
                    Ok(Err(error)) => break Err(error.context("netlink monitor")),
                    Err(error) => break Err(anyhow::anyhow!("netlink monitor task: {error}")),
                }
            }
            result = &mut dns_task => {
                match result {
                    Ok(Ok(())) => break Err(anyhow::anyhow!("DNS server stopped")),
                    Ok(Err(error)) => break Err(error.context("DNS server")),
                    Err(error) => break Err(anyhow::anyhow!("DNS task: {error}")),
                }
            }
        }
    };

    netlink_loop.abort();
    dns_changes.abort();
    control_task.abort();
    result
}

async fn reload(
    config_path: &Path,
    config_dir: &Path,
    config: &Arc<ArcSwap<LoadedConfig>>,
    store: &Arc<RwLock<Store>>,
    interfaces: &Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    dns: &Arc<DnsService>,
    gossip: &GossipHandle,
) -> Result<()> {
    let new = LoadedConfig::load(config_path, config_dir)?;
    let old = config.load();
    if new.zone != old.zone {
        bail!("changing zone requires a restart");
    }
    if new.raw.port != old.raw.port {
        warn!("changing port requires a restart; keeping {}", old.raw.port);
    }
    if new.raw.dns_listen != old.raw.dns_listen {
        warn!("changing dns_listen requires a restart");
    }
    if let Some(id) = new.raw.id
        && id != old.node_id()
    {
        bail!("changing id requires a restart");
    }
    let secret_changed = new.secret != old.secret;
    let new_secret = new.secret.clone();
    drop(old);
    config.store(Arc::new(new));
    if secret_changed {
        gossip.set_secret(new_secret).await;
    }
    refresh_local(store, config, interfaces, dns, gossip).await
}

async fn refresh_local(
    store: &Arc<RwLock<Store>>,
    config: &Arc<ArcSwap<LoadedConfig>>,
    interfaces: &Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    dns: &Arc<DnsService>,
    gossip: &GossipHandle,
) -> Result<()> {
    let (records, default_ttl) = {
        let config = config.load();
        (config.records.clone(), config.raw.default_ttl)
    };
    let diff = {
        let interfaces = interfaces.read().await;
        let mut store = store.write().await;
        store.set_local_records(&records, &interfaces, default_ttl)?
    };
    {
        let store = store.read().await;
        dns.update(&store)?;
    }
    if !diff.is_empty() {
        gossip.publish(diff).await?;
    }
    Ok(())
}

async fn is_local(interfaces: &Arc<RwLock<HashMap<String, Vec<IpAddr>>>>, ip: IpAddr) -> bool {
    interfaces
        .read()
        .await
        .values()
        .flatten()
        .any(|address| *address == ip)
}

async fn netlink_loop(
    store: Arc<RwLock<Store>>,
    interfaces: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    config: Arc<ArcSwap<LoadedConfig>>,
    dns: Arc<DnsService>,
    gossip: GossipHandle,
    rx: &mut mpsc::Receiver<NetlinkEvent>,
) {
    while let Some(event) = rx.recv().await {
        match event {
            NetlinkEvent::PeerUp(peer) => {
                if !is_local(&interfaces, peer.addr.ip()).await {
                    gossip.add_peer(peer);
                }
            }
            NetlinkEvent::PeerDown(peer) => gossip.remove_peer(peer),
            NetlinkEvent::AddrUp { interface, addr } => {
                {
                    let mut interfaces = interfaces.write().await;
                    let values = interfaces.entry(interface).or_default();
                    if !values.contains(&addr) {
                        values.push(addr);
                    }
                }
                if let Err(error) = refresh_local(&store, &config, &interfaces, &dns, &gossip).await
                {
                    warn!("refreshing interface records: {error:#}");
                }
            }
            NetlinkEvent::AddrDown { interface, addr } => {
                {
                    let mut interfaces = interfaces.write().await;
                    if let Some(values) = interfaces.get_mut(&interface) {
                        values.retain(|value| *value != addr);
                    }
                }
                if let Err(error) = refresh_local(&store, &config, &interfaces, &dns, &gossip).await
                {
                    warn!("refreshing interface records: {error:#}");
                }
            }
        }
    }
}
