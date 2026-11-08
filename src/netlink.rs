use std::{
    collections::HashMap,
    ffi::CStr,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

use anyhow::{Context, Result, bail};
use futures::{StreamExt, TryStreamExt};
use rtnetlink::{
    packet_core::NetlinkPayload,
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        address::{AddressAttribute, AddressMessage},
        route::{RouteAddress, RouteAttribute, RouteMessage, RouteType},
    },
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::debug;

use crate::config::Proto;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Peer {
    pub addr: SocketAddr,
    pub ifindex: u32,
    pub ifname: Option<String>,
}

#[derive(Clone, Debug)]
pub enum NetlinkEvent {
    PeerUp(Peer),
    PeerDown(Peer),
    AddrUp { interface: String, addr: IpAddr },
    AddrDown { interface: String, addr: IpAddr },
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub peers: Vec<Peer>,
    pub interfaces: HashMap<String, Vec<IpAddr>>,
}

pub async fn snapshot(proto: Proto, port: u16) -> Result<Snapshot> {
    let (connection, handle, _messages) = rtnetlink::new_connection().context("netlink route")?;
    let connection = tokio::spawn(connection);

    let routes = handle
        .route()
        .get(RouteMessage::default())
        .execute()
        .try_collect::<Vec<_>>()
        .await
        .context("dumping routes")?;
    let addresses = handle
        .address()
        .get()
        .execute()
        .try_collect::<Vec<_>>()
        .await
        .context("dumping addresses")?;
    connection.abort();

    let mut peers = routes
        .iter()
        .filter_map(|route| route_to_peer(route, proto, port))
        .collect::<Vec<_>>();
    let mut interfaces: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for address in &addresses {
        if let Some((interface, ip)) = address_to_entry(address) {
            interfaces.entry(interface).or_default().push(ip);
        }
    }
    for values in interfaces.values_mut() {
        values.sort();
        values.dedup();
    }
    peers.retain(|peer| {
        !interfaces
            .values()
            .flatten()
            .any(|address| *address == peer.addr.ip())
    });
    Ok(Snapshot { peers, interfaces })
}

pub fn monitor(
    proto: Proto,
    port: u16,
) -> Result<(JoinHandle<Result<()>>, mpsc::Receiver<NetlinkEvent>)> {
    let (connection, _handle, mut messages) = rtnetlink::new_multicast_connection(&[
        rtnetlink::MulticastGroup::Ipv4Route,
        rtnetlink::MulticastGroup::Ipv6Route,
        rtnetlink::MulticastGroup::Ipv4Ifaddr,
        rtnetlink::MulticastGroup::Ipv6Ifaddr,
    ])
    .context("opening netlink route monitor")?;
    let (tx, rx) = mpsc::channel(1024);
    let task = tokio::spawn(async move {
        let connection = tokio::spawn(connection);
        while let Some((message, _addr)) = messages.next().await {
            let event = match message.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
                    route_to_peer(&route, proto, port).map(NetlinkEvent::PeerUp)
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(route)) => {
                    route_to_peer(&route, proto, port).map(NetlinkEvent::PeerDown)
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(address)) => {
                    address_to_entry(&address)
                        .map(|(interface, addr)| NetlinkEvent::AddrUp { interface, addr })
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(address)) => {
                    address_to_entry(&address)
                        .map(|(interface, addr)| NetlinkEvent::AddrDown { interface, addr })
                }
                NetlinkPayload::Error(error) => {
                    connection.abort();
                    bail!("netlink monitor error: {error}");
                }
                _ => None,
            };
            if let Some(event) = event
                && tx.send(event).await.is_err()
            {
                break;
            }
        }
        connection.abort();
        Ok(())
    });
    Ok((task, rx))
}

fn route_to_peer(route: &RouteMessage, proto: Proto, port: u16) -> Option<Peer> {
    if route.header.kind != RouteType::Unicast {
        return None;
    }
    if let Some(expected) = proto.0
        && u8::from(route.header.protocol) != expected
    {
        return None;
    }
    let expected_prefix = match route.header.address_family {
        AddressFamily::Inet => 32,
        AddressFamily::Inet6 => 128,
        _ => return None,
    };
    if route.header.destination_prefix_length != expected_prefix {
        return None;
    }
    let destination = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(ip)) => Some(IpAddr::V4(*ip)),
            RouteAttribute::Destination(RouteAddress::Inet6(ip)) => Some(IpAddr::V6(*ip)),
            _ => None,
        })?;
    if destination.is_unspecified() || destination.is_multicast() {
        return None;
    }
    let ifindex = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        });
    let ifname = ifindex.and_then(ifname);
    let addr = match destination {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), port),
        IpAddr::V6(ip) => {
            let scope = ifindex.unwrap_or(0);
            SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope))
        }
    };
    Some(Peer {
        addr,
        ifindex: ifindex.unwrap_or(0),
        ifname,
    })
}

fn address_to_entry(message: &AddressMessage) -> Option<(String, IpAddr)> {
    if message
        .header
        .flags
        .intersects(rtnetlink::packet_route::address::AddressHeaderFlags::Tentative)
        || message
            .header
            .flags
            .intersects(rtnetlink::packet_route::address::AddressHeaderFlags::Dadfailed)
    {
        return None;
    }
    let interface = ifname(message.header.index)?;
    if interface == "lo" {
        return None;
    }
    let mut address = None;
    for attribute in &message.attributes {
        match attribute {
            AddressAttribute::Local(ip) => {
                address = Some(*ip);
                break;
            }
            AddressAttribute::Address(ip) => {
                address.get_or_insert(*ip);
            }
            _ => {}
        }
    }
    let address = address?;
    if address.is_unspecified() || address.is_multicast() || address.is_loopback() {
        return None;
    }
    if let IpAddr::V6(ip) = address
        && is_link_local_v6(&ip)
    {
        return None;
    }
    if let IpAddr::V4(ip) = address
        && ip.is_link_local()
    {
        return None;
    }
    Some((interface, address))
}

fn ifname(index: u32) -> Option<String> {
    let mut buffer = [0u8; libc::IF_NAMESIZE];
    let pointer = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr().cast()) };
    if pointer.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(pointer) };
    name.to_str().ok().map(str::to_owned)
}

fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

pub async fn resolve_ipv4(entry: &str) -> Result<IpAddr> {
    let _ = entry;
    bail!("not implemented")
}

#[allow(dead_code)]
fn log_route(route: &RouteMessage) {
    debug!(
        "route family={:?} proto={:?} prefix={} kind={:?}",
        route.header.address_family,
        route.header.protocol,
        route.header.destination_prefix_length,
        route.header.kind
    );
}

pub async fn dump_links() -> Result<()> {
    let (connection, handle, _messages) = rtnetlink::new_connection()?;
    let task = tokio::spawn(connection);
    let _ = handle.link().get().execute().try_collect::<Vec<_>>().await;
    task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::packet_route::route::{RouteHeader, RouteProtocol};

    fn route(prefix: u8, protocol: RouteProtocol, ip: &str) -> RouteMessage {
        let header = RouteHeader {
            address_family: AddressFamily::Inet,
            destination_prefix_length: prefix,
            protocol,
            kind: RouteType::Unicast,
            ..Default::default()
        };
        let mut message = RouteMessage::default();
        message.header = header;
        message.attributes = vec![RouteAttribute::Destination(RouteAddress::from(
            ip.parse::<std::net::Ipv4Addr>().unwrap(),
        ))];
        message
    }

    #[test]
    fn filters_host_routes() {
        let bird = Proto(Some(12));
        assert!(route_to_peer(&route(32, RouteProtocol::Bird, "10.0.0.1"), bird, 7654).is_some());
        assert!(route_to_peer(&route(24, RouteProtocol::Bird, "10.0.0.0"), bird, 7654).is_none());
        assert!(route_to_peer(&route(32, RouteProtocol::Static, "10.0.0.1"), bird, 7654).is_none());
    }

    #[test]
    fn ipv6_requires_128() {
        let mut message = route(32, RouteProtocol::Bird, "10.0.0.1");
        message.header.destination_prefix_length = 128;
        message.header.address_family = AddressFamily::Inet6;
        message.attributes = vec![RouteAttribute::Destination(RouteAddress::Inet6(
            "fd00::1".parse().unwrap(),
        ))];
        assert!(route_to_peer(&message, Proto(Some(12)), 7654).is_some());
        message.header.destination_prefix_length = 64;
        assert!(route_to_peer(&message, Proto(Some(12)), 7654).is_none());
    }

    #[test]
    fn proto_any_accepts_all() {
        assert!(
            route_to_peer(
                &route(32, RouteProtocol::Static, "10.0.0.1"),
                Proto(None),
                7654
            )
            .is_some()
        );
    }

    #[tokio::test]
    async fn snapshot_does_not_panic() {
        let result = snapshot(Proto(Some(12)), 7654).await;
        if let Ok(snapshot) = result {
            for peer in snapshot.peers {
                assert!(peer.addr.port() == 7654);
            }
        }
    }
}
