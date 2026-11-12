use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use hickory_proto::rr::{
    LowerName, Name, RData, Record,
    rdata::{A, AAAA, CNAME, NS, PTR, SOA, TXT},
};
use hickory_server::{
    ServerFuture,
    authority::{Catalog, ZoneType},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryAuthority,
};
use tokio::net::{TcpListener, UdpSocket};

use crate::store::{RecordData, Store};

#[derive(Clone)]
pub struct DnsHandler {
    catalog: Arc<ArcSwap<Catalog>>,
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.catalog
            .load()
            .handle_request(request, response_handle)
            .await
    }
}

pub struct DnsService {
    catalog: Arc<ArcSwap<Catalog>>,
    zone: Name,
    negative_ttl: u32,
}

impl DnsService {
    pub fn new(zone: Name, store: &Store, negative_ttl: u32) -> Result<Self> {
        let catalog = build_catalog(&zone, store, negative_ttl)?;
        Ok(Self {
            catalog: Arc::new(ArcSwap::from_pointee(catalog)),
            zone,
            negative_ttl,
        })
    }

    pub fn update(&self, store: &Store) -> Result<()> {
        let catalog = build_catalog(&self.zone, store, self.negative_ttl)?;
        self.catalog.store(Arc::new(catalog));
        Ok(())
    }

    pub fn handler(&self) -> DnsHandler {
        DnsHandler {
            catalog: self.catalog.clone(),
        }
    }

    pub async fn serve(self: Arc<Self>, listen: &[SocketAddr]) -> Result<()> {
        let mut server = ServerFuture::new(self.handler());
        for addr in listen {
            let udp = UdpSocket::bind(addr)
                .await
                .with_context(|| format!("binding UDP {addr}"))?;
            server.register_socket(udp);
            let tcp = TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding TCP {addr}"))?;
            server.register_listener(tcp, Duration::from_secs(30));
        }
        server.block_until_done().await.context("DNS server failed")
    }
}

fn rdata(record: &RecordData) -> RData {
    match record {
        RecordData::A(ip) => RData::A(A(*ip)),
        RecordData::Aaaa(ip) => RData::AAAA(AAAA(*ip)),
        RecordData::Cname(name) => RData::CNAME(CNAME(name.clone())),
        RecordData::Txt(text) => RData::TXT(TXT::new(vec![text.clone()])),
    }
}

fn build_catalog(zone: &Name, store: &Store, negative_ttl: u32) -> Result<Catalog> {
    let mut authority = authority_for(zone, negative_ttl)?;
    let mut reverse = BTreeMap::new();
    for origin in ["in-addr.arpa.", "ip6.arpa."] {
        let origin = Name::from_str(origin).expect("static reverse zone");
        reverse.insert(origin.clone(), authority_for(&origin, negative_ttl)?);
    }
    for (name, entry) in store.resolved_entries() {
        for rr in &entry.records {
            authority.upsert_mut(
                Record::from_rdata(name.clone(), entry.ttl, rdata(&rr.data)),
                entry.version as u32,
            );
            let Some(address) = rr.data.address() else {
                continue;
            };
            if !entry.rdns {
                continue;
            }
            if name.to_string().starts_with("*.") {
                continue;
            }
            let reverse_name = reverse_name(address);
            let target = reverse
                .iter_mut()
                .filter(|(zone, _)| zone.zone_of(&reverse_name))
                .max_by_key(|(zone, _)| zone.num_labels());
            if let Some((_, authority)) = target {
                authority.upsert_mut(
                    Record::from_rdata(reverse_name, entry.ttl, RData::PTR(PTR(name.clone()))),
                    entry.version as u32,
                );
            }
        }
    }

    let mut catalog = Catalog::new();
    catalog.upsert(LowerName::from(zone.clone()), vec![Arc::new(authority)]);
    for (zone, authority) in reverse {
        catalog.upsert(LowerName::from(zone), vec![Arc::new(authority)]);
    }
    Ok(catalog)
}

fn authority_for(origin: &Name, negative_ttl: u32) -> Result<InMemoryAuthority> {
    let mut authority = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);
    let ns_name = Name::from_str("ns").unwrap().append_domain(origin)?;
    let hostmaster = Name::from_str("hostmaster")
        .unwrap()
        .append_domain(origin)?;
    let soa = SOA::new(
        ns_name.clone(),
        hostmaster,
        1,
        3600,
        600,
        86400,
        negative_ttl,
    );
    authority.upsert_mut(
        Record::from_rdata(origin.clone(), negative_ttl, RData::SOA(soa)),
        1,
    );
    authority.upsert_mut(
        Record::from_rdata(origin.clone(), negative_ttl, RData::NS(NS(ns_name))),
        1,
    );
    Ok(authority)
}

fn reverse_name(address: IpAddr) -> Name {
    let text = match address {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa.",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(ip) => {
            let mut labels = Vec::with_capacity(32);
            for byte in ip.octets().iter().rev() {
                labels.push(format!("{:x}", byte & 0x0f));
                labels.push(format!("{:x}", byte >> 4));
            }
            format!("{}.ip6.arpa.", labels.join("."))
        }
    };
    Name::from_str(&text).expect("generated reverse name is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{RecordData, RecordTarget, ResolvedRecord};
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::RecordType,
        serialize::binary::BinEncodable,
    };
    use std::{collections::HashMap, net::SocketAddr};

    #[tokio::test]
    async fn serves_a_record() {
        let zone = Name::from_str("namae.").unwrap();
        let mut store = Store::new(zone.clone(), 1, 1);
        let name = Name::from_str("a.namae.").unwrap();
        store
            .set_local_records(
                &[ResolvedRecord {
                    name: name.clone(),
                    rtype: RecordType::A,
                    target: RecordTarget::Value(RecordData::A("10.0.0.1".parse().unwrap())),
                    ttl: Some(60),
                    priority: 100,
                    publish: true,
                    rdns: true,
                }],
                &HashMap::new(),
                60,
            )
            .unwrap();
        let service = Arc::new(DnsService::new(zone, &store, 30).unwrap());
        let addr: SocketAddr = "127.0.0.1:15354".parse().unwrap();
        let handle = tokio::spawn(async move { service.serve(&[addr]).await });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut query = Message::new();
        query.set_id(0x1234);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(false);
        query.add_query(Query::query(name, RecordType::A));
        let bytes = query.to_bytes().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&bytes, addr).await.unwrap();
        let mut buffer = [0u8; 2048];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = Message::from_vec(&buffer[..len]).unwrap();
        assert_eq!(
            response.response_code(),
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(response.answers().len(), 1);
        handle.abort();
    }
}

#[cfg(test)]
mod semantics_tests {
    use super::*;
    use crate::store::{RecordData, RecordTarget, ResolvedRecord};
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::RecordType,
        serialize::binary::BinEncodable,
    };
    use std::{collections::HashMap, net::SocketAddr};
    use tokio::task::JoinHandle;

    fn record(name: &str, rtype: RecordType, data: RecordData) -> ResolvedRecord {
        ResolvedRecord {
            name: Name::from_str(name).unwrap(),
            rtype,
            target: RecordTarget::Value(data),
            ttl: Some(60),
            priority: 100,
            publish: true,
            rdns: true,
        }
    }

    async fn start(zone: Name, records: Vec<ResolvedRecord>, port: u16) -> JoinHandle<Result<()>> {
        let mut store = Store::new(zone.clone(), 1, 1);
        store
            .set_local_records(&records, &HashMap::new(), 60)
            .unwrap();
        let service = Arc::new(DnsService::new(zone, &store, 30).unwrap());
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let handle = tokio::spawn(async move { service.serve(&[addr]).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        handle
    }

    async fn ask(port: u16, name: &str, rtype: RecordType) -> Message {
        let mut query = Message::new();
        query.set_id(0x2345);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(false);
        query.add_query(Query::query(Name::from_str(name).unwrap(), rtype));
        let bytes = query.to_bytes().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        client.send_to(&bytes, addr).await.unwrap();
        let mut buffer = [0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        Message::from_vec(&buffer[..len]).unwrap()
    }

    #[tokio::test]
    async fn cname_any_wildcard_and_nxdomain() {
        let zone = Name::from_str("namae.").unwrap();
        let records = vec![
            record(
                "target.namae.",
                RecordType::A,
                RecordData::A("10.0.0.2".parse().unwrap()),
            ),
            record(
                "alias.namae.",
                RecordType::CNAME,
                RecordData::Cname(Name::from_str("target.namae.").unwrap()),
            ),
            record(
                "*.namae.",
                RecordType::A,
                RecordData::A("10.0.0.9".parse().unwrap()),
            ),
        ];
        let handle = start(zone.clone(), records.clone(), 15356).await;
        let without_wildcard = start(zone, records[..2].to_vec(), 15358).await;

        let response = ask(15356, "alias.namae.", RecordType::A).await;
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().iter().any(|record| {
            matches!(record.data(), RData::CNAME(cname) if cname.0.to_string() == "target.namae.")
        }));
        assert!(
            response
                .answers()
                .iter()
                .chain(response.additionals())
                .any(|record| {
                    matches!(record.data(), RData::A(a) if a.0.to_string() == "10.0.0.2")
                })
        );

        let response = ask(15356, "target.namae.", RecordType::ANY).await;
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().iter().any(|record| {
            matches!(record.data(), RData::A(a) if a.0.to_string() == "10.0.0.2")
        }));

        let response = ask(15356, "target.namae.", RecordType::AAAA).await;
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().is_empty());
        assert!(
            response
                .name_servers()
                .iter()
                .any(|record| { matches!(record.data(), RData::SOA(_)) })
        );

        let response = ask(15356, "foo.namae.", RecordType::A).await;
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().iter().any(|record| {
            matches!(record.data(), RData::A(a) if a.0.to_string() == "10.0.0.9")
        }));

        let response = ask(15358, "missing.sub.namae.", RecordType::A).await;
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert!(
            response
                .name_servers()
                .iter()
                .any(|record| { matches!(record.data(), RData::SOA(soa) if soa.minimum() == 30) })
        );
        without_wildcard.abort();
        handle.abort();
    }

    #[tokio::test]
    async fn ptr_from_address_records() {
        let zone = Name::from_str("namae.").unwrap();
        let records = vec![record(
            "host.namae.",
            RecordType::A,
            RecordData::A("10.0.0.1".parse().unwrap()),
        )];
        let handle = start(zone, records, 15357).await;

        let response = ask(15357, "1.0.0.10.in-addr.arpa.", RecordType::PTR).await;
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().iter().any(|record| {
            matches!(record.data(), RData::PTR(ptr) if ptr.0.to_string() == "host.namae.")
        }));
        handle.abort();
    }

    #[tokio::test]
    async fn rdns_false_suppresses_ptr() {
        let zone = Name::from_str("namae.").unwrap();
        let mut address = record(
            "host.namae.",
            RecordType::A,
            RecordData::A("10.0.0.1".parse().unwrap()),
        );
        address.rdns = false;
        let handle = start(zone, vec![address], 15359).await;

        let response = ask(15359, "1.0.0.10.in-addr.arpa.", RecordType::PTR).await;
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        handle.abort();
    }

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name("10.0.0.1".parse().unwrap()).to_string(),
            "1.0.0.10.in-addr.arpa."
        );
        let v6 = reverse_name("2001:db8::1".parse().unwrap()).to_string();
        assert!(v6.ends_with(".ip6.arpa."));
        assert!(v6.starts_with("1.0."));
    }
}
