use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use hickory_proto::rr::{
    LowerName, Name, RData, Record,
    rdata::{A, AAAA, CNAME, NS, SOA, TXT},
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
    let origin = zone.clone();
    let mut authority = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);

    let ns_name = Name::from_str("ns").unwrap().append_domain(zone)?;
    let hostmaster = Name::from_str("hostmaster").unwrap().append_domain(zone)?;
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

    for (name, entry) in store.resolved_entries() {
        for rr in &entry.records {
            authority.upsert_mut(
                Record::from_rdata(name.clone(), entry.ttl, rdata(&rr.data)),
                entry.version as u32,
            );
        }
    }

    let mut catalog = Catalog::new();
    catalog.upsert(LowerName::from(zone.clone()), vec![Arc::new(authority)]);
    Ok(catalog)
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
