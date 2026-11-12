use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use hickory_proto::rr::{Name, RecordType};
use sha2::{Digest, Sha256};

pub type NodeId = u64;
pub type SnapshotData = (u64, u64, Vec<(Name, NameEntry)>, Vec<(Name, u64)>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Name),
    Txt(String),
}

impl RecordData {
    pub fn rtype(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::AAAA,
            Self::Cname(_) => RecordType::CNAME,
            Self::Txt(_) => RecordType::TXT,
        }
    }

    pub fn address(&self) -> Option<IpAddr> {
        match self {
            Self::A(ip) => Some(IpAddr::V4(*ip)),
            Self::Aaaa(ip) => Some(IpAddr::V6(*ip)),
            _ => None,
        }
    }
}

impl Hash for RecordData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.rtype().hash(state);
        match self {
            Self::A(ip) => ip.hash(state),
            Self::Aaaa(ip) => ip.hash(state),
            Self::Cname(name) => name.hash(state),
            Self::Txt(text) => text.hash(state),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrData {
    pub rtype: RecordType,
    pub data: RecordData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameEntry {
    pub owner: NodeId,
    pub priority: u16,
    pub version: u64,
    pub ttl: u32,
    pub rdns: bool,
    pub records: Vec<RrData>,
}

impl NameEntry {
    pub fn has_type(&self, rtype: RecordType) -> bool {
        self.records.iter().any(|record| record.rtype == rtype)
    }

    pub fn addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.records
            .iter()
            .filter_map(|record| record.data.address())
    }

    fn sort_records(&mut self) {
        self.records.sort_by(|a, b| {
            a.rtype
                .cmp(&b.rtype)
                .then_with(|| format!("{:?}", a.data).cmp(&format!("{:?}", b.data)))
        });
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedRecord {
    pub name: Name,
    pub rtype: RecordType,
    pub target: RecordTarget,
    pub ttl: Option<u32>,
    pub priority: u16,
    pub publish: bool,
    pub rdns: bool,
}

#[derive(Clone, Debug)]
pub enum RecordTarget {
    Value(RecordData),
    Interface(String),
}

#[derive(Clone, Debug)]
pub struct LocalEntry {
    pub entry: NameEntry,
    pub publish: bool,
}

#[derive(Clone, Debug, Default)]
pub struct LocalDiff {
    pub upserts: Vec<(Name, NameEntry)>,
    pub deletes: Vec<(Name, u64)>,
}

impl LocalDiff {
    pub fn is_empty(&self) -> bool {
        self.upserts.is_empty() && self.deletes.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginMeta {
    pub session: u64,
    pub seq: u64,
    pub last_seen: Instant,
}
#[derive(Clone, Debug)]
struct VersionMeta {
    version: u64,
    last_used: Instant,
}

#[derive(Clone, Debug)]
pub struct OriginDigest {
    pub origin: NodeId,
    pub session: u64,
    pub seq: u64,
}

#[derive(Clone, Debug)]
pub struct HeartbeatOutcome {
    pub updated: bool,
    pub needs_sync: bool,
}

#[derive(Clone, Debug)]
pub enum ApplyResult {
    Applied { changed: bool },
    Stale,
    Gap,
}

#[derive(Clone, Debug)]
pub struct Conflict {
    pub name: Name,
    pub candidates: Vec<NameEntry>,
}

#[derive(Clone, Debug)]
pub struct Store {
    zone: Name,
    local_id: NodeId,
    local_session: u64,
    local_seq: u64,
    local: BTreeMap<Name, LocalEntry>,
    remote: HashMap<NodeId, HashMap<Name, NameEntry>>,
    meta: HashMap<NodeId, OriginMeta>,
    tombstones: HashMap<(NodeId, Name), (u64, Instant)>,
    remote_digests: HashMap<NodeId, [u8; 16]>,
    versions: HashMap<Name, VersionMeta>,
    expired: HashMap<NodeId, Instant>,
}

impl Store {
    pub fn new(zone: Name, local_id: NodeId, local_session: u64) -> Self {
        Self {
            zone,
            local_id,
            local_session,
            local_seq: 0,
            local: BTreeMap::new(),
            remote: HashMap::new(),
            meta: HashMap::new(),
            tombstones: HashMap::new(),
            remote_digests: HashMap::new(),
            versions: HashMap::new(),
            expired: HashMap::new(),
        }
    }

    pub fn zone(&self) -> &Name {
        &self.zone
    }

    pub fn local_id(&self) -> NodeId {
        self.local_id
    }

    pub fn local_session(&self) -> u64 {
        self.local_session
    }

    pub fn local_seq(&self) -> u64 {
        self.local_seq
    }

    pub fn bump_local_seq(&mut self) -> u64 {
        self.local_seq = self.local_seq.wrapping_add(1);
        self.local_seq
    }

    pub fn local_published(&self) -> Vec<(Name, NameEntry)> {
        self.local
            .iter()
            .filter(|(_, entry)| entry.publish)
            .map(|(name, entry)| (name.clone(), entry.entry.clone()))
            .collect()
    }

    pub fn set_local_records(
        &mut self,
        records: &[ResolvedRecord],
        interfaces: &HashMap<String, Vec<IpAddr>>,
        default_ttl: u32,
    ) -> Result<LocalDiff> {
        let mut grouped: BTreeMap<Name, (Vec<RrData>, u32, u16, bool, bool)> = BTreeMap::new();
        for record in records {
            let (ttl, priority, publish) = (
                record.ttl.unwrap_or(default_ttl).clamp(5, 3600),
                record.priority,
                record.publish,
            );
            let slot = grouped
                .entry(record.name.clone())
                .or_insert_with(|| (Vec::new(), ttl, priority, publish, record.rdns));
            if slot.2 != priority || slot.3 != publish || slot.4 != record.rdns {
                bail!("inconsistent record options for {}", record.name);
            }
            slot.1 = slot.1.min(ttl);
            match &record.target {
                RecordTarget::Value(data) => slot.0.push(RrData {
                    rtype: data.rtype(),
                    data: data.clone(),
                }),
                RecordTarget::Interface(interface) => {
                    for ip in interfaces.get(interface).into_iter().flatten() {
                        let data = match (record.rtype, ip) {
                            (RecordType::A, IpAddr::V4(ip)) => RecordData::A(*ip),
                            (RecordType::AAAA, IpAddr::V6(ip)) => RecordData::Aaaa(*ip),
                            _ => continue,
                        };
                        slot.0.push(RrData {
                            rtype: data.rtype(),
                            data,
                        });
                    }
                }
            }
        }

        for (records, _, _, _, _) in grouped.values_mut() {
            records.sort_by(|a, b| {
                a.rtype
                    .cmp(&b.rtype)
                    .then_with(|| format!("{:?}", a.data).cmp(&format!("{:?}", b.data)))
            });
            records.dedup();
        }

        let mut diff = LocalDiff::default();
        let mut next_local: BTreeMap<Name, LocalEntry> = BTreeMap::new();
        for (name, (records, ttl, priority, publish, rdns)) in grouped {
            let now = Instant::now();
            let meta = self.versions.entry(name.clone()).or_insert(VersionMeta {
                version: 0,
                last_used: now,
            });
            meta.last_used = now;
            let mut entry = NameEntry {
                owner: self.local_id,
                priority,
                version: meta.version,
                ttl,
                rdns,
                records,
            };
            entry.sort_records();
            let previous = self.local.get(&name);
            let changed = previous.is_none_or(|previous| {
                previous.entry.records != entry.records
                    || previous.entry.ttl != entry.ttl
                    || previous.entry.priority != entry.priority
                    || previous.publish != publish
                    || previous.entry.rdns != rdns
            });
            if previous.is_none() || changed {
                meta.version = meta.version.wrapping_add(1);
                entry.version = meta.version;
                if publish {
                    diff.upserts.push((name.clone(), entry.clone()));
                } else if previous.is_some_and(|previous| previous.publish) {
                    diff.deletes.push((name.clone(), entry.version));
                }
            }
            next_local.insert(name, LocalEntry { entry, publish });
        }

        for name in self.local.keys() {
            if next_local.contains_key(name) {
                continue;
            }
            let Some(previous) = self.local.get(name) else {
                continue;
            };
            let now = Instant::now();
            let version = self.versions.entry(name.clone()).or_insert(VersionMeta {
                version: 0,
                last_used: now,
            });
            version.version = version.version.wrapping_add(1);
            version.last_used = now;
            if previous.publish {
                diff.deletes.push((name.clone(), version.version));
            }
        }
        self.local = next_local;
        if !diff.is_empty() {
            self.local_seq = self.local_seq.wrapping_add(1);
        }
        Ok(diff)
    }

    pub fn resolve(&self, name: &Name) -> Option<NameEntry> {
        if let Some(entry) = self.local.get(name) {
            return Some(entry.entry.clone());
        }
        self.remote
            .values()
            .filter_map(|entries| entries.get(name))
            .max_by(|a, b| {
                a.priority
                    .cmp(&b.priority)
                    .then_with(|| a.version.cmp(&b.version))
                    .then_with(|| b.owner.cmp(&a.owner))
            })
            .cloned()
    }

    pub fn resolve_type(&self, name: &Name, rtype: RecordType) -> ResolveOutcome {
        let Some(entry) = self.resolve(name) else {
            return ResolveOutcome::NxDomain;
        };
        if entry.has_type(rtype) || rtype == RecordType::ANY {
            return ResolveOutcome::Found(entry);
        }
        ResolveOutcome::NoData
    }

    pub fn apply_snapshot(
        &mut self,
        origin: NodeId,
        session: u64,
        seq: u64,
        entries: Vec<(Name, NameEntry)>,
        tombstones: Vec<(Name, u64)>,
    ) -> ApplyResult {
        self.apply_snapshot_from(origin, session, seq, entries, tombstones, true)
    }

    pub fn apply_snapshot_from(
        &mut self,
        origin: NodeId,
        session: u64,
        seq: u64,
        entries: Vec<(Name, NameEntry)>,
        tombstones: Vec<(Name, u64)>,
        from_origin: bool,
    ) -> ApplyResult {
        if let Some(meta) = self.meta.get(&origin)
            && meta.session == session
            && seq < meta.seq
        {
            return ApplyResult::Stale;
        }
        if !from_origin && self.expired.contains_key(&origin) {
            return ApplyResult::Stale;
        }
        let mut changed = false;
        let session_changed = self
            .meta
            .get(&origin)
            .is_none_or(|meta| meta.session != session);
        if session_changed && !from_origin && self.meta.contains_key(&origin) {
            return ApplyResult::Stale;
        }
        let last_seen = if from_origin {
            Instant::now()
        } else {
            self.meta
                .get(&origin)
                .map_or_else(Instant::now, |meta| meta.last_seen)
        };
        if from_origin {
            self.expired.remove(&origin);
        }
        if session_changed {
            self.remote.remove(&origin);
            self.tombstones.retain(|(owner, _), _| *owner != origin);
            changed = true;
        }
        let target = self.remote.entry(origin).or_default();
        let mut seen = HashSet::new();
        for (name, entry) in entries {
            if !self.zone.zone_of(&name) {
                continue;
            }
            seen.insert(name.clone());
            let replace = target
                .get(&name)
                .is_none_or(|current| entry.version > current.version);
            if replace {
                target.insert(name, entry);
                changed = true;
            }
        }
        target.retain(|name, _| seen.contains(name));
        for (name, version) in tombstones {
            self.tombstones
                .insert((origin, name.clone()), (version, Instant::now()));
            if let Some(current) = target.get(&name)
                && current.version <= version
            {
                target.remove(&name);
                changed = true;
            }
        }
        if let Some(digest) = self.remote_digest(origin) {
            self.remote_digests.insert(origin, digest);
        }
        self.meta.insert(
            origin,
            OriginMeta {
                session,
                seq,
                last_seen,
            },
        );
        ApplyResult::Applied { changed }
    }

    pub fn apply_delta(
        &mut self,
        origin: NodeId,
        session: u64,
        seq: u64,
        upserts: Vec<(Name, NameEntry)>,
        deletes: Vec<(Name, u64)>,
    ) -> ApplyResult {
        let Some(meta) = self.meta.get(&origin) else {
            return ApplyResult::Gap;
        };
        if meta.session != session {
            return ApplyResult::Gap;
        }
        if seq <= meta.seq {
            return ApplyResult::Stale;
        }
        if seq != meta.seq.wrapping_add(1) {
            return ApplyResult::Gap;
        }
        let mut changed = false;
        self.expired.remove(&origin);
        let target = self.remote.entry(origin).or_default();
        for (name, entry) in upserts {
            if !self.zone.zone_of(&name) {
                continue;
            }
            let replace = target
                .get(&name)
                .is_none_or(|current| entry.version > current.version);
            if replace {
                target.insert(name, entry);
                changed = true;
            }
        }
        for (name, version) in deletes {
            self.tombstones
                .insert((origin, name.clone()), (version, Instant::now()));
            if let Some(current) = target.get(&name)
                && current.version <= version
            {
                target.remove(&name);
                changed = true;
            }
        }
        if let Some(digest) = self.remote_digest(origin) {
            self.remote_digests.insert(origin, digest);
        }
        self.meta.insert(
            origin,
            OriginMeta {
                session,
                seq,
                last_seen: Instant::now(),
            },
        );
        ApplyResult::Applied { changed }
    }

    pub fn heartbeat(
        &mut self,
        origin: NodeId,
        session: u64,
        seq: u64,
        digest: [u8; 16],
    ) -> HeartbeatOutcome {
        let session_changed = self
            .meta
            .get(&origin)
            .is_some_and(|meta| meta.session != session);
        if session_changed {
            self.remote.remove(&origin);
            self.remote_digests.remove(&origin);
            self.tombstones.retain(|(owner, _), _| *owner != origin);
        }
        let updated = match self.meta.get_mut(&origin) {
            None => {
                self.meta.insert(
                    origin,
                    OriginMeta {
                        session,
                        seq,
                        last_seen: Instant::now(),
                    },
                );
                true
            }
            Some(meta) => {
                if meta.session == session && seq <= meta.seq {
                    false
                } else {
                    meta.session = session;
                    meta.seq = seq;
                    meta.last_seen = Instant::now();
                    true
                }
            }
        };
        if updated {
            self.expired.remove(&origin);
        }
        let needs_sync = self
            .remote_digests
            .get(&origin)
            .is_none_or(|known| known != &digest);
        self.remote_digests.insert(origin, digest);
        HeartbeatOutcome {
            updated,
            needs_sync,
        }
    }

    pub fn origin_digests(&self) -> Vec<OriginDigest> {
        let mut digests = self
            .meta
            .iter()
            .map(|(origin, meta)| OriginDigest {
                origin: *origin,
                session: meta.session,
                seq: meta.seq,
            })
            .collect::<Vec<_>>();
        digests.sort_by_key(|digest| digest.origin);
        digests
    }

    pub fn snapshot_for(&self, origin: NodeId) -> Option<SnapshotData> {
        let meta = self.meta.get(&origin)?;
        let entries = self
            .remote
            .get(&origin)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(name, entry)| (name.clone(), entry.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let tombstones = self
            .tombstones
            .iter()
            .filter(|((owner, _), _)| *owner == origin)
            .map(|((_, name), (version, _))| (name.clone(), *version))
            .collect::<Vec<_>>();
        Some((meta.session, meta.seq, entries, tombstones))
    }

    pub fn is_expired(&self, origin: NodeId) -> bool {
        self.expired.contains_key(&origin)
    }

    pub fn remote_entry(&self, origin: NodeId, name: &Name) -> Option<&NameEntry> {
        self.remote.get(&origin)?.get(name)
    }

    pub fn expire(&mut self, origin_timeout: Duration, tombstone_ttl: Duration) -> bool {
        let now = Instant::now();
        let mut changed = false;
        let expired = self
            .meta
            .iter()
            .filter(|(_, meta)| now.duration_since(meta.last_seen) > origin_timeout)
            .map(|(origin, _)| *origin)
            .collect::<Vec<_>>();
        for origin in expired {
            self.meta.remove(&origin);
            self.remote_digests.remove(&origin);
            if self.remote.remove(&origin).is_some() {
                changed = true;
            }
            self.expired.insert(origin, now);
        }
        self.tombstones.retain(|_, (_, seen)| {
            let keep = now.duration_since(*seen) <= tombstone_ttl;
            changed |= !keep;
            keep
        });
        let dead_ttl = tombstone_ttl.max(origin_timeout);
        self.expired
            .retain(|_, seen| now.duration_since(*seen) <= dead_ttl);

        let local = &self.local;
        self.versions.retain(|name, meta| {
            local.contains_key(name) || now.duration_since(meta.last_used) <= tombstone_ttl
        });
        changed
    }

    pub fn conflicts(&self) -> Vec<Conflict> {
        let mut names = BTreeMap::<Name, Vec<NameEntry>>::new();
        for entries in self.remote.values() {
            for (name, entry) in entries {
                names.entry(name.clone()).or_default().push(entry.clone());
            }
        }
        for (name, entry) in &self.local {
            names
                .entry(name.clone())
                .or_default()
                .push(entry.entry.clone());
        }
        names
            .into_iter()
            .filter(|(_, entries)| entries.len() > 1)
            .map(|(name, candidates)| Conflict { name, candidates })
            .collect()
    }

    pub fn local_digest(&self) -> [u8; 16] {
        digest_entries(self.local.iter().map(|(name, entry)| (name, &entry.entry)))
    }

    pub fn remote_digest(&self, origin: NodeId) -> Option<[u8; 16]> {
        self.remote
            .get(&origin)
            .map(|entries| digest_entries(entries.iter()))
    }

    pub fn all_entries(&self) -> Vec<(&Name, &NameEntry)> {
        self.local
            .iter()
            .map(|(name, entry)| (name, &entry.entry))
            .collect()
    }

    pub fn resolved_entries(&self) -> BTreeMap<Name, NameEntry> {
        let mut names = BTreeMap::<Name, NameEntry>::new();
        for entries in self.remote.values() {
            for (name, entry) in entries {
                match names.get(name) {
                    Some(current) if !wins(entry, current) => {}
                    _ => {
                        names.insert(name.clone(), entry.clone());
                    }
                }
            }
        }
        for (name, entry) in &self.local {
            names.insert(name.clone(), entry.entry.clone());
        }
        names
    }
}

fn digest_entries<'a>(entries: impl Iterator<Item = (&'a Name, &'a NameEntry)>) -> [u8; 16] {
    let mut hasher = Sha256::new();
    for (name, entry) in entries {
        hasher.update(name.to_lowercase().to_string().as_bytes());
        hasher.update(entry.priority.to_be_bytes());
        hasher.update(entry.version.to_be_bytes());
        hasher.update(entry.ttl.to_be_bytes());
        for record in &entry.records {
            hasher.update([u16::from(record.rtype) as u8]);
            hasher.update(format!("{:?}", record.data).as_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn wins(a: &NameEntry, b: &NameEntry) -> bool {
    a.priority > b.priority
        || (a.priority == b.priority && a.version > b.version)
        || (a.priority == b.priority && a.version == b.version && a.owner < b.owner)
}

#[derive(Clone, Debug)]
pub enum ResolveOutcome {
    Found(NameEntry),
    NoData,
    NxDomain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn zone() -> Name {
        Name::from_str("namae.").unwrap()
    }

    fn entry(owner: NodeId, version: u64, ip: &str) -> NameEntry {
        NameEntry {
            owner,
            priority: 100,
            version,
            ttl: 60,
            rdns: true,
            records: vec![RrData {
                rtype: RecordType::A,
                data: RecordData::A(ip.parse().unwrap()),
            }],
        }
    }

    #[test]
    fn local_beats_remote() {
        let mut store = Store::new(zone(), 1, 10);
        let name = Name::from_str("a.namae.").unwrap();
        store
            .apply_snapshot(
                2,
                1,
                1,
                vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
                vec![],
            )
            .is_applied();
        let records = vec![ResolvedRecord {
            name: name.clone(),
            rtype: RecordType::A,
            target: RecordTarget::Value(RecordData::A("10.0.0.1".parse().unwrap())),
            ttl: Some(60),
            priority: 100,
            publish: false,
            rdns: true,
        }];
        store
            .set_local_records(&records, &HashMap::new(), 60)
            .unwrap();
        let resolved = store.resolve(&name).unwrap();
        assert_eq!(resolved.owner, 1);
    }

    #[test]
    fn conflict_prefers_priority_then_version_then_low_owner() {
        let mut store = Store::new(zone(), 1, 10);
        let name = Name::from_str("a.namae.").unwrap();
        store
            .apply_snapshot(
                3,
                1,
                1,
                vec![(name.clone(), entry(3, 10, "10.0.0.3"))],
                vec![],
            )
            .is_applied();
        store
            .apply_snapshot(
                2,
                1,
                1,
                vec![(name.clone(), entry(2, 10, "10.0.0.2"))],
                vec![],
            )
            .is_applied();
        assert_eq!(store.resolve(&name).unwrap().owner, 2);
        let mut higher = entry(3, 11, "10.0.0.3");
        higher.priority = 200;
        store
            .apply_snapshot(3, 1, 2, vec![(name.clone(), higher)], vec![])
            .is_applied();
        assert_eq!(store.resolve(&name).unwrap().owner, 3);
    }

    #[test]
    fn delta_requires_consecutive_seq() {
        let mut store = Store::new(zone(), 1, 10);
        let name = Name::from_str("a.namae.").unwrap();
        store
            .apply_snapshot(
                2,
                1,
                1,
                vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
                vec![],
            )
            .is_applied();
        assert!(matches!(
            store.apply_delta(2, 1, 3, vec![(name, entry(2, 3, "10.0.0.3"))], vec![]),
            ApplyResult::Gap
        ));
    }

    #[test]
    fn new_session_replaces_old_entries() {
        let mut store = Store::new(zone(), 1, 10);
        let name = Name::from_str("a.namae.").unwrap();
        store
            .apply_snapshot(
                2,
                1,
                1,
                vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
                vec![],
            )
            .is_applied();
        store.apply_snapshot(2, 2, 1, vec![], vec![]).is_applied();
        assert!(store.resolve(&name).is_none());
    }

    #[test]
    fn heartbeat_then_snapshot_at_same_seq_applies() {
        let mut store = Store::new(zone(), 1, 10);
        let name = Name::from_str("a.namae.").unwrap();
        store.heartbeat(2, 1, 5, [0u8; 16]);
        let result = store.apply_snapshot(
            2,
            1,
            5,
            vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
            vec![],
        );
        assert!(matches!(result, ApplyResult::Applied { changed: true }));
        assert!(store.resolve(&name).is_some());
    }

    #[test]
    fn stale_local_versions_are_pruned() {
        let mut store = Store::new(zone(), 1, 1);
        let names = ["a.namae.", "b.namae."];
        for name in names {
            store
                .set_local_records(
                    &[ResolvedRecord {
                        name: Name::from_str(name).unwrap(),
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
        }
        store
            .set_local_records(
                &[ResolvedRecord {
                    name: Name::from_str("a.namae.").unwrap(),
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
        store.expire(Duration::ZERO, Duration::ZERO);
        assert!(
            store
                .versions
                .contains_key(&Name::from_str("a.namae.").unwrap())
        );
        assert!(
            !store
                .versions
                .contains_key(&Name::from_str("b.namae.").unwrap())
        );
    }

    #[test]
    fn new_session_drops_stale_tombstones() {
        let mut store = Store::new(zone(), 1, 1);
        let name = Name::from_str("a.namae.").unwrap();
        store
            .apply_snapshot(
                2,
                1,
                1,
                vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
                vec![],
            )
            .is_applied();
        store
            .apply_delta(2, 1, 2, vec![], vec![(name.clone(), 2)])
            .is_applied();
        assert!(store.resolve(&name).is_none());
        store
            .apply_snapshot(
                2,
                2,
                1,
                vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
                vec![],
            )
            .is_applied();
        assert!(store.resolve(&name).is_some());
        let (_, _, _, tombstones) = store.snapshot_for(2).unwrap();
        assert!(!tombstones.iter().any(|(tombstone, _)| tombstone == &name));
    }

    #[test]
    fn relayed_snapshot_does_not_revive_expired_origin() {
        let mut store = Store::new(zone(), 1, 1);
        let name = Name::from_str("a.namae.").unwrap();
        store
            .apply_snapshot(
                2,
                1,
                1,
                vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
                vec![],
            )
            .is_applied();
        std::thread::sleep(Duration::from_millis(5));
        store.expire(Duration::from_millis(1), Duration::from_secs(30));
        assert!(store.resolve(&name).is_none());
        let result = store.apply_snapshot_from(
            2,
            1,
            2,
            vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
            vec![],
            false,
        );
        assert!(matches!(result, ApplyResult::Stale));
        assert!(store.resolve(&name).is_none());
        store
            .apply_snapshot_from(
                2,
                1,
                3,
                vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
                vec![],
                true,
            )
            .is_applied();
        assert!(store.resolve(&name).is_some());
    }

    #[test]
    fn stale_session_relayed_snapshot_is_ignored() {
        let mut store = Store::new(zone(), 1, 1);
        let name = Name::from_str("a.namae.").unwrap();
        store
            .apply_snapshot_from(
                2,
                1,
                1,
                vec![(name.clone(), entry(2, 1, "10.0.0.1"))],
                vec![],
                true,
            )
            .is_applied();
        store
            .apply_snapshot_from(
                2,
                2,
                1,
                vec![(name.clone(), entry(2, 1, "10.0.0.2"))],
                vec![],
                true,
            )
            .is_applied();
        let result = store.apply_snapshot_from(
            2,
            1,
            2,
            vec![(name.clone(), entry(2, 1, "10.0.0.3"))],
            vec![],
            false,
        );
        assert!(matches!(result, ApplyResult::Stale));
        assert_eq!(
            store.resolve(&name).unwrap().records[0].data,
            RecordData::A("10.0.0.2".parse().unwrap())
        );
    }

    #[test]
    fn new_owner_wins_after_old_origin_expires() {
        let mut store = Store::new(zone(), 1, 1);
        let name = Name::from_str("a.namae.").unwrap();
        store
            .apply_snapshot(
                2,
                1,
                1,
                vec![(name.clone(), entry(2, 5, "10.0.0.1"))],
                vec![],
            )
            .is_applied();
        std::thread::sleep(Duration::from_millis(5));
        store.expire(Duration::from_millis(1), Duration::from_secs(30));
        assert!(store.resolve(&name).is_none());
        store
            .apply_snapshot(
                3,
                1,
                1,
                vec![(name.clone(), entry(3, 1, "10.0.0.2"))],
                vec![],
            )
            .is_applied();
        assert_eq!(
            store.resolve(&name).unwrap().records[0].data,
            RecordData::A("10.0.0.2".parse().unwrap())
        );
    }

    trait ApplyExt {
        fn is_applied(&self);
    }

    impl ApplyExt for ApplyResult {
        fn is_applied(&self) {
            assert!(matches!(self, ApplyResult::Applied { .. }));
        }
    }
}
