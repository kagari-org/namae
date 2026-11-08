# Design notes

## Goals

- **Decentralized:** no central registry; every node can publish and resolve records.
- **Low operational overhead:** one binary, one main TOML file, one drop-in directory.
- **Incremental deployment:** a node can start with local DNS only and add peers later.

## Key decisions

### Independent of cryonet

`namae` borrows only the registry ideas from cryonet:

- each origin has a session and sequence number;
- conflicts are resolved with a deterministic claim/tie-break;
- fanout, hop limits, and periodic anti-entropy.

It does not depend on cryonet's mesh, UAPI, or crypto. Peer discovery relies only on the system routing table and manual seeds.

### No persistence

- No node-id file, no cached remote records, no persisted tombstones.
- A node pulls snapshots from peers after startup.
- A restart creates a new session; records from the old origin expire after `origin_timeout`.
- Set `id` explicitly when a stable identity is needed.

### Partial mesh

A full mesh is not required:

- heartbeats carry sequence numbers and digests and are forwarded with a hop limit;
- only a strictly newer sequence number refreshes a lease;
- applied snapshots are forwarded to other peers;
- digest anti-entropy runs every 60 seconds.

### Record model

- `[[records]]` covers both static values and dynamic `from_interface` values; there is no separate policy type.
- Local static records take precedence over remote records; `publish = false` stays local and is not gossiped.
- One winner is selected per name: `priority`, then `version`, then the lower `owner`.

### DNS

- Authoritative answers only; no recursion or forwarding.
- Queries outside the zone return `REFUSED`.
- A process has one forward `zone`; `reverse_zones` are auxiliary and do not add a second forward zone.
- A/AAAA records are also synthesized as PTR records under matching reverse zones. CNAME chains, ANY, wildcards, and SOA negative TTL are supported.
- No systemd-resolved, NSS, or resolv.conf integration; that is left to the operator.

### Security

- v1 uses a shared-secret HMAC club model.
- HMAC authenticates membership, not individual nodes; any member can forge names.
- Gossip frames are authenticated but not encrypted.
- Per-node Ed25519 signatures are the path for protecting against malicious members.

## Non-goals

- L2, broadcast, or multicast discovery.
- A full-mesh guarantee.
- DNSSEC.
- State persistence, auditing, or CRLs.
- A NixOS module or system resolver integration.
- Windows, macOS, or wasm.

## Failure behavior

- Netlink monitor unavailable: startup fails.
- Invalid configuration: startup fails; reload keeps the previous configuration.
- Gossip handshake failure: close the connection, count it, retry later.
- No heartbeat from a peer for too long: the origin's records expire.
- Changes to `zone`, `dns_listen`, `reverse_zones`, `port`, or `id`: reload rejects the change or asks for a restart.
