# namae

A decentralized DNS service for routed networks.

`namae` lets each node publish its own `name → address` records, discover peers from the system routing table, and synchronize records over a gossip protocol. Every node serves an authoritative DNS zone locally, so names remain resolvable without a central registry or a dedicated DNS server.

```
records ──────────────► local DNS server ──────────────► clients
   │
   └──► gossip ◄──► peers
            ▲
            │
   BIRD routes / manual seeds
```

## Features

- **No central registry** — every node owns its records and serves them locally.
- **Route-driven peer discovery** — reads `proto bird` host routes from netlink; IPv4 `/32` and IPv6 `/128` routes become peers.
- **Works with partial connectivity** — heartbeat, delta, and digest anti-entropy keep records moving across multiple hops; a full mesh is not required.
- **Authoritative local DNS** — serves `A`, `AAAA`, `CNAME`, `TXT`, wildcard, and synthesized `PTR` records for a private zone.
- **Reloadable configuration** — a main TOML file plus a drop-in directory.
- **Stateless by design** — no record database, no node-id file; a restarted node resynchronizes from its peers.
- **Authenticated gossip** — HMAC-SHA256 handshake and per-frame authentication with a shared secret.
- **Small operational surface** — one daemon, one control socket, no external database.

## Getting started

### Build

```sh
nix develop
cargo build --release
```

Or, with a Rust toolchain already available:

```sh
cargo build --release
```

### Configure

Main configuration lives in `/etc/namae.toml`:

```toml
zone = "namae."
# reverse_zones = ["10.in-addr.arpa."]
dns_listen = ["127.0.0.1:15353"]
port = 7654
secret = "change-me"

proto = "bird"
seeds = ["10.0.0.2:7654"]

default_ttl = 60
negative_ttl = 30
```

Additional record files live in `/etc/namae.d/*.toml`. They may only contain `[[records]]`:

```toml
[[records]]
name = "router"
type = "A"
value = "10.0.0.1"
ttl = 300

[[records]]
name = "host.namae."
type = "AAAA"
from_interface = "eth0"
ttl = 60
```

### Run

```sh
namae daemon --config /etc/namae.toml --config-dir /etc/namae.d
```

### Query

```sh
dig @127.0.0.1 -p 15353 router.namae A
dig @127.0.0.1 -p 15353 router.namae AAAA
```

`namae` provides the DNS service only. Wiring it into the system resolver is left to the operator.

## Configuration

All options are top-level. `zone` is required.

| Option | Default | Description |
|---|---|---|
| `zone` | required | Authoritative forward zone, e.g. `namae.` |
| `reverse_zones` | `[]` | Auxiliary reverse zones for PTR, e.g. `["10.in-addr.arpa."]` |
| `dns_listen` | `["127.0.0.1:15353"]` | DNS UDP/TCP listen addresses |
| `port` | `7654` | Gossip listen/connect port |
| `secret` / `secret_file` | at least one | Shared HMAC secret; mutually exclusive |
| `seeds` | `[]` | Manual peers, e.g. `"10.0.0.2:7654"` |
| `proto` | `"bird"` | Route protocol filter: `bird`, `static`, `babel`, `ospf`, `any`, or a number |
| `id` | random | Node ID; set explicitly for a stable identity |
| `default_ttl` | `60` | Default record TTL |
| `negative_ttl` | `30` | SOA negative TTL |
| `announce_interval` | `"30s"` | Heartbeat interval |
| `origin_timeout` | `"90s"` | Record lease timeout |
| `tombstone_ttl` | `"1h"` | How long deletions are remembered |

## Records

```toml
[[records]]
name = "router.namae."
type = "A"                # A | AAAA | CNAME | TXT
value = "10.0.0.1"        # mutually exclusive with from_interface
ttl = 300                 # optional
priority = 100            # optional; used for conflict resolution
publish = true            # optional; default true
```

- A single-label name is expanded under `zone`; dotted names are treated as FQDNs.
- A leading `*.` creates a wildcard record (e.g. `*.namae.`).
- `from_interface` is only valid for `A` and `AAAA`. It publishes every address of the matching family on that interface, skipping link-local, tentative, DADFAILED, and loopback addresses.
- A name must use one `publish` value and one `priority` value across its records.
- `publish = false` keeps a record local; it is not gossiped.

## How it works

### Peer discovery

At startup, `namae` dumps the routing table and subscribes to netlink route updates. It considers a route a peer if:

- its protocol matches `proto` (default `bird`, protocol 12);
- it is a unicast route in the main table;
- it is an IPv4 `/32` or an IPv6 `/128`.

The destination address becomes the peer address; for IPv6, `RTA_OIF` supplies the scope ID. Manual `seeds` are always merged in, and local addresses are excluded. Route monitoring is required; if netlink monitor is unavailable, `namae` exits instead of silently falling back to polling. Failed connection attempts use exponential backoff from 1 second to 60 seconds with jitter, so routes that do not run `namae` are probed only occasionally; a successful connection resets the backoff.

### Gossip

Peers authenticate with HMAC-SHA256 and exchange state over TCP. Each node has a session ID and a monotonic sequence number.

- Changes are sent as `Delta` messages and forwarded with a hop limit.
- Periodic `Heartbeat` messages refresh a peer's lease and carry a digest of its records.
- `Digest` messages provide anti-entropy, repairing missed updates with full snapshots.
- Relayed snapshots repair records but do not refresh the origin's lease; only heartbeats, deltas, or direct origin snapshots do. Expired origins are remembered for `tombstone_ttl` so relayed snapshots cannot resurrect them.
- Deletions are represented by tombstones.

Records from different origins use a deterministic conflict rule: higher `priority`, then higher `version`, then lower owner ID. Local static records win locally.

### DNS

`zone` is authoritative and served over UDP and TCP. `reverse_zones` add auxiliary reverse authorities for PTR lookups.

- Name exists, queried type does not: `NOERROR/NODATA` with SOA.
- Name does not exist: `NXDOMAIN` with SOA.
- Outside the zone: `REFUSED`.
- `AXFR`, `IXFR`, and `NOTIFY`: `REFUSED`.
- A/AAAA records are also published as PTR records under a matching configured `reverse_zones` entry.

EDNS0, UDP truncation, and TCP fallback are handled by the DNS server.

## Control

```sh
namae ctl stats
namae ctl peers
namae ctl records [filter]
namae ctl conflicts
namae ctl resolve router.namae --type A
namae ctl reload
namae ctl sync
```

The default control socket is `/run/namae/ctl.sock`; override it with `--socket`.

## Reload

The daemon does not watch files. After changing the main config, a drop-in, or `secret_file`, run `namae ctl reload` or send `SIGHUP`.

- Valid configuration is swapped atomically.
- Invalid configuration is rejected and the previous one stays active.
- Records, seeds, TTLs, and intervals reload without a restart.
- Changing `zone`, `dns_listen`, `reverse_zones`, `port`, or `id` requires a restart.
- Changing the secret closes existing gossip connections and reconnects with the new key.

## Security model

`namae` uses a shared-secret trust model:

- HMAC proves knowledge of the secret, not the identity of an individual node.
- Any member holding the secret can publish or forge any name.
- Gossip frames are authenticated but not encrypted.

This is appropriate for a small, trusted network. It is not a replacement for per-node signatures, DNSSEC, or an untrusted multi-tenant deployment.

## Limitations

- Linux only.
- No persistence: records, peers, and tombstones live in memory. A node with a random `id` gets a new origin after restart; old records expire after `origin_timeout`.
- No L2, broadcast, or multicast discovery.
- No recursive resolution or forwarding.
- One forward `zone` per process; `reverse_zones` are auxiliary and do not add a second forward zone.
- No DNSSEC.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

An end-to-end namespace test is available:

```sh
cargo build
DIG=$(command -v dig) ./tests/netns_e2e.sh
DIG=$(command -v dig) TC=$(command -v tc) ./tests/netns_chaos.sh
DIG=$(command -v dig) TC=$(command -v tc) ./tests/netns_scale.sh
DIG=$(command -v dig) ./tests/netns_mem.sh
./tests/netns_backoff.sh
```

`netns_e2e.sh` covers a three-node partial mesh, PTR, and route flap. `netns_chaos.sh` covers a four-node ring, partition and heal, 10% packet loss on both links of a node, node offline record expiry, and restart/resync. `netns_scale.sh` covers a six-node ring with a chord, split-brain partition, node loss/restart, packet loss on both links of a node, explicit reload, and delete propagation. `netns_mem.sh` repeatedly restarts nodes, flaps routes, and explicitly reloads unique records while checking RSS, thread count, and file descriptors. `netns_backoff.sh` verifies that a route without `namae` is retried with increasing delays and stops retrying when the route is removed.

## Documentation

- [Protocol](docs/protocol.md)
- [Design notes](docs/design.md)
