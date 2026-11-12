# namae gossip protocol v1

Gossip is `namae`'s internal synchronization protocol. It is not exposed to the public internet and is not the DNS protocol itself.

## Transport

- TCP, default port `7654`.
- After the handshake, every frame is length-prefixed and authenticated with HMAC-SHA256.
- Frames are encoded as JSON; `namae/1` is the current version.
- Maximum frame size is 1 MiB.

## Handshake

```text
C -> S: ClientHello { v, node_id_c, listen_port_c, nonce_c[32] }
S -> C: ServerHello { v, node_id_s, listen_port_s, nonce_s[32],
                      mac_s = HMAC(secret, "namae/1 server" || nonce_c || nonce_s || id_c || port_c || id_s || port_s) }
C -> S: ClientAuth  { mac_c = HMAC(secret, "namae/1 client" || nonce_c || nonce_s || id_c || port_c || id_s || port_s) }
```

- After both sides verify the MAC, HKDF-SHA256 derives one key per direction:
  - `k_c2s = HKDF(secret, salt = nonce_c || nonce_s, info = "namae/1 c2s")`
  - `k_s2c = HKDF(secret, salt = nonce_c || nonce_s, info = "namae/1 s2c")`
- Handshake timeout is 5 seconds; handshake frames are limited to 4 KiB.
- `listen_port` lets the receiver turn an inbound TCP connection's ephemeral source port into the peer's gossip listen address.
- For each pair, the lower node ID initiates; the higher ID accepts. A non-preferred inbound connection is closed, and the lower-ID node learns the peer address and initiates its own connection.
- A wrong secret, a bad MAC, or a replay closes the connection.

## Frame

```text
magic "NM" | v u8 | kind u8 | seq u64 | len u32 | body | mac[32]
```

- `mac = HMAC(k_dir, header || body)`.
- `seq` strictly increases in each direction; the receiver rejects `seq <= last_seq`.
- `kind`:
  - 1 `Snapshot`
  - 2 `Delta`
  - 3 `Heartbeat`
  - 4 `Digest`
  - 5 `SyncRequest`
  - 6 `Ping`
  - 7 `Pong`

## Messages

### Snapshot

```json
{
  "origin": 123,
  "session": 456,
  "seq": 7,
  "chunk": 0,
  "total": 1,
  "entries": [
    {
      "name": "router.namae.",
      "priority": 100,
      "version": 3,
      "ttl": 300,
      "rdns": true,
      "records": [
        { "rtype": "A", "value": "10.0.0.1" }
      ]
    }
  ],
  "tombstones": [
    { "name": "old.namae.", "version": 4 }
  ]
}
```

- When `total > 1`, chunks are assembled by `(origin, session, seq)`; each chunk holds at most 128 entries.
- A complete snapshot replaces the current state for that origin.
- After a successful apply that changes state, the snapshot is forwarded to other peers.

### Delta

```json
{
  "origin": 123,
  "session": 456,
  "seq": 8,
  "upserts": [ ... ],
  "deletes": [ { "name": "old.namae.", "version": 5 } ],
  "hops": 6
}
```

- `seq` must be the known sequence number plus one; otherwise the receiver requests a snapshot.
- When `hops > 0`, the delta is forwarded with `hops - 1`; fanout is at most 4.

### Heartbeat

```json
{
  "origin": 123,
  "session": 456,
  "seq": 9,
  "digest": [0, 1, 2, ...],
  "hops": 6
}
```

- Sent every `announce_interval`.
- Only a strictly newer `seq` refreshes `last_seen`; duplicate or old heartbeats do not.
- A digest mismatch causes the receiver to request a snapshot from the sender.
- If no update arrives within `origin_timeout`, the origin's records expire.
- Only heartbeats, deltas, and direct snapshots from the origin refresh its lease. Relayed snapshots repair state without extending the lease, and expired origins are remembered for `tombstone_ttl` to prevent relayed snapshots from reviving them.
- A relayed snapshot with a different session is rejected; a new session must be established by a heartbeat or a direct origin snapshot first.

### Digest

```json
{
  "entries": [
    { "origin": 123, "session": 456, "seq": 9 }
  ]
}
```

- Used for anti-entropy. On receipt, the local state is compared:
  - local state missing or behind: send `SyncRequest`;
  - local state ahead: send a snapshot.
- Sent once on startup or connection establishment, then to a random peer every 60 seconds.

### SyncRequest

```json
{ "origins": [123, 456] }
```

- Requests a complete snapshot for the specified origins.

### Ping / Pong

```json
{ "nonce": 123 }
```

- Reserved keepalive and diagnostic messages.

## State and conflict

```text
NameEntry {
  owner: u64,
  priority: u16,
  version: u64,
  ttl: u32,
  rdns: bool,
  records: [(RecordType, RData)],
}
```

- Each origin maintains its own session and sequence number.
- Remote conflicts for the same name are resolved by:
  1. higher `priority`;
  2. higher `version`;
  3. lower `owner`.
- Local static records take precedence over remote records.
- Deletes are written as tombstones; an older version cannot overwrite a tombstone.
- No persistence: a restart creates a new session; records from the old origin expire after `origin_timeout`.

## Limits

- Maximum frame size is 1 MiB; a snapshot has at most 1024 chunks; each chunk holds at most 128 records.
- Each peer has a 256-frame send queue; a full queue drops frames and increments a counter.
- Handshake timeout is 5 seconds; the handshake must complete within 5 seconds of connecting.
