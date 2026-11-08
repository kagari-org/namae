# namae gossip protocol v1

gossip 是 namae 的内部同步协议。它不面向公网，也不是 DNS 协议本身。

## Transport

- TCP，默认端口 `7654`。
- 握手完成后，每一帧都是长度前缀 + HMAC-SHA256。
- 帧编码是 JSON；`namae/1` 是当前版本。
- 单帧最大 1 MiB。

## Handshake

```text
C -> S: ClientHello { v, node_id_c, nonce_c[32] }
S -> C: ServerHello { v, node_id_s, nonce_s[32],
                      mac_s = HMAC(secret, "namae/1 server" || nonce_c || nonce_s || id_c || id_s) }
C -> S: ClientAuth  { mac_c = HMAC(secret, "namae/1 client" || nonce_c || nonce_s || id_c || id_s) }
```

- 双方验证 MAC 后，用 HKDF-SHA256 派生每方向密钥：
  - `k_c2s = HKDF(secret, salt = nonce_c || nonce_s, info = "namae/1 c2s")`
  - `k_s2c = HKDF(secret, salt = nonce_c || nonce_s, info = "namae/1 s2c")`
- 握手 5 秒超时；握手帧最大 4 KiB。
- 错误 secret、MAC 错误、重放都会关闭连接。

## Frame

```text
magic "NM" | v u8 | kind u8 | seq u64 | len u32 | body | mac[32]
```

- `mac = HMAC(k_dir, header || body)`。
- `seq` 每方向严格递增；接收端拒绝 `seq <= last_seq`。
- `kind`：
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

- `total > 1` 时按 `(origin, session, seq)` 组装；每 chunk 最多 128 条。
- 接收方用完整 snapshot 替换该 origin 的当前状态。
- 应用成功且内容变化后，会继续转发给其他 peer。

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

- `seq` 必须是已知 seq + 1；否则请求 snapshot。
- `hops > 0` 时继续转发，`hops - 1`；fanout 最多 4。

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

- 每 `announce_interval` 发一次。
- `seq` 严格更新才刷新 `last_seen`；重复/旧 heartbeat 不刷新。
- `digest` 不匹配时向发送者请求 snapshot。
- 超过 `origin_timeout` 没有更新，该 origin 的记录过期。

### Digest

```json
{
  "entries": [
    { "origin": 123, "session": 456, "seq": 9 }
  ]
}
```

- 用于 anti-entropy；收到后比较本地状态：
  - 本地缺失/落后 → `SyncRequest`；
  - 本地更新 → 发送 snapshot。
- 启动/连接建立时发送一次；之后每 60 秒随机 peer 一次。

### SyncRequest

```json
{ "origins": [123, 456] }
```

- 请求指定 origin 的完整 snapshot。

### Ping / Pong

```json
{ "nonce": 123 }
```

- 保留的保活/诊断消息。

## State and conflict

```text
NameEntry {
  owner: u64,
  priority: u16,
  version: u64,
  ttl: u32,
  records: [(RecordType, RData)],
}
```

- 每个 origin 维护自己的 session/seq。
- 同一个 name 的远端冲突：
  1. `priority` 高者胜；
  2. `version` 高者胜；
  3. `owner` 小者胜。
- 本地静态记录优先于远端记录。
- 删除写 tombstone；低版本不能覆盖 tombstone。
- 无持久化：重启产生新 session；旧 origin 在 `origin_timeout` 后过期。

## Limits

- 单帧 1 MiB；snapshot 最多 1024 chunks；每 chunk 128 条记录。
- 每个 peer 的发送队列 256 帧；满则丢弃并计数。
- 握手 5 秒超时；连接建立后 5 秒内完成握手。
