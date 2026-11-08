# design notes

## Goals

- 去中心化：没有中心 registry；每个节点都能发布和解析记录。
- 低运维：一个二进制、一个 TOML 主配置、一个 drop-in 目录。
- 可增量部署：可以先只跑本地 DNS，再逐步加 peer。

## Key decisions

### 独立于 cryonet

`namae` 只复用 cryonet registry 的思路：

- 每个 origin 有 session/seq；
- 冲突用 deterministic claim/tie-break；
- fanout + hop limit + 周期 anti-entropy。

它不依赖 cryonet 的 mesh、UAPI 或 crypto。peer 发现只依赖系统路由表和手动 seed。

### 无持久化

- 不写 node-id、不缓存远端记录、不持久化 tombstone。
- 启动后从 peer 拉 snapshot。
- 重启产生新 session；旧 origin 在 `origin_timeout` 后过期。
- 需要稳定身份时在配置里固定 `id`。

### 部分 mesh

不要求 full mesh：

- heartbeat 携带 seq/digest，按 hop limit 转发；
- 只有严格更新的 seq 才刷新 lease；
- snapshot 应用后会继续转发；
- 每 60 秒 digest anti-entropy。

### 记录模型

- `[[records]]` 同时覆盖静态值和 `from_interface` 动态值，不再区分 policy。
- 本地静态记录优先于远端记录；`publish=false` 不进入 gossip。
- 同一个名字选一个 winner：`priority` → `version` → `owner`（小者胜）。

### DNS

- 只做权威回答，不做递归/转发。
- 非 zone 查询返回 `REFUSED`。
- 不接 systemd-resolved/NSS/resolv.conf；这些是使用方的事情。

### 安全

- v1 是 shared secret HMAC 俱乐部模型。
- HMAC 认证成员，不区分具体节点；成员可以伪造名字。
- 不加密 gossip 内容。
- 需要防成员作恶时，后续加 Ed25519 per-node 签名。

## Non-goals

- L2/广播/组播发现。
- full mesh 保证。
- DNSSEC。
- 状态持久化/审计/CRL。
- NixOS module 或系统解析器集成。
- Windows/macOS/wasm。

## Failure behavior

- netlink monitor 不可用：启动失败。
- 配置非法：启动失败；reload 时保留旧配置。
- gossip 握手失败：关闭连接并计数；稍后重连。
- 对端长时间无 heartbeat：origin 记录过期。
- `zone`/`dns_listen`/`port`/`id` 变更：reload 拒绝或提示重启。
