#!/usr/bin/env bash
set -euo pipefail

if [ "${NAMAE_NETNS_INNER:-0}" != "1" ]; then
    exec env NAMAE_NETNS_INNER=1 unshare -Urnm bash -c '
        set -e
        ipdir=$(dirname "$(readlink -f "$(command -v ip)")")
        resolv=$(mktemp /tmp/namae-resolv.XXXXXX)
        printf "nameserver 127.0.0.1\n" > "$resolv"
        mount --bind "$resolv" /etc/resolv.conf
        rm -f "$resolv"
        mount -t tmpfs tmpfs /run
        mkdir -p /run/netns
        PATH="$ipdir:$PATH"
        export PATH
        exec "$@"
    ' _ "$0" "$@"
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${NAMAE_BIN:-$ROOT/target/debug/namae}
DIG=${DIG:-$(command -v dig || true)}
TMP=$(mktemp -d "$ROOT/target/namae-dualstack.XXXXXX")
N1="namae-dualstack-$$-1"
N2="namae-dualstack-$$-2"
PIDS=()

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    for ns in "$N1" "$N2"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $*" >&2
    for ns in 1 2; do
        echo "--- n$ns log ---" >&2
        cat "$TMP/n$ns.log" 2>/dev/null >&2 || true
    done
    exit 1
}

[ -x "$BIN" ] || fail "missing $BIN; run cargo build first"
[ -n "$DIG" ] || fail "missing dig; set DIG=/path/to/dig"

ip netns add "$N1"
ip netns add "$N2"
ip link add v1 type veth peer name v2
ip link set v1 netns "$N1"
ip link set v2 netns "$N2"
ip -n "$N1" link set lo up
ip -n "$N1" link set v1 up
ip -n "$N2" link set lo up
ip -n "$N2" link set v2 up
ip -n "$N1" -6 addr add fd00::1/64 dev v1 nodad
ip -n "$N1" addr add 10.200.0.1/24 dev v1
ip -n "$N1" addr add 10.200.1.1/24 dev v1
ip -n "$N2" addr add 10.200.0.2/24 dev v2
ip -n "$N2" addr add 10.200.1.2/24 dev v2
ip -n "$N2" -6 addr add fd00::2/64 dev v2 nodad
ip -n "$N1" -6 route add fd00::2/128 proto bird dev v1
ip -n "$N1" route add 10.200.0.2/32 proto bird dev v1
ip -n "$N1" route add 10.200.1.2/32 proto bird dev v1
ip -n "$N2" -6 route add fd00::1/128 proto bird dev v2
ip -n "$N2" route add 10.200.0.1/32 proto bird dev v2
ip -n "$N2" route add 10.200.1.1/32 proto bird dev v2

write_config() {
    local path=$1 name=$2 v4=$3 v6=$4
    mkdir -p "$path.d"
    cat > "$path" <<CONFIG
zone = "namae."
dns_listen = ["127.0.0.1:15353"]
port = 17664
secret = "netns-dualstack"
proto = "bird"
announce_interval = "1s"
origin_timeout = "10s"

[[records]]
name = "$name"
type = "A"
value = "$v4"
publish = true

[[records]]
name = "$name"
type = "AAAA"
value = "$v6"
publish = true
CONFIG
}

write_config "$TMP/n1.toml" "n1.namae." "10.0.0.1" "fd00::1"
write_config "$TMP/n2.toml" "n2.namae." "10.0.0.2" "fd00::2"

start_node() {
    local ns=$1 n=$2
    ip netns exec "$ns" "$BIN" daemon \
        --config "$TMP/n$n.toml" --config-dir "$TMP/n$n.toml.d" \
        --ctl-path "$TMP/n$n.sock" >"$TMP/n$n.log" 2>&1 &
    PIDS+=("$!")
}

start_node "$N1" 1
start_node "$N2" 2
for n in 1 2; do
    for _ in $(seq 1 50); do
        [ -S "$TMP/n$n.sock" ] && break
        sleep 0.1
    done
    [ -S "$TMP/n$n.sock" ] || fail "node n$n did not start"
done

resolve() {
    local ns=$1 name=$2 rtype=$3
    ip netns exec "$ns" "$DIG" @127.0.0.1 -p 15353 +short +time=1 +tries=1 "$name" "$rtype" 2>/dev/null || true
}

for _ in $(seq 1 100); do
    [ "$(resolve "$N1" "n2.namae." A)" = "10.0.0.2" ] && break
    sleep 0.1
done
[ "$(resolve "$N1" "n2.namae." A)" = "10.0.0.2" ] || fail "n1 did not resolve n2 over IPv4"
[ "$(resolve "$N1" "n2.namae." AAAA)" = "fd00::2" ] || fail "n1 did not resolve n2 over IPv6"

peers=$("$BIN" ctl --socket "$TMP/n1.sock" peers 2>/dev/null || true)
[ "$(grep -c '"node_id"' <<<"$peers")" -eq 1 ] || fail "expected exactly one peer, got: $peers"
grep -Eq '10.200.(0|1).2' <<<"$peers" || fail "IPv4 connection was not preferred: $peers"
sleep 5
peers=$("$BIN" ctl --socket "$TMP/n1.sock" peers 2>/dev/null || true)
[ "$(grep -c '"node_id"' <<<"$peers")" -eq 1 ] || fail "peer flapped after 5s: $peers"
grep -Eq '10.200.(0|1).2' <<<"$peers" || fail "peer moved off IPv4: $peers"

echo "PASS: netns dual-stack discovery and gossip"
