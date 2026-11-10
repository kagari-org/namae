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
TMP=$(mktemp -d "$ROOT/target/namae-ipv6.XXXXXX")
N1="namae-ipv6-$$-1"
N2="namae-ipv6-$$-2"
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
ip -n "$N2" -6 addr add fd00::2/64 dev v2 nodad
ip -n "$N1" -6 route add fd00::2/128 proto bird dev v1
ip -n "$N2" -6 route add fd00::1/128 proto bird dev v2

write_config() {
    local path=$1 name=$2 record=$3
    mkdir -p "$path.d"
    cat > "$path" <<CONFIG
zone = "namae."
dns_listen = ["127.0.0.1:15353"]
port = 17663
secret = "netns-ipv6"
proto = "bird"
announce_interval = "1s"
origin_timeout = "10s"

[[records]]
name = "$name"
type = "AAAA"
value = "$record"
publish = true
CONFIG
}

write_config "$TMP/n1.toml" "n1.namae." "fd00::1"
write_config "$TMP/n2.toml" "n2.namae." "fd00::2"

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
    local ns=$1 name=$2
    ip netns exec "$ns" "$DIG" @127.0.0.1 -p 15353 +short +time=1 +tries=1 "$name" AAAA 2>/dev/null || true
}

for _ in $(seq 1 100); do
    [ "$(resolve "$N1" "n2.namae.")" = "fd00::2" ] && break
    sleep 0.1
done
[ "$(resolve "$N1" "n2.namae.")" = "fd00::2" ] || fail "n1 did not resolve n2 over IPv6"
if ! "$BIN" ctl --socket "$TMP/n1.sock" peers 2>/dev/null | grep -q 'fd00::2'; then
    fail "n1 did not discover the IPv6 peer"
fi

echo "PASS: netns IPv6 route discovery and gossip"
