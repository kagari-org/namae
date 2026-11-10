#!/usr/bin/env bash
set -euo pipefail

if [ "${NAMAE_NETNS_INNER:-0}" != "1" ]; then
    exec env NAMAE_NETNS_INNER=1 unshare -Urnm bash -c '
        set -e
        ipdir=$(dirname "$(readlink -f "$(command -v ip)")")
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
TMP=$(mktemp -d "$ROOT/target/namae-netns.XXXXXX")
N1="namae-e2e-$$-1"
N2="namae-e2e-$$-2"
N3="namae-e2e-$$-3"
PIDS=()

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    for ns in "$N1" "$N2" "$N3"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $*" >&2
    for ns in 1 2 3; do
        echo "--- n$ns log ---" >&2
        cat "$TMP/n$ns.log" 2>/dev/null >&2 || true
    done
    exit 1
}

[ -x "$BIN" ] || fail "missing $BIN; run cargo build first"
[ -n "$DIG" ] || fail "missing dig; set DIG=/path/to/dig"

for ns in "$N1" "$N2" "$N3"; do
    ip netns add "$ns"
done

ip link add veth1 type veth peer name veth2
ip link set veth1 netns "$N1"
ip link set veth2 netns "$N2"
ip link add veth3 type veth peer name veth4
ip link set veth3 netns "$N2"
ip link set veth4 netns "$N3"

ip -n "$N1" addr add 10.200.0.1/24 dev veth1
ip -n "$N2" addr add 10.200.0.2/24 dev veth2
ip -n "$N2" addr add 10.200.1.2/24 dev veth3
ip -n "$N3" addr add 10.200.1.3/24 dev veth4

for ns in "$N1" "$N2" "$N3"; do
    ip -n "$ns" link set lo up
done
ip -n "$N1" link set veth1 up
ip -n "$N2" link set veth2 up
ip -n "$N2" link set veth3 up
ip -n "$N3" link set veth4 up

ip -n "$N1" route add 10.200.0.2/32 proto bird dev veth1
ip -n "$N2" route add 10.200.0.1/32 proto bird dev veth2
ip -n "$N2" route add 10.200.1.3/32 proto bird dev veth3
ip -n "$N3" route add 10.200.1.2/32 proto bird dev veth4

write_config() {
    local path=$1 name=$2 record=$3
    mkdir -p "$path.d"
    cat > "$path" <<CONFIG
zone = "namae."
reverse_zones = ["10.in-addr.arpa."]
dns_listen = ["127.0.0.1:15353"]
port = 17654
secret = "netns-e2e"
proto = "bird"
announce_interval = "1s"
origin_timeout = "10s"
tombstone_ttl = "60s"

[[records]]
name = "$name"
type = "A"
value = "$record"
publish = true
CONFIG
}

write_config "$TMP/n1.toml" "a.namae." "10.0.0.1"
write_config "$TMP/n2.toml" "b.namae." "10.0.0.2"
write_config "$TMP/n3.toml" "placeholder.namae." "10.0.0.3"

start_node() {
    local ns=$1 cfg=$2 sock=$3 log=$4
    ip netns exec "$ns" "$BIN" daemon \
        --config "$cfg" --config-dir "$cfg.d" --ctl-path "$sock" \
        >"$log" 2>&1 &
    PIDS+=("$!")
}

start_node "$N1" "$TMP/n1.toml" "$TMP/n1.sock" "$TMP/n1.log"
start_node "$N2" "$TMP/n2.toml" "$TMP/n2.sock" "$TMP/n2.log"
start_node "$N3" "$TMP/n3.toml" "$TMP/n3.sock" "$TMP/n3.log"

for ns in 1 2 3; do
    for _ in $(seq 1 50); do
        [ -S "$TMP/n$ns.sock" ] && break
        sleep 0.1
    done
    [ -S "$TMP/n$ns.sock" ] || fail "node n$ns did not start"
done

resolve() {
    local ns=$1 name=$2
    ip netns exec "$ns" "$DIG" @127.0.0.1 -p 15353 +short +time=1 +tries=1 "$name" A 2>/dev/null || true
}

wait_for() {
    local ns=$1 name=$2 expected=$3
    for _ in $(seq 1 60); do
        local out
        out=$(resolve "$ns" "$name")
        if [ "$out" = "$expected" ]; then
            return 0
        fi
        sleep 0.2
    done
    fail "$name did not resolve to $expected in $ns (got '$(resolve "$ns" "$name")')"
}

wait_for "$N1" "a.namae." "10.0.0.1"
wait_for "$N2" "a.namae." "10.0.0.1"
wait_for "$N2" "b.namae." "10.0.0.2"

# n1 and n3 only know n2; this exercises two-hop gossip.
wait_for "$N3" "a.namae." "10.0.0.1"
wait_for "$N1" "b.namae." "10.0.0.2"

# PTR from the A record.
if ! ip netns exec "$N1" "$DIG" @127.0.0.1 -p 15353 +short 1.0.0.10.in-addr.arpa. PTR 2>/dev/null | grep -qx "a.namae."; then
    fail "expected PTR for 10.0.0.1 to be a.namae."
fi

# DNS negative behavior.
if ! ip netns exec "$N3" "$DIG" @127.0.0.1 -p 15353 +noall +comments missing.namae A 2>/dev/null | grep -q 'status: NXDOMAIN'; then
    fail "expected NXDOMAIN for missing.namae"
fi
if ! ip netns exec "$N3" "$DIG" @127.0.0.1 -p 15353 +noall +comments example.com A 2>/dev/null | grep -q 'status: REFUSED'; then
    fail "expected REFUSED for example.com"
fi


# Route flap: remove the n1 <-> n2 paths, then bring them back.
ip -n "$N1" route del 10.200.0.2/32 proto bird
ip -n "$N2" route del 10.200.0.1/32 proto bird
for _ in $(seq 1 50); do
    if "$BIN" ctl --socket "$TMP/n1.sock" peers 2>/dev/null | grep -q '"peers": \[\]'; then
        break
    fi
    sleep 0.2
done
if ! "$BIN" ctl --socket "$TMP/n1.sock" peers 2>/dev/null | grep -q '"peers": \[\]'; then
    fail "n1 did not drop its peer after route removal"
fi
ip -n "$N1" route add 10.200.0.2/32 proto bird dev veth1
ip -n "$N2" route add 10.200.0.1/32 proto bird dev veth2
wait_for "$N1" "b.namae." "10.0.0.2"

echo "PASS: netns e2e (n1 <-> n2 <-> n3, two-hop gossip, PTR, route flap)"
