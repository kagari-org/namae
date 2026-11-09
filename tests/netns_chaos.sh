#!/usr/bin/env bash
set -euo pipefail

if [ "${NAMAE_NETNS_INNER:-0}" != "1" ]; then
    exec env NAMAE_NETNS_INNER=1 unshare -Urnm bash -c '
        set -e
        mount -t tmpfs tmpfs /run/netns
        exec "$@"
    ' _ "$0" "$@"
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${NAMAE_BIN:-$ROOT/target/debug/namae}
DIG=${DIG:-$(command -v dig || true)}
TC=${TC:-$(command -v tc || true)}
TMP=$(mktemp -d "$ROOT/target/namae-chaos.XXXXXX")
N1="namae-chaos-$$-1"
N2="namae-chaos-$$-2"
N3="namae-chaos-$$-3"
N4="namae-chaos-$$-4"
PIDS=()
LAST_PID=

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    for ns in "$N1" "$N2" "$N3" "$N4"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $*" >&2
    echo "TMP=$TMP" >&2
    ls -ld "$TMP" >&2 || true
    ps -o pid,cmd -p "${PIDS[@]}" >&2 || true
    ls -la "$TMP" >&2 || true
    for ns in 1 2 3 4; do
        echo "--- n$ns log ---" >&2
        ls -l "$TMP/n$ns.log" >&2 || true
        cat "$TMP/n$ns.log" >&2 || true
        echo "--- n$ns peers ---" >&2
        "$BIN" ctl --socket "$TMP/n$ns.sock" peers >&2 || true
        echo "--- n$ns records ---" >&2
        "$BIN" ctl --socket "$TMP/n$ns.sock" records >&2 || true
    done
    exit 1
}

[ -x "$BIN" ] || fail "missing $BIN; run cargo build first"
[ -n "$DIG" ] || fail "missing dig; set DIG=/path/to/dig"
[ -n "$TC" ] || fail "missing tc; set TC=/path/to/tc"

for ns in "$N1" "$N2" "$N3" "$N4"; do
    ip netns add "$ns"
done

# Ring: n1 - n2 - n3 - n4 - n1
ip link add v1 type veth peer name v2
ip link set v1 netns "$N1"
ip link set v2 netns "$N2"
ip link add v3 type veth peer name v4
ip link set v3 netns "$N2"
ip link set v4 netns "$N3"
ip link add v5 type veth peer name v6
ip link set v5 netns "$N3"
ip link set v6 netns "$N4"
ip link add v7 type veth peer name v8
ip link set v7 netns "$N4"
ip link set v8 netns "$N1"

ip -n "$N1" addr add 10.200.0.1/24 dev v1
ip -n "$N2" addr add 10.200.0.2/24 dev v2
ip -n "$N2" addr add 10.200.1.2/24 dev v3
ip -n "$N3" addr add 10.200.1.3/24 dev v4
ip -n "$N3" addr add 10.200.2.3/24 dev v5
ip -n "$N4" addr add 10.200.2.4/24 dev v6
ip -n "$N4" addr add 10.200.3.4/24 dev v7
ip -n "$N1" addr add 10.200.3.1/24 dev v8

for ns in "$N1" "$N2" "$N3" "$N4"; do
    ip -n "$ns" link set lo up
done
ip -n "$N1" link set v1 up
ip -n "$N1" link set v8 up
ip -n "$N2" link set v2 up
ip -n "$N2" link set v3 up
ip -n "$N3" link set v4 up
ip -n "$N3" link set v5 up
ip -n "$N4" link set v6 up
ip -n "$N4" link set v7 up

# Each node only discovers its two ring neighbours.
ip -n "$N1" route add 10.200.0.2/32 proto bird dev v1
ip -n "$N1" route add 10.200.3.4/32 proto bird dev v8
ip -n "$N2" route add 10.200.0.1/32 proto bird dev v2
ip -n "$N2" route add 10.200.1.3/32 proto bird dev v3
ip -n "$N3" route add 10.200.1.2/32 proto bird dev v4
ip -n "$N3" route add 10.200.2.4/32 proto bird dev v5
ip -n "$N4" route add 10.200.2.3/32 proto bird dev v6
ip -n "$N4" route add 10.200.3.1/32 proto bird dev v7

write_config() {
    local path=$1 name=$2 record=$3
    mkdir -p "$path.d"
    cat > "$path" <<CONFIG
zone = "namae."
dns_listen = ["127.0.0.1:15353"]
port = 17656
secret = "netns-chaos"
proto = "bird"
announce_interval = "1s"
origin_timeout = "4s"
tombstone_ttl = "30s"

[[records]]
name = "$name"
type = "A"
value = "$record"
publish = true
CONFIG
}

write_config "$TMP/n1.toml" "n1.namae." "10.0.0.1"
write_config "$TMP/n2.toml" "n2.namae." "10.0.0.2"
write_config "$TMP/n3.toml" "n3.namae." "10.0.0.3"
write_config "$TMP/n4.toml" "n4.namae." "10.0.0.4"

start_node() {
    local ns=$1 n=$2
    ip netns exec "$ns" "$BIN" daemon \
        --config "$TMP/n$n.toml" --config-dir "$TMP/n$n.toml.d" \
        --ctl-path "$TMP/n$n.sock" >"$TMP/n$n.log" 2>&1 &
    LAST_PID=$!
    PIDS+=("$LAST_PID")
}

start_node "$N1" 1
N1_PID=$LAST_PID
start_node "$N2" 2
N2_PID=$LAST_PID
start_node "$N3" 3
N3_PID=$LAST_PID
start_node "$N4" 4
N4_PID=$LAST_PID

for n in 1 2 3 4; do
    for _ in $(seq 1 50); do
        [ -S "$TMP/n$n.sock" ] && break
        sleep 0.1
    done
    [ -S "$TMP/n$n.sock" ] || fail "node n$n did not start"
done

resolve() {
    local ns=$1 name=$2
    ip netns exec "$ns" "$DIG" @127.0.0.1 -p 15353 +short +time=1 +tries=1 "$name" A 2>/dev/null || true
}

wait_for() {
    local ns=$1 name=$2 expected=$3
    for _ in $(seq 1 100); do
        local out
        out=$(resolve "$ns" "$name")
        if [ "$out" = "$expected" ]; then
            return 0
        fi
        sleep 0.2
    done
    fail "$name did not resolve to $expected in $ns (got '$(resolve "$ns" "$name")')"
}

wait_gone() {
    local ns=$1 name=$2
    for _ in $(seq 1 100); do
        if [ -z "$(resolve "$ns" "$name")" ]; then
            return 0
        fi
        sleep 0.2
    done
    fail "$name did not expire in $ns (got '$(resolve "$ns" "$name")')"
}

set_loss() {
    local ns=$1 dev=$2 loss=$3
    ip netns exec "$ns" "$TC" qdisc replace dev "$dev" root netem loss "$loss"
}

clear_loss() {
    local ns=$1 dev=$2
    ip netns exec "$ns" "$TC" qdisc del dev "$dev" root 2>/dev/null || true
}

echo "== initial ring convergence =="
wait_for "$N1" "n2.namae." "10.0.0.2"
wait_for "$N1" "n3.namae." "10.0.0.3"
wait_for "$N1" "n4.namae." "10.0.0.4"
wait_for "$N3" "n1.namae." "10.0.0.1"
wait_for "$N4" "n2.namae." "10.0.0.2"

echo "== partition n1 from the ring =="
ip -n "$N1" route del 10.200.0.2/32 proto bird
ip -n "$N1" route del 10.200.3.4/32 proto bird
ip -n "$N2" route del 10.200.0.1/32 proto bird
ip -n "$N4" route del 10.200.3.1/32 proto bird
wait_gone "$N1" "n3.namae."
wait_gone "$N1" "n4.namae."

echo "== heal partition =="
ip -n "$N1" route add 10.200.0.2/32 proto bird dev v1
ip -n "$N1" route add 10.200.3.4/32 proto bird dev v8
ip -n "$N2" route add 10.200.0.1/32 proto bird dev v2
ip -n "$N4" route add 10.200.3.1/32 proto bird dev v7
wait_for "$N1" "n3.namae." "10.0.0.3"
wait_for "$N1" "n4.namae." "10.0.0.4"

echo "== packet loss on both n1 links =="
set_loss "$N1" v1 10%
set_loss "$N2" v2 10%
set_loss "$N1" v8 10%
set_loss "$N4" v7 10%
cat > "$TMP/n3.toml.d/loss.toml" <<'CONFIG'
[[records]]
name = "loss.namae."
type = "A"
value = "10.0.0.9"
publish = true
CONFIG
wait_for "$N1" "loss.namae." "10.0.0.9"
clear_loss "$N1" v1
clear_loss "$N2" v2
clear_loss "$N1" v8
clear_loss "$N4" v7

echo "== node n2 offline and record expiry =="
kill "$N2_PID" 2>/dev/null || true
sleep 0.2
wait_gone "$N1" "n2.namae."
wait_for "$N3" "n4.namae." "10.0.0.4"

echo "== restart n2 and resync =="
start_node "$N2" 2
N2_PID=$LAST_PID
for _ in $(seq 1 50); do
    [ -S "$TMP/n2.sock" ] && break
    sleep 0.1
done
wait_for "$N1" "n2.namae." "10.0.0.2"
wait_for "$N3" "n1.namae." "10.0.0.1"

echo "PASS: netns chaos (ring, partition, packet loss, node offline/restart)"
