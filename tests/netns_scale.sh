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
TC=${TC:-$(command -v tc || true)}
[ -x "$TC" ] || TC=$(command -v tc)
TMP=$(mktemp -d "$ROOT/target/namae-scale.XXXXXX")
N1="namae-scale-$$-1"
N2="namae-scale-$$-2"
N3="namae-scale-$$-3"
N4="namae-scale-$$-4"
N5="namae-scale-$$-5"
N6="namae-scale-$$-6"
PIDS=()
LAST_PID=

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    for ns in "$N1" "$N2" "$N3" "$N4" "$N5" "$N6"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $*" >&2
    echo "TMP=$TMP" >&2
    for ns in 1 2 3 4 5 6; do
        echo "--- n$ns log ---" >&2
        cat "$TMP/n$ns.log" 2>/dev/null >&2 || true
        echo "--- n$ns peers ---" >&2
        "$BIN" ctl --socket "$TMP/n$ns.sock" peers 2>/dev/null >&2 || true
        echo "--- n$ns records ---" >&2
        "$BIN" ctl --socket "$TMP/n$ns.sock" records 2>/dev/null >&2 || true
    done
    exit 1
}

[ -x "$BIN" ] || fail "missing $BIN; run cargo build first"
[ -n "$DIG" ] || fail "missing dig; set DIG=/path/to/dig"
[ -n "$TC" ] || fail "missing tc; set TC=/path/to/tc"

for ns in "$N1" "$N2" "$N3" "$N4" "$N5" "$N6"; do
    ip netns add "$ns"
done

# Ring: n1 - n2 - n3 - n4 - n5 - n6 - n1, plus n1 - n4 chord.
make_pair() {
    local a=$1 b=$2 ifa=$3 ifb=$4 ns_a=$5 ns_b=$6
    ip link add "$ifa" type veth peer name "$ifb"
    ip link set "$ifa" netns "$ns_a"
    ip link set "$ifb" netns "$ns_b"
}
make_pair v1 v2 v1 v2 "$N1" "$N2"
make_pair v3 v4 v3 v4 "$N2" "$N3"
make_pair v5 v6 v5 v6 "$N3" "$N4"
make_pair v7 v8 v7 v8 "$N4" "$N5"
make_pair v9 v10 v9 v10 "$N5" "$N6"
make_pair v11 v12 v11 v12 "$N6" "$N1"
make_pair v13 v14 v13 v14 "$N1" "$N4"

ip -n "$N1" addr add 10.200.0.1/24 dev v1
ip -n "$N2" addr add 10.200.0.2/24 dev v2
ip -n "$N2" addr add 10.200.1.2/24 dev v3
ip -n "$N3" addr add 10.200.1.3/24 dev v4
ip -n "$N3" addr add 10.200.2.3/24 dev v5
ip -n "$N4" addr add 10.200.2.4/24 dev v6
ip -n "$N4" addr add 10.200.3.4/24 dev v7
ip -n "$N5" addr add 10.200.3.5/24 dev v8
ip -n "$N5" addr add 10.200.4.5/24 dev v9
ip -n "$N6" addr add 10.200.4.6/24 dev v10
ip -n "$N6" addr add 10.200.5.6/24 dev v11
ip -n "$N1" addr add 10.200.5.1/24 dev v12
ip -n "$N1" addr add 10.200.6.1/24 dev v13
ip -n "$N4" addr add 10.200.6.4/24 dev v14

for ns in "$N1" "$N2" "$N3" "$N4" "$N5" "$N6"; do
    ip -n "$ns" link set lo up
done
for ns in "$N1" "$N2" "$N3" "$N4" "$N5" "$N6"; do
    for dev in $(ip -n "$ns" -o link show | awk -F': ' '$2 ~ /^v/ {print $2}' | cut -d@ -f1); do
        ip -n "$ns" link set "$dev" up
    done
done

ip -n "$N1" route add 10.200.0.2/32 proto bird dev v1
ip -n "$N1" route add 10.200.5.6/32 proto bird dev v12
ip -n "$N1" route add 10.200.6.4/32 proto bird dev v13
ip -n "$N2" route add 10.200.0.1/32 proto bird dev v2
ip -n "$N2" route add 10.200.1.3/32 proto bird dev v3
ip -n "$N3" route add 10.200.1.2/32 proto bird dev v4
ip -n "$N3" route add 10.200.2.4/32 proto bird dev v5
ip -n "$N4" route add 10.200.2.3/32 proto bird dev v6
ip -n "$N4" route add 10.200.3.5/32 proto bird dev v7
ip -n "$N4" route add 10.200.6.1/32 proto bird dev v14
ip -n "$N5" route add 10.200.3.4/32 proto bird dev v8
ip -n "$N5" route add 10.200.4.6/32 proto bird dev v9
ip -n "$N6" route add 10.200.4.5/32 proto bird dev v10
ip -n "$N6" route add 10.200.5.1/32 proto bird dev v11

write_config() {
    local path=$1 name=$2 record=$3
    mkdir -p "$path.d"
    cat > "$path" <<CONFIG
zone = "namae."
dns_listen = ["127.0.0.1:15353"]
port = 17657
secret = "netns-scale"
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

for i in 1 2 3 4 5 6; do
    write_config "$TMP/n$i.toml" "n$i.namae." "10.0.0.$i"
done

start_node() {
    local ns=$1 n=$2
    ip netns exec "$ns" "$BIN" daemon \
        --config "$TMP/n$n.toml" --config-dir "$TMP/n$n.toml.d" \
        --ctl-path "$TMP/n$n.sock" >"$TMP/n$n.log" 2>&1 &
    LAST_PID=$!
    PIDS+=("$LAST_PID")
}

start_node "$N1" 1; N1_PID=$LAST_PID
start_node "$N2" 2; N2_PID=$LAST_PID
start_node "$N3" 3; N3_PID=$LAST_PID
start_node "$N4" 4; N4_PID=$LAST_PID
start_node "$N5" 5; N5_PID=$LAST_PID
start_node "$N6" 6; N6_PID=$LAST_PID

for n in 1 2 3 4 5 6; do
    for _ in $(seq 1 50); do
        [ -S "$TMP/n$n.sock" ] && break
        sleep 0.1
    done
    [ -S "$TMP/n$n.sock" ] || fail "node n$n did not start"
done

reload_node() {
    "$BIN" ctl --socket "$TMP/n$1.sock" reload >/dev/null
}

resolve() {
    local ns=$1 name=$2
    ip netns exec "$ns" "$DIG" @127.0.0.1 -p 15353 +short +time=1 +tries=1 "$name" A 2>/dev/null || true
}

wait_for() {
    local ns=$1 name=$2 expected=$3
    for _ in $(seq 1 120); do
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
    for _ in $(seq 1 120); do
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

echo "== six-node ring convergence =="
for i in 2 3 4 5 6; do
    wait_for "$N1" "n$i.namae." "10.0.0.$i"
done
for i in 1 2 3 4 5; do
    wait_for "$N6" "n$i.namae." "10.0.0.$i"
done
if ! ip netns exec "$N1" "$DIG" @127.0.0.1 -p 15353 +tcp +short n4.namae. A 2>/dev/null | grep -qx "10.0.0.4"; then
    fail "TCP DNS query failed on n1"
fi

echo "== split ring into {n1,n2,n3} and {n4,n5,n6} =="
ip -n "$N3" route del 10.200.2.4/32 proto bird
ip -n "$N4" route del 10.200.2.3/32 proto bird
ip -n "$N6" route del 10.200.5.1/32 proto bird
ip -n "$N1" route del 10.200.5.6/32 proto bird
ip -n "$N1" route del 10.200.6.4/32 proto bird
ip -n "$N4" route del 10.200.6.1/32 proto bird

cat > "$TMP/n2.toml.d/left.toml" <<'CONFIG'
[[records]]
name = "left.namae."
type = "A"
value = "10.0.0.12"
publish = true
CONFIG
cat > "$TMP/n5.toml.d/right.toml" <<'CONFIG'
[[records]]
name = "right.namae."
type = "A"
value = "10.0.0.15"
publish = true
CONFIG
reload_node 2
reload_node 5
wait_for "$N1" "left.namae." "10.0.0.12"
wait_for "$N6" "right.namae." "10.0.0.15"
sleep 2
[ -z "$(resolve "$N1" "right.namae.")" ] || fail "right leaked into the left partition"
[ -z "$(resolve "$N6" "left.namae.")" ] || fail "left leaked into the right partition"

echo "== heal the split =="
ip -n "$N3" route add 10.200.2.4/32 proto bird dev v5
ip -n "$N4" route add 10.200.2.3/32 proto bird dev v6
ip -n "$N6" route add 10.200.5.1/32 proto bird dev v11
ip -n "$N1" route add 10.200.5.6/32 proto bird dev v12
ip -n "$N1" route add 10.200.6.4/32 proto bird dev v13
ip -n "$N4" route add 10.200.6.1/32 proto bird dev v14
wait_for "$N1" "right.namae." "10.0.0.15"
wait_for "$N6" "left.namae." "10.0.0.12"

echo "== node n3 offline and restart =="
kill "$N3_PID" 2>/dev/null || true
sleep 0.2
wait_gone "$N1" "n3.namae."
wait_for "$N1" "n4.namae." "10.0.0.4"
start_node "$N3" 3
N3_PID=$LAST_PID
for _ in $(seq 1 50); do
    [ -S "$TMP/n3.sock" ] && break
    sleep 0.1
done
wait_for "$N1" "n3.namae." "10.0.0.3"

echo "== 10% loss on both n3 links =="
set_loss "$N3" v4 10%
set_loss "$N3" v5 10%
set_loss "$N4" v6 10%
set_loss "$N2" v3 10%
set_loss "$N2" v2 10%
set_loss "$N1" v1 10%
cat > "$TMP/n3.toml.d/loss.toml" <<'CONFIG'
[[records]]
name = "scale-loss.namae."
type = "A"
value = "10.0.0.33"
publish = true
CONFIG
reload_node 3
wait_for "$N1" "scale-loss.namae." "10.0.0.33"
clear_loss "$N3" v4
clear_loss "$N3" v5
clear_loss "$N4" v6
clear_loss "$N2" v3
clear_loss "$N2" v2
clear_loss "$N1" v1

echo "== reload and delete on n5 =="
cat > "$TMP/n5.toml.d/reload.toml" <<'CONFIG'
[[records]]
name = "scale-reload.namae."
type = "A"
value = "10.0.0.55"
publish = true
CONFIG
reload_node 5
wait_for "$N1" "scale-reload.namae." "10.0.0.55"
rm "$TMP/n5.toml.d/reload.toml"
reload_node 5
wait_gone "$N1" "scale-reload.namae."

echo "PASS: netns scale (6-node ring + chord, split-brain, offline/restart, loss, reload)"
