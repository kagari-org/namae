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

export MALLOC_ARENA_MAX=1

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${NAMAE_BIN:-$ROOT/target/debug/namae}
DIG=${DIG:-$(command -v dig || true)}
TMP=$(mktemp -d "$ROOT/target/namae-mem.XXXXXX")
N1="namae-mem-$$-1"
N2="namae-mem-$$-2"
N3="namae-mem-$$-3"
PIDS=()
LAST_PID=
N1_PID= N2_PID= N3_PID=

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
        tail -20 "$TMP/n$ns.log" 2>/dev/null >&2 || true
    done
    exit 1
}

[ -x "$BIN" ] || fail "missing $BIN; run cargo build first"
[ -n "$DIG" ] || fail "missing dig; set DIG=/path/to/dig"

for ns in "$N1" "$N2" "$N3"; do
    ip netns add "$ns"
done

ip link add v1 type veth peer name v2
ip link set v1 netns "$N1"
ip link set v2 netns "$N2"
ip link add v3 type veth peer name v4
ip link set v3 netns "$N2"
ip link set v4 netns "$N3"
ip link add v5 type veth peer name v6
ip link set v5 netns "$N3"
ip link set v6 netns "$N1"

ip -n "$N1" addr add 10.200.0.1/24 dev v1
ip -n "$N2" addr add 10.200.0.2/24 dev v2
ip -n "$N2" addr add 10.200.1.2/24 dev v3
ip -n "$N3" addr add 10.200.1.3/24 dev v4
ip -n "$N3" addr add 10.200.2.3/24 dev v5
ip -n "$N1" addr add 10.200.2.1/24 dev v6

for ns in "$N1" "$N2" "$N3"; do
    ip -n "$ns" link set lo up
done
for ns in "$N1" "$N2" "$N3"; do
    for dev in $(ip -n "$ns" -o link show | awk -F': ' '$2 ~ /^v/ {print $2}' | cut -d@ -f1); do
        ip -n "$ns" link set "$dev" up
    done
done

ip -n "$N1" route add 10.200.0.2/32 proto bird dev v1
ip -n "$N1" route add 10.200.2.3/32 proto bird dev v6
ip -n "$N2" route add 10.200.0.1/32 proto bird dev v2
ip -n "$N2" route add 10.200.1.3/32 proto bird dev v3
ip -n "$N3" route add 10.200.1.2/32 proto bird dev v4
ip -n "$N3" route add 10.200.2.1/32 proto bird dev v5

write_config() {
    local path=$1 name=$2 record=$3
    mkdir -p "$path.d"
    cat > "$path" <<CONFIG
zone = "namae."
dns_listen = ["127.0.0.1:15353"]
port = 17658
secret = "netns-mem"
proto = "bird"
announce_interval = "1s"
origin_timeout = "3s"
tombstone_ttl = "2s"

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

start_node() {
    local ns=$1 n=$2
    ip netns exec "$ns" "$BIN" daemon \
        --config "$TMP/n$n.toml" --config-dir "$TMP/n$n.toml.d" \
        --ctl-path "$TMP/n$n.sock" >"$TMP/n$n.log" 2>&1 &
    LAST_PID=$!
    PIDS+=("$LAST_PID")
}

start_all() {
    start_node "$N1" 1; N1_PID=$LAST_PID
    start_node "$N2" 2; N2_PID=$LAST_PID
    start_node "$N3" 3; N3_PID=$LAST_PID
    for n in 1 2 3; do
        for _ in $(seq 1 50); do
            [ -S "$TMP/n$n.sock" ] && break
            sleep 0.1
        done
        [ -S "$TMP/n$n.sock" ] || fail "node n$n did not start"
    done
}

reload_node() {
    "$BIN" ctl --socket "$TMP/n$1.sock" reload >/dev/null
}

resolve() {
    local ns=$1 name=$2
    ip netns exec "$ns" "$DIG" @127.0.0.1 -p 15353 +short +time=1 +tries=1 "$name" A 2>/dev/null || true
}

wait_for() {
    local ns=$1 name=$2 expected=$3
    for _ in $(seq 1 100); do
        if [ "$(resolve "$ns" "$name")" = "$expected" ]; then
            return 0
        fi
        sleep 0.1
    done
    fail "$name did not resolve to $expected in $ns"
}

wait_gone() {
    local ns=$1 name=$2
    for _ in $(seq 1 100); do
        if [ -z "$(resolve "$ns" "$name")" ]; then
            return 0
        fi
        sleep 0.1
    done
    fail "$name did not expire in $ns"
}

rss_kb() {
    awk '/VmRSS:/ {print $2}' "/proc/$1/status" 2>/dev/null || true
}

threads() {
    awk '/Threads:/ {print $2}' "/proc/$1/status" 2>/dev/null || true
}

fd_count() {
    find "/proc/$1/fd" -maxdepth 1 -type l 2>/dev/null | wc -l
}

sample() {
    local label=$1
    local total_rss=0 total_threads=0 total_fds=0
    for pid in "$N1_PID" "$N2_PID" "$N3_PID"; do
        total_rss=$((total_rss + $(rss_kb "$pid")))
        total_threads=$((total_threads + $(threads "$pid")))
        total_fds=$((total_fds + $(fd_count "$pid")))
    done
    printf '%s rss=%sKiB threads=%s fds=%s\n' "$label" "$total_rss" "$total_threads" "$total_fds"
    LAST_RSS=$total_rss
    LAST_THREADS=$total_threads
    LAST_FDS=$total_fds
}

start_all
wait_for "$N1" "n2.namae." "10.0.0.2"
wait_for "$N1" "n3.namae." "10.0.0.3"

echo "== warmup =="
for i in $(seq 1 5); do
    kill "$N2_PID" 2>/dev/null || true
    sleep 0.2
    start_node "$N2" 2; N2_PID=$LAST_PID
    for _ in $(seq 1 50); do [ -S "$TMP/n2.sock" ] && break; sleep 0.1; done
    wait_for "$N1" "n2.namae." "10.0.0.2"
done
sleep 12
sample "baseline"
base_rss=$LAST_RSS
base_threads=$LAST_THREADS
base_fds=$LAST_FDS

echo "== churn =="
for i in $(seq 1 12); do
    # Restart a node with a new random identity.
    kill "$N2_PID" 2>/dev/null || true
    sleep 0.15
    start_node "$N2" 2; N2_PID=$LAST_PID
    for _ in $(seq 1 50); do [ -S "$TMP/n2.sock" ] && break; sleep 0.1; done
    wait_for "$N1" "n2.namae." "10.0.0.2"

    # Route flap.
    ip -n "$N1" route del 10.200.0.2/32 proto bird || true
    ip -n "$N2" route del 10.200.0.1/32 proto bird || true
    sleep 0.2
    ip -n "$N1" route add 10.200.0.2/32 proto bird dev v1
    ip -n "$N2" route add 10.200.0.1/32 proto bird dev v2

    # Unique dynamically reloaded name, then delete it.
    cat > "$TMP/n3.toml.d/churn.toml" <<CONFIG
[[records]]
name = "churn-$i.namae."
type = "A"
value = "10.0.0.9"
publish = true
CONFIG
    reload_node 3
    wait_for "$N1" "churn-$i.namae." "10.0.0.9"
    rm "$TMP/n3.toml.d/churn.toml"
    reload_node 3
    wait_gone "$N1" "churn-$i.namae."
done

sleep 15
sample "after-churn"
echo "baseline: rss=${base_rss}KiB threads=${base_threads} fds=${base_fds}"
echo "final:    rss=${LAST_RSS}KiB threads=${LAST_THREADS} fds=${LAST_FDS}"

delta_rss=$((LAST_RSS - base_rss))
delta_threads=$((LAST_THREADS - base_threads))
delta_fds=$((LAST_FDS - base_fds))
echo "delta: rss=${delta_rss}KiB threads=${delta_threads} fds=${delta_fds}"

[ "$delta_rss" -lt 32768 ] || fail "RSS grew by ${delta_rss}KiB"
[ "$delta_threads" -le 2 ] || fail "thread count grew by ${delta_threads}"
[ "$delta_fds" -le 8 ] || fail "FD count grew by ${delta_fds}"

echo "PASS: netns memory churn"
