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
TMP=$(mktemp -d "$ROOT/target/namae-backoff.XXXXXX")
N1="namae-backoff-$$-1"
N2="namae-backoff-$$-2"
PID=

cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
    wait 2>/dev/null || true
    ip netns del "$N1" 2>/dev/null || true
    ip netns del "$N2" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $*" >&2
    cat "$TMP/n1.log" 2>/dev/null >&2 || true
    exit 1
}

[ -x "$BIN" ] || fail "missing $BIN; run cargo build first"

ip netns add "$N1"
ip netns add "$N2"
ip link add v1 type veth peer name v2
ip link set v1 netns "$N1"
ip link set v2 netns "$N2"
ip -n "$N1" addr add 10.200.0.1/24 dev v1
ip -n "$N2" link set v2 up
ip -n "$N1" link set lo up
ip -n "$N1" link set v1 up

cat > "$TMP/n1.toml" <<'CONFIG'
zone = "namae."
dns_listen = ["127.0.0.1:15353"]
port = 17659
secret = "netns-backoff"
proto = "bird"
announce_interval = "1s"
origin_timeout = "10s"

[[records]]
name = "n1.namae."
type = "A"
value = "10.0.0.1"
publish = true
CONFIG
mkdir -p "$TMP/n1.toml.d"

ip -n "$N1" route add 10.200.0.99/32 proto bird dev v1

RUST_LOG=namae=debug ip netns exec "$N1" "$BIN" daemon \
    --config "$TMP/n1.toml" --config-dir "$TMP/n1.toml.d" \
    --ctl-path "$TMP/n1.sock" >"$TMP/n1.log" 2>&1 &
PID=$!
for _ in $(seq 1 50); do
    [ -S "$TMP/n1.sock" ] && break
    sleep 0.1
done
[ -S "$TMP/n1.sock" ] || fail "daemon did not start"

for _ in $(seq 1 200); do
    if grep -q 'attempt 3' "$TMP/n1.log"; then
        break
    fi
    sleep 0.2
done
grep -q '10.200.0.99:17659' "$TMP/n1.log" || fail "no connection attempts for the unreachable route"
grep -q 'attempt 1' "$TMP/n1.log" || fail "no first retry"
grep -q 'attempt 2' "$TMP/n1.log" || fail "no second retry"
grep -q 'attempt 3' "$TMP/n1.log" || fail "no third retry"

before=$(grep -c '10.200.0.99:17659.*retrying' "$TMP/n1.log" || true)
ip -n "$N1" route del 10.200.0.99/32 proto bird
sleep 3
after=$(grep -c '10.200.0.99:17659.*retrying' "$TMP/n1.log" || true)
[ "$before" = "$after" ] || fail "retries continued after route removal ($before -> $after)"

echo "PASS: netns connection backoff (route without namae, retries stop on route removal)"
