#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Attach xdp_semfw and xdp_l3 on a veth pair in xdpgeneric mode, blast
# the corpus with a userspace sender, count drops. Fails loudly if XDP
# cannot load or attach. Native-NIC Mpps is NOT measured here.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OBJ="${1:-$ROOT/bpf/fw.bpf.o}"
DENY="${2:-$ROOT/data/denylist.txt}"
OUT="${3:-$ROOT/results/veth-bench.json}"
NS=c9sfw$$
V0=c9a$$
V1=c9b$$
cleanup() {
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$V0" 2>/dev/null || true
}
trap cleanup EXIT

ip link add "$V0" type veth peer name "$V1"
ip netns add "$NS"
ip link set "$V1" netns "$NS"
ip addr add 10.67.0.1/30 dev "$V0"
ip netns exec "$NS" ip addr add 10.67.0.2/30 dev "$V1"
ip link set "$V0" up
ip netns exec "$NS" ip link set "$V1" up
ip link set "$V0" mtu 1500
ip netns exec "$NS" ip link set "$V1" mtu 1500

# Load object, attach xdpgeneric on V0 (ingress from V1)
"$ROOT/bin/loader" --skb-only "$OBJ" "$DENY" "$V0" &
LPID=$!
sleep 0.5
if ! kill -0 "$LPID" 2>/dev/null; then
  echo "FATAL: loader died; XDP did not attach" >&2
  exit 2
fi

# Sender in the peer namespace: replay the pcap as raw frames
START=$(date +%s%N)
ip netns exec "$NS" "$ROOT/bin/pcap_send" "$ROOT/corpus/corpus.pcap" "$V1"
END=$(date +%s%N)
kill -INT "$LPID" 2>/dev/null || true
wait "$LPID" 2>/dev/null || true

# Stats come from the measure path; this script's job is the attach+blast
# smoke and a wall-clock pps lower bound. Precise per-packet ns is from
# `measure bench` (BPF_PROG_TEST_RUN).
N=$(wc -l < "$ROOT/corpus/labels.csv")
N=$((N - 1))
NS_ELAPSED=$((END - START))
PPS=$(python3 -c "print(round($N / ($NS_ELAPSED / 1e9), 2) if $NS_ELAPSED else 0)")
mkdir -p "$(dirname "$OUT")"
python3 - <<PY
import json
print(json.dumps({
  "mode": "xdpgeneric/veth",
  "n_packets": $N,
  "wall_ns": $NS_ELAPSED,
  "pps_lower_bound": $PPS,
  "note": "wall-clock send rate on veth; not native-NIC Mpps. Per-packet program ns is in results/bench.csv (BPF_PROG_TEST_RUN).",
}, indent=2))
PY
python3 -c "import json; json.dump({'mode':'xdpgeneric/veth','n_packets':$N,'wall_ns':$NS_ELAPSED,'pps_lower_bound':$PPS,'note':'wall-clock send rate on veth; native-NIC Mpps unverified'}, open('$OUT','w'), indent=2)"
echo "wrote $OUT"
