# Pre-registration — cortex9-xdp-semantic-fw-v2

This document is committed **before** the corpus is generated and
**before** any measurement. Changing thresholds, heuristics or the
corpus after measuring is forbidden; a missed threshold is reported
plainly as a failure.

## Thresholds (acceptance)

| Metric | Threshold | Population |
|--------|-----------|------------|
| TPR | ≥ 90 % | 1000 attack packets |
| FPR | ≤ 1 %  | 10000 legit packets |

Throughput (Mpps / drop rate) is reported as measured on a veth pair
in SKB (`xdpgeneric`) mode on CI `ubuntu-latest`. Native-NIC
performance is **unverified**.

## Fixed corpus (seed 20261029)

- **10000 legit flows**, seed `20261029`, domains from
  `data/legit-domains.txt` (Tranco top, collision-free with the
  denylist):
  - 4000 DNS queries (UDP/53) for the domains
  - 4000 TLS ClientHello with SNI = the domains, with a **realistic
    key_share**: X25519MLKEM768 (1216 B client share, RFC 10024) so
    the SNI sits past the ~263 B header region that defeated v1
  - 2000 HTTP/1.1 GET with Host = the domains and a **263-byte**
    header block (Accept, User-Agent, Cookie, …) so the Host is past
    the old 192 B window
- **1000 attacks**:
  - 400 DNS tunnelling queries: a single label of ≥ 50 base32
    characters, QNAME total ≥ 150 (heuristic pre-registered below)
  - 400 TLS ClientHello whose SNI is a denylisted domain (same
    realistic key_share as above)
  - 200 HTTP/1.1 GET whose Host is a denylisted domain (same 263 B
    headers)

Labels (ground truth) are written to `corpus/labels.csv` at
generation time. The generator refuses to overwrite an existing
corpus.

## Pre-registered tunnelling heuristic

A DNS query is dropped as tunnelling when **either**:

- any single label has length ≥ **50**, or
- the whole QNAME has length ≥ **150**.

Constants live in `bpf/fw_common.h` (`TUN_LABEL`, `TUN_TOTAL`) and
are never tuned after measuring.

## Denylist

`data/denylist.txt`: 200 domains from the 2026-10-29 snapshot of
malware-filter/urlhaus-filter (CC0/MIT), first 200 by
`sha256(domain)`, excluding Tranco top-10k collisions. Matching is
exact on DNS label boundaries (reversed-FNV hash of every suffix),
so `notevil.com` never matches a rule for `evil.com`.

## Baseline

The same denylist, applied as nftables `string` matches (case-
insensitive) over the full packet on the same replay. On kernels
without `xt_string` / nft string, the baseline is emulated offline
by scanning the same bytes for each denylist domain (documented as
emulated).

## What this remake fixes from v1

1. **Byte-192 window**: v1 only saw 192 B of payload; with a real
   MCP/HTTP header block of 263 B the Host/SNI never entered the
   window (0 % blocking). v2 copies up to 2048 B of L4 payload with
   `bpf_xdp_load_bytes` and walks it with `bpf_loop`.
2. **Substring FPR**: v1 matched free-text keywords anywhere in the
   window (FPR 5.3–13.9 points over tolerance). v2 matches only
   structured names (DNS QNAME / TLS SNI / HTTP Host) and only on
   label boundaries.
3. **Honest scope**: native-NIC Mpps is unverified; CI runs
   `xdpgeneric` on veth and fails loudly if XDP cannot load.
