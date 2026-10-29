# cortex9-xdp-semantic-fw-v2

XDP semantic firewall that parses **DNS QNAME** (UDP/53), **TLS
ClientHello SNI** (TCP/443) and **HTTP/1.x Host** (TCP/80) at their
real offsets and drops packets whose name falls under a denylisted
domain (plus a pre-registered DNS-tunnelling heuristic).

Remake of
[`cortex9-xdp-semantic-firewall`](https://github.com/federiconbaez/cortex9-xdp-semantic-firewall)
(v1), which failed its value threshold: FPR 5.3–13.9 points over
tolerance, and **0 % blocking** with 263-byte real headers because of
a fixed 192-byte window. Thresholds and corpus were
[pre-registered](docs/PREREGISTRO.md) **before** measuring.

## Results (measured)

Corpus: 10000 legit + 1000 attacks, seed `20261029`
(`corpus/MANIFEST`). Runner: real `xdp_semfw` bytecode via
`BPF_PROG_TEST_RUN` (`bin/measure`).

| Metric | Threshold | Measured | Pass? |
|--------|-----------|----------|-------|
| TPR (attacks) | ≥ 90 % | **100.0 %** (1000/1000) | yes |
| FPR (legit) | ≤ 1 % | **0.0 %** (0/10000) | yes |
| nftables `string --icase` baseline TPR | (control) | 60.0 % (misses all 400 DNS tunnels) | — |
| nftables baseline FPR | (control) | 0.0 % | — |

Per-kind drop rate: dns-tunnel 400/400, sni-deny 400/400,
http-deny 200/200; all 10000 legit kinds 0 drops. Raw files:
`results/verdicts.csv`, `results/baseline.csv`,
`results/summary.json`.

### Throughput (honest)

| What | Number | Notes |
|------|--------|-------|
| Program ns p50 (semantic) | 800 ns | `BPF_PROG_TEST_RUN`, 300-pkt sample × 500 |
| Program ns p50 (L3 IP deny) | 19 ns | same harness |
| Implied Mpps from program ns | ~1.25 vs ~52.6 | **not** wire rate |
| Ratio vs L3 (program ns) | ~42× slower | semantic parse ≫ IP lookup |
| veth `xdpgeneric` wall-clock | ~0.16 Mpps lower bound | AF_PACKET send path dominates |
| Native NIC Mpps | **unverified** | no commodity NIC in this environment |
| Mpps ≥ 50 % of L3 baseline on NIC | **not claimed** | would fail if program-ns were the proxy |

## What v2 fixes from v1

1. **No 192-byte window.** Up to 2048 B of L4 payload is copied with
   `bpf_xdp_load_bytes` and walked by `bpf_loop`. The corpus puts HTTP
   `Host` past byte 422 of L4 and TLS SNI past byte 1294 (X25519MLKEM768
   key_share first, [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024)).
2. **No free-text keywords.** Only structured names are matched, and
   only on DNS label boundaries (reversed FNV-1a of every suffix), so
   `notevil.com` never matches a rule for `evil.com`.
3. **Loud failure.** CI loads XDP with `sudo` on `ubuntu-latest` and
   **exits non-zero** if load/attach fails. No silent skip.

## Build & measure

```bash
sudo apt-get install -y clang llvm libbpf-dev libelf-dev iproute2
make
make test                 # offline unit tests
sudo make ci-xdp          # load+attach on a veth; FAILS if it cannot
sudo make measure         # BPF_PROG_TEST_RUN over the fixed corpus
```

## Layout

| Path | Role |
|------|------|
| `bpf/fw.bpf.c` | `xdp_semfw` + `xdp_l3` |
| `src/measure.c` | verdicts + bench via `BPF_PROG_TEST_RUN` |
| `src/loader.c` | attach (`xdpgeneric` default, `--native` optional) |
| `data/denylist.txt` | 200 domains from urlhaus-filter (see `data/SOURCES.md`) |
| `corpus/` | fixed pcap + labels + MANIFEST (do not regenerate lightly) |
| `docs/PREREGISTRO.md` | thresholds & heuristic, committed before measuring |

## Out of scope / unverified

- Native-NIC Mpps and Mpps ≥ 50 % of an L3 XDP baseline on commodity
  hardware
- Encrypted Client Hello, DoH, DoT
- IPv6 extension headers and IP fragments (PASSed, not inspected)
- Replacing a WAF; ML in the datapath

## License

Apache-2.0. Data: Tranco (MIT), urlhaus-filter (CC0/MIT) — see
`data/SOURCES.md`.
