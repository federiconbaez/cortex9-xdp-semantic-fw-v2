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

### Adversarial reading of the 100 % TPR

**The 100 % TPR is by construction, not a claim about detecting unknown
threats.** Read it that way:

- **600 of 1000 attacks** put a domain from `data/denylist.txt` in the
  SNI or `Host` field. The program drops when that exact name (or a
  label-aligned suffix) is in the BPF map. Catching them proves the
  parser finds the name at a *real* offset (SNI past byte 1294 of L4
  with an X25519MLKEM768 key_share first; `Host` past byte 422) and
  that label-boundary matching does not invent substring hits — it
  does **not** prove the denylist knows about tomorrow's phishing
  domain.
- **400 of 1000 attacks** are DNS queries whose QNAME was *generated*
  to trip the pre-registered tunnelling heuristic (`TUN_LABEL=50`,
  `TUN_TOTAL=150` in `bpf/fw_common.h`): one base32 label of length 60
  and a total QNAME ≥ 160. The generator and the thresholds were
  written together on purpose. Catching them proves the heuristic
  fires when those constants say it should — it does **not** prove
  those cut-offs separate real tunnels from real long-but-legit names
  on the public Internet.

What this measurement *does* show, and what v1 could not:

1. Correct parsing of DNS QNAME / TLS SNI / HTTP Host at offsets past
   the old 192-byte window.
2. Label-boundary denylist matching with **0** substring false
   positives on 10000 Tranco-derived legit flows (FPR 0 %).
3. The nftables `string --icase` control still misses all 400 tunnel
   queries (TPR 60 %), so the structured path is doing work the
   baseline cannot.

#### How `TUN_LABEL` / `TUN_TOTAL` were chosen

They are **engineering defaults**, not fitted to a labelled tunnel
corpus:

- DNS labels are at most 63 octets (RFC 1035). Lengths ≥ 50 leave
  little room for anything but encoded payload in a single label —
  a common shape in DNS-tunnel tools — without yet forbidding every
  long-but-legit label.
- A whole QNAME ≥ 150 octets is well above typical interactive names
  and below the 255-octet absolute maximum, so it is a coarse “this
  name is carrying bulk data” tripwire.

They were **fixed in commit `c9674cb`** (the first commit of this
repo: `docs/PREREGISTRO.md`, `bpf/fw_common.h`, and the corpus
generator that emits labels of length 60 / total ≥ 160) **before**
any `BPF_PROG_TEST_RUN` measurement. The measurement commit is
`fd01f4be`. The constants were not tuned afterwards.

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
