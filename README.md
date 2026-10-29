# cortex9-xdp-semantic-fw-v2

XDP semantic firewall that parses **DNS QNAME** (UDP/53), **TLS
ClientHello SNI** (TCP/443) and **HTTP/1.x Host** (TCP/80) at their
real offsets and drops packets whose name falls under a denylisted
domain (plus a pre-registered DNS-tunnelling heuristic).

This is a remake of
[`cortex9-xdp-semantic-firewall`](https://github.com/federiconbaez/cortex9-xdp-semantic-firewall)
that failed its value threshold (FPR 5.3–13.9 points over tolerance;
0 % blocking with 263-byte real headers because of a fixed 192-byte
window). See [`docs/PREREGISTRO.md`](docs/PREREGISTRO.md) for the
pre-registered thresholds and corpus, committed **before** measuring.

## Status

Measurement pending — see `results/` after `make measure`.

## What is verified / what is not

| Claim | Status |
|-------|--------|
| TPR ≥ 90 % on 1000 attacks | pending |
| FPR ≤ 1 % on 10000 legit | pending |
| XDP loads and attaches (`xdpgeneric`) on CI `ubuntu-latest` | pending (job fails loudly if it cannot) |
| Mpps on a physical NIC | **unverified** |
| Encrypted Client Hello / DoH / DoT | out of scope |
| IPv6 extension headers / IP fragments | PASSed, not inspected |

## Build

```bash
sudo apt-get install -y clang llvm libbpf-dev libelf-dev
make
sudo make measure   # loads the REAL bytecode via BPF_PROG_TEST_RUN
```

## License

Apache-2.0. Data: Tranco (MIT), urlhaus-filter (CC0/MIT) — see
`data/SOURCES.md`.
