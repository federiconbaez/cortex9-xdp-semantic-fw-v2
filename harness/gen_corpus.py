#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the FIXED corpus described in docs/PREREGISTRO.md.

Refuses to overwrite an existing corpus/ directory that already
contains labels.csv — regenerate only after deleting it deliberately.
"""
from __future__ import annotations
import argparse, csv, hashlib, os, pathlib, random, struct, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEED = 20261029
BASE32 = "abcdefghijklmnopqrstuvwxyz234567"

def u16(n): return struct.pack("!H", n)
def u24(n): return struct.pack("!I", n)[1:]

def pcap_write(path: pathlib.Path, frames: list[bytes]) -> None:
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(frames):
            f.write(struct.pack("<IIII", i, 0, len(pkt), len(pkt)))
            f.write(pkt)

def eth_ip4(payload: bytes, proto: int, sport: int, dport: int, tcp: bool) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
    # IPv4 header
    tot = 20 + len(payload)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = u16(tot)
    ip[8] = 64
    ip[9] = proto
    ip[12:16] = bytes((10, 0, 0, 1))
    ip[16:20] = bytes((10, 0, 0, 2))
    # checksum
    s = sum(struct.unpack("!10H", ip))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    ip[10:12] = u16((~s) & 0xFFFF)
    return eth + bytes(ip) + payload

def udp(payload: bytes, sport: int, dport: int) -> bytes:
    hdr = u16(sport) + u16(dport) + u16(8 + len(payload)) + u16(0)
    return eth_ip4(hdr + payload, 17, sport, dport, False)

def tcp(payload: bytes, sport: int, dport: int) -> bytes:
    # 20-byte TCP header, ACK+PSH, no options
    seq = b"\x00\x00\x00\x01"
    ack = b"\x00\x00\x00\x02"
    hdr = u16(sport) + u16(dport) + seq + ack + b"\x50\x18" + u16(65535) + u16(0) + u16(0)
    return eth_ip4(hdr + payload, 6, sport, dport, True)

def dns_qname(name: str) -> bytes:
    out = bytearray()
    for lab in name.rstrip(".").split("."):
        b = lab.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)

def dns_query(name: str, txid: int) -> bytes:
    hdr = u16(txid) + u16(0x0100) + u16(1) + u16(0) * 3
    q = dns_qname(name) + u16(1) + u16(1)  # A IN
    return udp(hdr + q, 53000 + (txid % 1000), 53)

def tls_clienthello(sni: str, pad_keyshare: bool = True) -> bytes:
    """Build a TLS 1.2-looking ClientHello whose SNI is `sni`.

    When pad_keyshare is True we include an X25519MLKEM768 key_share
    (1216 B client share, RFC 10024) so the SNI sits well past the
    192/263-byte region that defeated v1. The record version and
    handshake contents are otherwise minimal and need not be a valid
    TLS handshake — only the wire layout of the SNI extension matters
    to the XDP parser.
    """
    sni_b = sni.encode("ascii")
    # server_name extension
    sni_list = b"\x00" + u16(len(sni_b)) + sni_b          # type=host_name
    sni_ext = u16(0) + u16(2 + len(sni_list)) + u16(len(sni_list)) + sni_list
    # supported_versions (TLS1.3)
    sv = u16(43) + u16(3) + b"\x02\x03\x04"
    # key_share FIRST (X25519MLKEM768, RFC 10024, 1216 B client share) so
    # the SNI sits past the 192 B window that defeated v1. Real clients
    # often emit key_share before SNI when PQ groups are negotiated.
    if pad_keyshare:
        share = b"\x11" * 1216
        ks_entry = u16(0x11EC) + u16(len(share)) + share
        ks = u16(51) + u16(2 + len(ks_entry)) + u16(len(ks_entry)) + ks_entry
    else:
        share = b"\x11" * 32
        ks_entry = u16(0x001D) + u16(len(share)) + share
        ks = u16(51) + u16(2 + len(ks_entry)) + u16(len(ks_entry)) + ks_entry
    exts = ks + sv + sni_ext
    # body: version + random + session_id + ciphers + compression + exts
    body = (b"\x03\x03" + os.urandom(32) + b"\x00"
            + u16(2) + u16(0x1301) + b"\x01\x00"
            + u16(len(exts)) + exts)
    hs = b"\x01" + u24(len(body)) + body
    rec = b"\x16\x03\x01" + u16(len(hs)) + hs
    return tcp(rec, 40000, 443)

def http_get(host: str, fat_headers: bool = True) -> bytes:
    """HTTP/1.1 GET whose Host header sits after a 263-byte block when
    fat_headers is True (the v1 failure mode)."""
    lines = [f"GET /index.html HTTP/1.1"]
    if fat_headers:
        # Build ~263 bytes of headers BEFORE Host, matching the
        # streamable profile size that made v1 drop to 0% blocking.
        pad = (
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Connection: keep-alive\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "Cache-Control: max-age=0\r\n"
            "Cookie: session=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF\r\n"
        )
        lines.append(pad.rstrip("\r\n"))
    lines.append(f"Host: {host}")
    lines.append("")
    lines.append("")
    body = "\r\n".join(lines).encode("ascii")
    return tcp(body, 41000, 80)

def tunnel_qname(rng: random.Random) -> str:
    """QNAME with one label >= 50 base32 chars and total >= 150."""
    lab = "".join(rng.choice(BASE32) for _ in range(60))
    # pad with more labels so total length >= 150
    rest = []
    while 1 + len(lab) + 1 + sum(len(x) + 1 for x in rest) < 160:
        rest.append("".join(rng.choice(BASE32) for _ in range(40)))
    return ".".join([lab] + rest + ["tunnel", "example"])

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    out = ROOT / "corpus"
    labels = out / "labels.csv"
    if labels.exists() and not args.force:
        print(f"REFUSING: {labels} already exists (delete or --force)", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    legit = (ROOT / "data" / "legit-domains.txt").read_text().splitlines()
    deny = [d for d in (ROOT / "data" / "denylist.txt").read_text().splitlines()
            if d and not d.startswith("#")]
    rng = random.Random(SEED)
    # Deterministic domain picks
    legit_dns = [legit[i % len(legit)] for i in range(4000)]
    legit_sni = [legit[(i + 17) % len(legit)] for i in range(4000)]
    legit_http = [legit[(i + 97) % len(legit)] for i in range(2000)]
    atk_sni = [deny[i % len(deny)] for i in range(400)]
    atk_http = [deny[(i + 7) % len(deny)] for i in range(200)]

    frames: list[bytes] = []
    rows: list[tuple] = []
    idx = 0
    def add(pkt, kind, label, name):
        nonlocal idx
        frames.append(pkt)
        rows.append((idx, kind, label, name, len(pkt)))
        idx += 1

    for i, d in enumerate(legit_dns):
        add(dns_query(d, i), "dns", "legit", d)
    for i, d in enumerate(legit_sni):
        add(tls_clienthello(d, True), "sni", "legit", d)
    for i, d in enumerate(legit_http):
        add(http_get(d, True), "http", "legit", d)
    for i in range(400):
        n = tunnel_qname(rng)
        add(dns_query(n, 50000 + i), "dns-tunnel", "attack", n)
    for i, d in enumerate(atk_sni):
        add(tls_clienthello(d, True), "sni-deny", "attack", d)
    for i, d in enumerate(atk_http):
        add(http_get(d, True), "http-deny", "attack", d)

    assert len(frames) == 11000, len(frames)
    pcap_write(out / "corpus.pcap", frames)
    with labels.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["index", "kind", "label", "name", "pkt_len"])
        w.writerows(rows)
    # Manifest with hashes — committed alongside the corpus
    h_pcap = hashlib.sha256((out / "corpus.pcap").read_bytes()).hexdigest()
    h_lab = hashlib.sha256(labels.read_bytes()).hexdigest()
    (out / "MANIFEST").write_text(
        f"seed={SEED}\n"
        f"n_legit=10000\n"
        f"n_attack=1000\n"
        f"corpus.pcap sha256={h_pcap}\n"
        f"labels.csv sha256={h_lab}\n"
        f"generator=harness/gen_corpus.py\n"
    )
    print(f"wrote {len(frames)} frames; pcap={h_pcap[:16]}…")
    # Sanity: Host offset for a fat HTTP packet
    sample = frames[8000]  # first HTTP legit
    # find Host:
    pos = sample.find(b"\nHost:")
    print(f"sample HTTP Host offset from Ethernet = {pos}; pkt_len={len(sample)}")
    sample_sni = frames[4000]
    pos2 = sample_sni.find(b"\x00\x00")  # rough
    print(f"sample SNI pkt_len={len(sample_sni)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
