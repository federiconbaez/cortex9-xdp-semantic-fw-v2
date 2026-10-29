# SPDX-License-Identifier: Apache-2.0
"""Byte-exact packet builders (stdlib only) with real-world header sizes.

Everything is deterministic given a random.Random instance, so a corpus
generated with a fixed seed is reproducible bit for bit.
"""
import random
import struct

MSS4 = 1448  # 1500 MTU - 20 IPv4 - 32 TCP (with timestamps)
MSS6 = 1428  # 1500 MTU - 40 IPv6 - 32 TCP


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(payload: bytes, ethertype: int, src=b"\x02\x00\x00\x00\x00\x01",
        dst=b"\x02\x00\x00\x00\x00\x02") -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes, ident=0, ttl=64,
         options=b"") -> bytes:
    ihl = 5 + len(options) // 4
    hdr = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, 20 + len(options) + len(payload),
                      ident, 0x4000, ttl, proto, 0, src, dst) + options
    c = csum(hdr)
    hdr = hdr[:10] + struct.pack("!H", c) + hdr[12:]
    return hdr + payload


def ipv6(src: bytes, dst: bytes, nh: int, payload: bytes, hlim=64) -> bytes:
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), nh, hlim, src, dst) + payload


def _pseudo(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    if len(src) == 4:
        return src + dst + struct.pack("!BBH", 0, proto, length)
    return src + dst + struct.pack("!IxxxB", length, proto)


def udp(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    h = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    c = csum(_pseudo(src, dst, 17, 8 + len(payload)) + h + payload) or 0xFFFF
    return h[:6] + struct.pack("!H", c) + payload


def tcp(src: bytes, dst: bytes, sport: int, dport: int, seq: int, ack: int,
        payload: bytes, flags=0x18, tsval=0, tsecr=0, window=502) -> bytes:
    # NOP NOP Timestamps (10) -> 12 bytes of options, doff = 8 (32 bytes)
    opts = b"\x01\x01\x08\x0a" + struct.pack("!II", tsval, tsecr)
    doff = (20 + len(opts)) // 4
    h = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, doff << 4, flags, window, 0, 0) + opts
    c = csum(_pseudo(src, dst, 6, len(h) + len(payload)) + h + payload)
    return h[:16] + struct.pack("!H", c) + h[18:] + payload


# ---------------------------------------------------------------- DNS
def dns_qname_wire(name: str) -> bytes:
    out = b""
    for lab in name.rstrip(".").split("."):
        b = lab.encode()
        assert 0 < len(b) <= 63, (name, lab)
        out += bytes([len(b)]) + b
    return out + b"\0"


def dns_query(name: str, rng: random.Random, qtype=1, edns=True, cookie=False) -> bytes:
    hdr = struct.pack("!HHHHHH", rng.getrandbits(16), 0x0100, 1, 0, 0, 1 if edns else 0)
    q = dns_qname_wire(name) + struct.pack("!HH", qtype, 1)
    add = b""
    if edns:
        rdata = b""
        if cookie:  # RFC 7873 client cookie (8 bytes)
            rdata = struct.pack("!HH", 10, 8) + rng.randbytes(8)
        add = b"\0" + struct.pack("!HHIH", 41, 1232, 0, len(rdata)) + rdata
    return hdr + q + add


def case_0x20(name: str, rng: random.Random) -> str:
    return "".join(c.upper() if c.isalpha() and rng.random() < 0.5 else c for c in name)


# ---------------------------------------------------------------- TLS
GREASE = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
          0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA]
X25519MLKEM768 = 0x11EC  # RFC 10024, client share 1216 bytes


def _ext(t: int, body: bytes) -> bytes:
    return struct.pack("!HH", t, len(body)) + body


def _v16(b: bytes) -> bytes:
    return struct.pack("!H", len(b)) + b


def client_hello(sni: str, rng: random.Random, pq: bool, shuffle: bool,
                 grease: bool, alpn=(b"h2", b"http/1.1")) -> bytes:
    """A TLS 1.3 ClientHello record. pq=True adds an X25519MLKEM768 key share
    (1216 B) so the record no longer fits in one TCP segment."""
    g = rng.choice(GREASE)
    suites = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
              0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    if grease:
        suites = [g] + suites
    groups = ([g] if grease else []) + ([X25519MLKEM768] if pq else []) + [0x001D, 0x0017, 0x0018]
    shares = b""
    if grease:
        shares += struct.pack("!HH", g, 1) + b"\0"
    if pq:
        shares += struct.pack("!HH", X25519MLKEM768, 1216) + rng.
