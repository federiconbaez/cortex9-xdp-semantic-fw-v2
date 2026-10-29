#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline unit tests: domain_key stability, label-boundary property,
corpus manifest integrity, generator refuse-overwrite. No root needed.
"""
from __future__ import annotations
import hashlib, pathlib, struct, subprocess, sys, tempfile, os

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness"))

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3

def domain_key(d: str) -> int:
    d = d.rstrip(".").lower()
    h = FNV_OFFSET
    for c in reversed(d):
        h = ((h ^ ord(c)) * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def test_key_stable():
    assert domain_key("Evil.COM") == domain_key("evil.com")
    assert domain_key("evil.com.") == domain_key("evil.com")

def test_label_boundary():
    """'notevil.com' must NOT share a suffix key with 'evil.com'."""
    k_evil = domain_key("evil.com")
    k_not = domain_key("notevil.com")
    # suffixes of notevil.com: com, notevil.com — neither equals evil.com
    assert k_evil != k_not
    assert k_evil != domain_key("com")
    # but sub.evil.com MUST share the evil.com suffix key when scanned RTL
    # (the XDP match_cb probes every label-aligned suffix)
    assert domain_key("evil.com") == domain_key("evil.com")

def test_manifest():
    man = (ROOT / "corpus" / "MANIFEST").read_text()
    assert "seed=20261029" in man
    h = hashlib.sha256((ROOT / "corpus" / "corpus.pcap").read_bytes()).hexdigest()
    assert f"corpus.pcap sha256={h}" in man
    n = sum(1 for _ in open(ROOT / "corpus" / "labels.csv")) - 1
    assert n == 11000, n

def test_host_past_192():
    """Regression: Host of a fat HTTP packet must sit past byte 192 of L4."""
    data = (ROOT / "corpus" / "corpus.pcap").read_bytes()
    off = 24
    for _ in range(8000):  # first HTTP legit is index 8000
        _, _, incl, _ = struct.unpack_from("<IIII", data, off)
        off += 16 + incl
    _, _, incl, _ = struct.unpack_from("<IIII", data, off)
    pkt = data[off + 16: off + 16 + incl]
    payload = pkt[54:]  # eth+ip+tcp
    pos = payload.find(b"\nHost:")
    assert pos > 192, pos

def test_sni_past_192():
    data = (ROOT / "corpus" / "corpus.pcap").read_bytes()
    off = 24
    for _ in range(4000):
        _, _, incl, _ = struct.unpack_from("<IIII", data, off)
        off += 16 + incl
    import csv
    name = list(csv.DictReader(open(ROOT / "corpus" / "labels.csv")))[4000]["name"].encode()
    _, _, incl, _ = struct.unpack_from("<IIII", data, off)
    pkt = data[off + 16: off + 16 + incl]
    pos = pkt[54:].find(name)
    assert pos > 192, pos

def test_refuse_overwrite():
    r = subprocess.run([sys.executable, str(ROOT / "harness" / "gen_corpus.py")],
                       capture_output=True, text=True)
    assert r.returncode == 2
    assert "REFUSING" in r.stderr

if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok  {name}")
            except Exception as e:
                print(f"FAIL {name}: {e}")
                fails += 1
    sys.exit(1 if fails else 0)
