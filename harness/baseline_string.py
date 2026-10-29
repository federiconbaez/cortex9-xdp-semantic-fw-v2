#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Emulate nftables `string --icase` over every packet of the corpus.

For each denylist domain, a packet is a DROP if the lowercase domain
bytes appear anywhere in the frame. This is the control described in
docs/PREREGISTRO.md; on kernels with xt_string it is equivalent to
loading one rule per domain. Output: index,action (1=DROP,2=PASS).
"""
from __future__ import annotations
import argparse, pathlib, struct, sys

def read_pcap(path):
    data = pathlib.Path(path).read_bytes()
    magic, = struct.unpack_from("<I", data, 0)
    assert magic in (0xA1B2C3D4, 0xD4C3B2A1)
    off = 24
    frames = []
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack_from("<IIII", data, off)
        off += 16
        frames.append(data[off:off + incl])
        off += incl
    return frames

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--deny", required=True)
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()
    deny = [d.strip().lower().encode()
            for d in pathlib.Path(args.deny).read_text().splitlines()
            if d.strip() and not d.startswith("#")]
    frames = read_pcap(args.pcap)
    with open(args.out, "w") as f:
        f.write("# index,action  (1=DROP 2=PASS)  emulated string --icase\n")
        for i, pkt in enumerate(frames):
            low = pkt.lower()
            drop = any(d in low for d in deny)
            f.write(f"{i},{1 if drop else 2}\n")
    print(f"baseline: {len(frames)} packets, {len(deny)} needles", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
