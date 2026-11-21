"""Generate JARM known-answer vectors from the reference jarm.py (not vendored).

Usage: python3 -I katgen.py <path/to/jarm.py> <outdir> <name=dump.hex>...
Writes:
  <outdir>/clienthello_golden.txt  - 10 ClientHello hex with deterministic entropy, SNI "kat.example"
  <outdir>/<name>.kat              - line 1..10: server response hex, then raw results, then hash
"""
import codecs, hashlib, itertools, os, random, struct, sys

src_path, outdir = sys.argv[1], sys.argv[2]
src = open(src_path).read().splitlines()
start = next(i for i, l in enumerate(src) if l.startswith("def choose_grease"))
end = next(i for i, l in enumerate(src) if l.startswith("def ParseNumber"))
ns = {"codecs": codecs, "hashlib": hashlib, "os": os, "random": random, "struct": struct}
exec("\n".join(src[start - 1:end]), ns)

# Deterministic entropy, mirrored by kat entropy in jarm_test.go.
ctr = itertools.count()
gctr = itertools.count()
ns["os"] = type("O", (), {"urandom": staticmethod(lambda n: bytes(next(ctr) & 0xFF for _ in range(n)))})
ns["random"] = type("R", (), {"choice": staticmethod(lambda lst: lst[next(gctr) % len(lst)])})

H = "kat.example"
queue = [
    [H, 443, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"],
    [H, 443, "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"],
    [H, 443, "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
    [H, 443, "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"],
    [H, 443, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"],
    [H, 443, "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
    [H, 443, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"],
    [H, 443, "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"],
    [H, 443, "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"],
    [H, 443, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"],
]
with open(os.path.join(outdir, "clienthello_golden.txt"), "w") as f:
    for q in queue:
        f.write(ns["packet_building"](q).hex() + "\n")

for arg in sys.argv[3:]:
    name, dump = arg.split("=", 1)
    lines = open(dump).read().split("\n")[:10]
    raws = []
    for l in lines:
        data = bytearray(bytes.fromhex(l)) if l.strip() else None
        raws.append(ns["read_packet"](data, None))
    h = ns["jarm_hash"](",".join(raws))
    with open(os.path.join(outdir, name + ".kat"), "w") as f:
        for l in lines:
            f.write(l + "\n")
        for r in raws:
            f.write(r + "\n")
        f.write(h + "\n")
    print(name, h)
