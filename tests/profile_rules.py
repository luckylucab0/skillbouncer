"""Misst, wie lange jede Regel des Scanners ueber alle Textdateien braucht.
Aufruf: python3 -I profile_rules.py <scanner.py> <ordner> [<ordner> ...]"""
import importlib.util
import sys
import time
from pathlib import Path

spec = importlib.util.spec_from_file_location("scan", sys.argv[1])
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

texts = []
for base in sys.argv[2:]:
    for f in Path(base).rglob("*"):
        if not f.is_file() or f.is_symlink() or ".git" in f.parts:
            continue
        ext = f.suffix.lower()
        if ext in scan.BENIGN_BINARY_EXT or ext in scan.DANGEROUS_BINARY_EXT:
            continue
        data = f.read_bytes()[: scan.MAX_TEXT_BYTES]
        if b"\x00" in data[:8192]:
            continue
        texts.append((f, data.decode("utf-8", "replace")))
print("Dateien:", len(texts))

timings = []
for rid, sev, desc, rx, code_only in scan.RULES:
    t = time.perf_counter()
    for f, text in texts:
        for line in text.splitlines():
            rx.search(line)
    timings.append((time.perf_counter() - t, "RULE " + rid))
for cid, _, rx in scan.CAPABILITIES:
    t = time.perf_counter()
    for f, text in texts:
        rx.search(text)
    timings.append((time.perf_counter() - t, "CAP " + cid))
t = time.perf_counter()
for f, text in texts:
    list(scan.HEX_BLOB_RE.finditer(text)); list(scan.B64_RE.finditer(text))
timings.append((time.perf_counter() - t, "BLOBS"))
for dt, name in sorted(timings, reverse=True)[:15]:
    print("%8.2fs  %s" % (dt, name))
print("Summe: %.1fs" % sum(d for d, _ in timings))
