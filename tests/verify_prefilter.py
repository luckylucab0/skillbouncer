"""Prueft, dass der Vorfilter keinen Treffer der Zeilenpruefung verliert."""
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("scan", sys.argv[1]); scan = importlib.util.module_from_spec(spec); spec.loader.exec_module(scan)
lost = 0; hits = 0; files = 0
for base in sys.argv[2:]:
    for f in Path(base).rglob("*"):
        if not f.is_file() or f.is_symlink() or ".git" in f.parts: continue
        data = f.read_bytes()[: scan.MAX_TEXT_BYTES]
        if b"\x00" in data[:8192]: continue
        text = data.decode("utf-8", "replace"); low = text.lower(); files += 1
        lines = text.splitlines()
        for rid, sev, desc, rx, code_only in scan.RULES:
            line_hit = any(rx.search(l) for l in lines)
            pre = bool(scan.RULES_PREFILTER[rid].search(low))
            hits += line_hit
            if line_hit and not pre:
                lost += 1; print("VERLOREN", rid, f)
print("Dateien %d, Regeltreffer (Datei x Regel) %d, verloren %d" % (files, hits, lost))
