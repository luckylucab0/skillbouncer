"""Proves that the lower-cased whole-file prefilter loses no per-line hit.

Usage: python3 -I verify_prefilter.py <scanner.py> <folder> [<folder> ...]
Prints "lost 0" and exits 0 when the prefilter is a superset; exits 1
otherwise. Run it after every rule change."""
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("scan", sys.argv[1]); scan = importlib.util.module_from_spec(spec); spec.loader.exec_module(scan)
lost = 0; hits = 0; files = 0
for base in sys.argv[2:]:
    for f in Path(base).rglob("*"):
        if not f.is_file() or f.is_symlink(): continue
        # Decoded and folded exactly as scan_file does it; the proof is
        # about that text, not about the raw bytes.
        text = scan.read_text_file(f); low = scan.fold_for_prefilter(text); files += 1
        lines = text.splitlines()
        for rid, sev, desc, rx, code_only in scan.RULES:
            line_hit = any(rx.search(l) for l in lines)
            pre = bool(scan.RULES_PREFILTER[rid].search(low))
            hits += line_hit
            if line_hit and not pre:
                lost += 1; print("LOST", rid, f)
print("files %d, rule hits (file x rule) %d, lost %d" % (files, hits, lost))
sys.exit(1 if lost else 0)
