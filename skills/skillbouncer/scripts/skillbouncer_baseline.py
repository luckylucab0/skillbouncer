#!/usr/bin/env python3
"""
skillcheck_baseline.py - Referenzstand (Baseline) installierter Skills
erfassen und mit einem spaeteren Stand vergleichen.

Wozu?
-----
Skills und Plugins aktualisieren sich still im Hintergrund (Marketplace-
Sync, Anthropic-Updates). Wird ein Anbieter kompromittiert, kommt
Schadcode genau auf diesem Weg ("Supply-Chain-Angriff"). Ein einmaliger
Review beim Installieren reicht deshalb nicht: Wir merken uns pro Datei
einen SHA-256-Hash des geprueften Stands. Beim naechsten Lauf zeigt der
Vergleich exakt, welche Dateien neu, geaendert oder verschwunden sind.
Nur diese muessen erneut geprueft werden.

Warum Hashes statt Kopien?
  * Eine Baseline mit vollstaendigen Kopien waere mehrere MB gross und
    wuerde fremde (teils proprietaere) Inhalte duplizieren. Hashes sind
    klein und reichen, um jede Aenderung zu erkennen. Geaenderte Dateien
    werden dann komplett neu gelesen, nicht nur ein Diff.

Einheiten ("units")
-------------------
  * plugin:<name>  - ein Ordner mit .claude-plugin/plugin.json. Der Name
                     kommt aus plugin.json, nicht aus dem Ordnernamen,
                     weil installierte Plugins in Ordnern mit UUID-Namen
                     liegen koennen.
  * skill:<name>   - ein Ordner mit SKILL.md ausserhalb eines Plugins.
  * loose:<root>   - restliche Dateien eines Wurzelordners (z. B. die
                     .skill-Archive in /mnt/skills/public), damit auch
                     dort nichts unbemerkt dazukommt.

Unterbefehle
------------
  snapshot ROOT [ROOT ...] --out snap.json
      Erfasst den aktuellen Stand.
  export --snapshot snap.json --out-dir DIR
      Schreibt je Einheit eine JSON-Datei (fuer ArtifactData-Batch-Writes
      mit file_path, damit grosse Dokumente nicht durch den Chat muessen).
  diff --baseline-dir DIR --snapshot snap.json --out diff.json
      Vergleicht. DIR enthaelt die Baseline-Dokumente als JSON (so, wie
      ArtifactData sie mit out_dir ablegt: DIR/baseline/<id>.json, oder
      direkt DIR/<id>.json). Gibt eine lesbare Zusammenfassung aus und
      schreibt absolute Pfade aller zu pruefenden Dateien in diff.json.

Nur Standardbibliothek; mit "python3 -I" aufrufen (siehe skillcheck_scan.py).
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ordner/Dateien, die sich zur Laufzeit aendern, ohne dass sich der Skill
# aendert. Wuerden sie gehasht, gaebe es bei jedem Lauf Fehlalarme.
IGNORE_NAMES = {".in_use", ".last-complete-round", ".git", "__pycache__", ".DS_Store", "node_modules"}

# Erlaubte Zeichen fuer Dokument-IDs in der Artifact-Datenbank.
DOC_ID_SAFE = re.compile(r"[^A-Za-z0-9_\-.~:@+]")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def doc_id_for(unit_id):
    """Einheit -> gueltige Dokument-ID (max. 200 Zeichen, erlaubte Zeichen)."""
    return DOC_ID_SAFE.sub("_", unit_id)[:200]


def iter_files(base):
    """Alle Dateien unter base, inklusive versteckter, ohne IGNORE_NAMES.
    Symlinks werden nicht verfolgt, aber als eigener Eintrag gehasht
    (Ziel als Text), denn ein neu auftauchender Symlink ist selbst ein
    Warnsignal."""
    for p in sorted(base.rglob("*")):
        if any(part in IGNORE_NAMES for part in p.relative_to(base).parts):
            continue
        if p.is_symlink():
            yield p, "symlink:" + hashlib.sha256(str(p.readlink()).encode()).hexdigest()
        elif p.is_file():
            yield p, sha256_file(p)


def read_json(path):
    try:
        return json.loads(Path(path).read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def load_manifest_info(root):
    """Liest Versions-/Herkunftsangaben aus den manifest.json-Dateien, die
    claude.ai neben die installierten Skills legt. Das hilft spaeter beim
    Einordnen ("Update von Anthropic am 2026-11-03" vs. "unerwartet")."""
    info = {}
    m = read_json(root / "manifest.json")
    for s in m.get("skills", []):
        info["skill:" + s.get("name", "")] = {"source": s.get("source"), "updatedAt": s.get("updatedAt")}
    for p in m.get("plugins", []):
        info["plugin:" + p.get("name", "")] = {"source": p.get("marketplaceName"), "version": p.get("version"), "updatedAt": p.get("updatedAt")}
    return info


def snapshot(roots):
    units = {}
    for root_arg in roots:
        # Der Name fuer Einheiten kommt aus dem angegebenen Pfad
        # (/mnt/skills/plugin-files -> "plugin-files"), nicht aus dem
        # aufgeloesten Ziel: das ist ein Sync-Ordner mit UUID-Namen, der sich
        # zwischen Sitzungen aendern kann und sonst jeden Monat einen
        # Fehlalarm "neu/entfernt" ausloesen wuerde.
        label = Path(root_arg).name
        root = Path(root_arg).resolve()
        meta = load_manifest_info(root)
        claimed = set()  # Dateien, die schon einer Einheit gehoeren

        # 1) Plugins zuerst, damit Skills innerhalb eines Plugins nicht
        #    zusaetzlich als eigene Einheit gezaehlt werden.
        plugin_roots = sorted({pj.parent.parent for pj in root.rglob(".claude-plugin/plugin.json")})
        for pr in plugin_roots:
            pj = read_json(pr / ".claude-plugin" / "plugin.json")
            name = pj.get("name") or pr.name
            uid = "plugin:" + name
            files = {}
            for f, digest in iter_files(pr):
                files[str(f.relative_to(pr))] = digest
                claimed.add(f)
            sidecar = read_json(pr.parent / (pr.name + ".meta.json"))
            units[uid] = {
                "id": uid, "kind": "plugin", "name": name, "path": str(pr),
                "version": pj.get("version") or meta.get(uid, {}).get("version"),
                "source": sidecar.get("marketplace_name") or meta.get(uid, {}).get("source"),
                "updatedAt": meta.get(uid, {}).get("updatedAt"),
                "files": files,
            }

        # 2) Eigenstaendige Skills
        for sk in sorted(root.rglob("SKILL.md")):
            sd = sk.parent
            if sk in claimed or any(sd == pr or pr in sd.parents for pr in plugin_roots):
                continue
            uid = "skill:" + sd.name
            files = {}
            for f, digest in iter_files(sd):
                files[str(f.relative_to(sd))] = digest
                claimed.add(f)
            m = meta.get(uid, {})
            if uid in units:
                # claude.ai legt dieselben Skills teils in mehreren Ordnern ab
                # (user/, organization/, private/ ...). Identische Kopien
                # zaehlen nur einmal; weicht eine Kopie ab, bekommt sie den
                # Wurzelnamen als Zusatz und wird separat verfolgt, denn
                # genau so eine Abweichung waere verdaechtig.
                if units[uid]["files"] == files:
                    continue
                uid = "skill:%s@%s" % (sd.name, label)
            units[uid] = {
                "id": uid, "kind": "skill", "name": sd.name, "path": str(sd),
                "version": None, "source": m.get("source"), "updatedAt": m.get("updatedAt"),
                "files": files,
            }

        # 3) Lose Dateien (Archive, Manifeste, Fremdkoerper)
        loose = {}
        for f, digest in iter_files(root):
            if f in claimed or f.name in ("manifest.json",) or f.name.endswith(".meta.json"):
                continue
            loose[str(f.relative_to(root))] = digest
        if loose:
            uid = "loose:" + label
            units[uid] = {"id": uid, "kind": "loose", "name": label, "path": str(root),
                          "version": None, "source": None, "updatedAt": None, "files": loose}

    for u in units.values():
        # Gesamthash ueber alle Dateien: erlaubt, eine verschobene, aber
        # inhaltlich identische Einheit als "unveraendert" zu erkennen.
        u["unit_hash"] = hashlib.sha256(json.dumps(u["files"], sort_keys=True).encode()).hexdigest()
        u["file_count"] = len(u["files"])
        u["doc_id"] = doc_id_for(u["id"])
    return {"created": datetime.now(timezone.utc).isoformat(timespec="seconds"), "units": units}


def load_baseline_dir(d):
    """Liest Baseline-Dokumente. ArtifactData legt sie unter
    <out_dir>/baseline/<doc_id>.json ab; wir akzeptieren auch flache Ordner.
    Dokumente ohne 'files' (z. B. Konfiguration) werden ignoriert."""
    d = Path(d)
    base = {}
    for p in sorted(d.rglob("*.json")):
        doc = read_json(p)
        doc = doc.get("data", doc) if isinstance(doc, dict) else {}
        if isinstance(doc, dict) and "files" in doc and "id" in doc:
            base[doc["id"]] = doc
    return base


def diff(baseline, snap):
    cur = snap["units"]
    by_hash = {u.get("unit_hash"): uid for uid, u in baseline.items()}
    result = {"new": [], "removed": [], "changed": [], "unchanged": [], "to_review": []}

    for uid, u in sorted(cur.items()):
        b = baseline.get(uid)
        if b is None:
            if u["unit_hash"] in by_hash:
                # Gleicher Inhalt unter anderem Namen/Pfad: nicht neu pruefen.
                result["unchanged"].append(uid)
                continue
            result["new"].append({"id": uid, "version": u.get("version"), "source": u.get("source"), "files": u["file_count"]})
            result["to_review"] += [str(Path(u["path"]) / f) for f in u["files"]]
            continue
        bf, cf = b.get("files", {}), u["files"]
        added = sorted(set(cf) - set(bf))
        removed = sorted(set(bf) - set(cf))
        modified = sorted(f for f in set(cf) & set(bf) if cf[f] != bf[f])
        if added or removed or modified:
            result["changed"].append({
                "id": uid, "old_version": b.get("version"), "new_version": u.get("version"),
                "source": u.get("source"), "added": added, "modified": modified, "removed": removed,
            })
            result["to_review"] += [str(Path(u["path"]) / f) for f in added + modified]
        else:
            result["unchanged"].append(uid)

    for uid in sorted(set(baseline) - set(cur)):
        if baseline[uid].get("unit_hash") not in {u["unit_hash"] for u in cur.values()}:
            result["removed"].append(uid)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot"); s.add_argument("roots", nargs="+"); s.add_argument("--out", required=True)
    e = sub.add_parser("export"); e.add_argument("--snapshot", required=True); e.add_argument("--out-dir", required=True)
    e.add_argument("--reviewed-by", default="skillcheck"); e.add_argument("--verdict", default="CLEAN")
    e.add_argument("--only", nargs="*", help="Nur diese Einheiten-IDs exportieren")
    d = sub.add_parser("diff"); d.add_argument("--baseline-dir", required=True); d.add_argument("--snapshot", required=True); d.add_argument("--out", required=True)
    a = ap.parse_args()

    if a.cmd == "snapshot":
        snap = snapshot(a.roots)
        Path(a.out).write_text(json.dumps(snap, indent=1), "utf-8")
        print("Snapshot: %d Einheiten, %d Dateien -> %s" % (
            len(snap["units"]), sum(u["file_count"] for u in snap["units"].values()), a.out))

    elif a.cmd == "export":
        snap = json.loads(Path(a.snapshot).read_text("utf-8"))
        out = Path(a.out_dir); out.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        n = 0
        for uid, u in snap["units"].items():
            if a.only and uid not in a.only:
                continue
            doc = dict(u)
            doc.pop("path", None)  # Pfade sind sitzungsabhaengig, nicht Teil des Referenzstands
            doc.update({"reviewed_at": now, "reviewed_by": a.reviewed_by, "verdict": a.verdict})
            (out / (u["doc_id"] + ".json")).write_text(json.dumps(doc, indent=1), "utf-8")
            n += 1
        print("%d Baseline-Dokumente nach %s geschrieben" % (n, out))

    elif a.cmd == "diff":
        base = load_baseline_dir(a.baseline_dir)
        snap = json.loads(Path(a.snapshot).read_text("utf-8"))
        r = diff(base, snap)
        Path(a.out).write_text(json.dumps(r, indent=1), "utf-8")
        print("Baseline: %d Einheiten | aktuell: %d" % (len(base), len(snap["units"])))
        print("unveraendert: %d | neu: %d | geaendert: %d | entfernt: %d | zu pruefende Dateien: %d" % (
            len(r["unchanged"]), len(r["new"]), len(r["changed"]), len(r["removed"]), len(r["to_review"])))
        for n in r["new"]:
            print("  NEU       %s (Version %s, Quelle %s, %d Dateien)" % (n["id"], n["version"], n["source"], n["files"]))
        for c in r["changed"]:
            print("  GEAENDERT %s (%s -> %s): +%d ~%d -%d" % (c["id"], c["old_version"], c["new_version"], len(c["added"]), len(c["modified"]), len(c["removed"])))
        for uid in r["removed"]:
            print("  ENTFERNT  %s" % uid)
        # Exit-Code 1 signalisiert "es gibt etwas zu pruefen".
        sys.exit(1 if (r["new"] or r["changed"]) else 0)


if __name__ == "__main__":
    main()
