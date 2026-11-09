#!/usr/bin/env python3
"""
skillbouncer_baseline.py - record the reviewed state (baseline) of installed
skills and plugins and compare it with a later state.

Why?
----
Skills and plugins update silently in the background (marketplace sync,
vendor updates). If a vendor gets compromised, malicious code arrives by
exactly that route (a "supply-chain attack"). A one-time review at install
time is therefore not enough: per file we remember a SHA-256 hash of the
reviewed state. On the next run the comparison shows exactly which files
are new, changed or gone. Only those need another review.

Why hashes and not copies?
  * A baseline of full copies would be several MB and would duplicate
    third-party (partly proprietary) content. Hashes are small and enough
    to detect any change. Changed files are then read again in full, not
    just as a diff.

Units
-----
  * plugin:<name>  - a folder with .claude-plugin/plugin.json. The name
                     comes from plugin.json, not from the folder name,
                     because installed plugins can live in folders named
                     by UUID.
  * skill:<name>   - a folder with SKILL.md outside any plugin.
  * loose:<root>   - the remaining files of a root (e.g. the .skill
                     archives next to the bundled skills), so that nothing
                     gets added there unnoticed either.

Subcommands
-----------
  snapshot (--auto [--root DIR ...] | ROOT [ROOT ...]) --out snap.json
      Records the current state. --auto discovers the install locations
      at runtime; they differ between Claude products and sessions. Exits
      2 when a root given explicitly does not exist or when no unit at all
      is found: an empty snapshot would read as "nothing changed" forever.
  export --snapshot snap.json --out-dir DIR [--only ID ...] [--verdict V]
      Writes one JSON document per unit into DIR. How those documents get
      into the user's baseline store (a database, a private repository) is
      not this script's business; it only ever sees JSON directories.
  diff --baseline-dir DIR --snapshot snap.json --out diff.json
      Compares. DIR holds the baseline documents as JSON, directly or in
      subfolders (DIR/baseline/<id>.json works too). Prints a readable
      summary and writes the absolute paths of everything to review into
      diff.json. Exit 1 = something to review, including "the scanner
      rules changed since the baseline was written"; 0 = nothing.
  names --snapshot snap.json --out names.txt
      Writes the names of all installed skills, one per line, for the
      scanner's --known-names option.
  selfcheck (--expect HASH:PATH[,HASH:PATH ...] | --expect-file FILE | --print)
      Hashes this script, the scanner and SKILL.md and compares them with
      hashes kept outside the sandbox. Exit 2 on any mismatch or missing
      expectation.

node_modules
------------
Dependency folders are part of what gets executed, so they are covered.
To keep baseline documents small, each node_modules/<package>/ directory
becomes one entry (a SHA-256 over its sorted file paths and file hashes)
with a trailing slash in its key. A plugin with 800 packages then adds
800 entries of about 110 bytes each, roughly 90 KB, where one entry per
file would add several MB. Stores with a per-document cap (1 MiB is
common) stay usable that way. The price: a changed package is reported as
a whole directory, not per file; scan and read that directory.

Standard library only; run with "python3 -I" (see skillbouncer_scan.py).
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Folders/files that change at runtime without the skill changing. Hashing
# them would raise a false alarm on every run. node_modules is deliberately
# not in this list (see module docstring).
IGNORE_NAMES = {".in_use", ".last-complete-round", ".git", "__pycache__", ".DS_Store"}

# Characters allowed in document IDs of common document stores.
DOC_ID_SAFE = re.compile(r"[^A-Za-z0-9_\-.~:@+]")

HOME = Path.home()
# Where Claude products keep installed skills and plugins. Checked at
# runtime because no single session has all of them. Folders with a
# "synced" child are expanded: each sync folder becomes its own root.
AUTO_CANDIDATES = [
    HOME / ".claude" / "plugins" / "synced",
    HOME / ".claude" / "plugins" / "cache",
    HOME / ".claude" / "skills",
    Path("/mnt/skills/user"),
    Path("/mnt/skills/public"),
    Path("/mnt/skills/plugin-files"),
    Path("/mnt/skills/organization"),
    Path("/mnt/skills/private"),
    Path("/mnt/skills/plugins"),
    Path("/mnt/user-data/skills"),
]
# Shipped examples, not installed: nothing loads them.
AUTO_SKIPPED = [Path("/mnt/skills/examples")]

SELF_FILES = ("scripts/skillbouncer_scan.py", "scripts/skillbouncer_baseline.py", "SKILL.md")


def fail(msg):
    """Exit 2 with a message. Used wherever silence would look like a pass."""
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def tool_version():
    """VERSION of the scanner next to this script, read as text. Importing
    the scanner would work too, but under "python3 -I" the script folder is
    not on sys.path, and a version string does not justify loading code."""
    scan = Path(__file__).resolve().parent / "skillbouncer_scan.py"
    try:
        m = re.search(r'^VERSION = "([^"]+)"', scan.read_text("utf-8"), re.M)
    except OSError:
        m = None
    if not m:
        fail("cannot read VERSION from %s; the baseline would not record which rules reviewed it" % scan)
    return m.group(1)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def doc_id_for(unit_id):
    """Unit -> valid document ID (max. 200 characters, allowed characters)."""
    return DOC_ID_SAFE.sub("_", unit_id)[:200]


def entry_hash(p):
    """Hash of one directory entry, or None for anything that is neither a
    file nor a symlink. Symlinks are not followed but hashed as an entry of
    their own (the target as text), because a symlink that newly appears
    is a warning sign in itself."""
    if p.is_symlink():
        return "symlink:" + hashlib.sha256(str(p.readlink()).encode()).hexdigest()
    if p.is_file():
        return sha256_file(p)
    return None


def iter_files(base, exclude=()):
    """Yields (path, digest) for everything under base, hidden files
    included, minus IGNORE_NAMES and the folders in exclude. Each
    node_modules/<package>/ directory yields a single (directory, "dir:...")
    pair instead of one pair per file."""
    packages = {}
    for p in sorted(base.rglob("*")):
        parts = p.relative_to(base).parts
        if any(part in IGNORE_NAMES for part in parts):
            continue
        if any(p == e or e in p.parents for e in exclude):
            continue
        digest = entry_hash(p)
        if digest is None:
            continue
        if "node_modules" in parts[:-1]:
            i = parts.index("node_modules")
            # @scope/name packages sit one level deeper.
            depth = i + 3 if parts[i + 1].startswith("@") else i + 2
            if len(parts) > depth:
                pkg = base.joinpath(*parts[:depth])
                packages.setdefault(pkg, []).append("%s\0%s\n" % ("/".join(parts[depth:]), digest))
                continue
        yield p, digest
    for pkg, lines in sorted(packages.items()):
        yield pkg, "dir:" + hashlib.sha256("".join(sorted(lines)).encode()).hexdigest()


def rel_key(path, base):
    """Key of an entry in a unit's file map. Aggregated directories get a
    trailing slash so they cannot be mistaken for a file of that name."""
    rel = str(path.relative_to(base))
    return rel + "/" if path.is_dir() and not path.is_symlink() else rel


def read_json(path):
    try:
        data = json.loads(Path(path).read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load_manifest_info(root):
    """Reads version and origin from the manifest.json files that Claude
    places next to installed skills and plugins. That helps later to judge
    a change ("vendor update on 2026-11-03" versus "unexpected")."""
    info = {}
    m = read_json(root / "manifest.json")
    for s in m.get("skills", []) or []:
        if isinstance(s, dict):
            info["skill:" + str(s.get("name", ""))] = {"source": s.get("source"), "updatedAt": s.get("updatedAt")}
    for p in m.get("plugins", []) or []:
        if isinstance(p, dict):
            info["plugin:" + str(p.get("name", ""))] = {"source": p.get("marketplaceName"), "version": p.get("version"), "updatedAt": p.get("updatedAt")}
    return info


def discover_roots(extra):
    """Roots for "snapshot --auto": (path, label, excluded folders) per
    root, plus the candidates that do not exist here. Labels must not
    depend on sync-folder names: those contain account IDs and may change,
    which would make every "loose:" unit look new."""
    found, missing = [], []
    seen = set()

    def add(path, label, exclude=()):
        real = path.resolve()
        if real in seen:
            return
        seen.add(real)
        found.append((path, label, tuple(exclude)))

    for cand in AUTO_CANDIDATES:
        if not cand.is_dir():
            missing.append(cand)
            continue
        base_label = "%s-%s" % (cand.parent.name, cand.name) if cand.name in ("synced", "cache") else cand.name
        sync_parent = cand if cand.name == "synced" else cand / "synced"
        sync_dirs = sorted(d for d in sync_parent.iterdir() if d.is_dir() and not d.is_symlink()) if sync_parent.is_dir() else []
        sync_label = base_label if cand.name == "synced" else base_label + "-synced"
        for n, d in enumerate(sync_dirs, 1):
            add(d, sync_label if n == 1 else "%s-%d" % (sync_label, n))
        # The parent stays a root for whatever lies next to the sync
        # folders (marker files, skills installed by hand).
        add(cand, base_label + "-root" if cand.name == "synced" else base_label, [d.resolve() for d in sync_dirs])
    for e in extra:
        p = Path(e)
        if not p.is_dir():
            fail("root given with --root does not exist: %s" % e)
        add(p, p.name)
    return found, missing


def snapshot(roots):
    """roots: list of (path, label, excluded folders)."""
    units = {}

    def store(uid, label, unit):
        # The same unit can be installed in several roots. Identical copies
        # count once; a differing copy gets the root label appended and is
        # tracked separately, because exactly that difference is suspicious.
        if uid in units:
            if units[uid]["files"] == unit["files"]:
                return
            uid = "%s@%s" % (uid, label)
        unit["id"] = uid
        units[uid] = unit

    for root_arg, label, exclude in roots:
        root = Path(root_arg).resolve()
        meta = load_manifest_info(root)
        claimed = set()  # entries that already belong to a unit

        def inside(p):
            return not any(p == e or e in p.parents for e in exclude)

        # 1) Plugins first, so that skills inside a plugin are not counted
        #    again as units of their own.
        plugin_roots = sorted({pj.parent.parent for pj in root.rglob(".claude-plugin/plugin.json")
                               if inside(pj) and not any(part in IGNORE_NAMES or part == "node_modules" for part in pj.relative_to(root).parts)})
        for pr in plugin_roots:
            pj = read_json(pr / ".claude-plugin" / "plugin.json")
            name = str(pj.get("name") or pr.name)
            uid = "plugin:" + name
            files = {}
            for f, digest in iter_files(pr):
                files[rel_key(f, pr)] = digest
                claimed.add(f)
            sidecar = read_json(pr.parent / (pr.name + ".meta.json"))
            store(uid, label, {
                "kind": "plugin", "name": name, "path": str(pr),
                "version": pj.get("version") or meta.get(uid, {}).get("version"),
                "source": sidecar.get("marketplace_name") or meta.get(uid, {}).get("source"),
                "updatedAt": meta.get(uid, {}).get("updatedAt"),
                "files": files,
            })

        # 2) Stand-alone skills
        for sk in sorted(root.rglob("SKILL.md")):
            sd = sk.parent
            if not inside(sk) or not sk.is_file() or sk in claimed or any(sd == pr or pr in sd.parents for pr in plugin_roots):
                continue
            if any(part in IGNORE_NAMES or part == "node_modules" for part in sk.relative_to(root).parts):
                continue
            uid = "skill:" + sd.name
            files = {}
            for f, digest in iter_files(sd):
                files[rel_key(f, sd)] = digest
                claimed.add(f)
            m = meta.get(uid, {})
            store(uid, label, {
                "kind": "skill", "name": sd.name, "path": str(sd),
                "version": None, "source": m.get("source"), "updatedAt": m.get("updatedAt"),
                "files": files,
            })

        # 3) Loose files (archives, manifests, foreign objects). manifest.json
        #    and the .meta.json sidecars carry timestamps that change on
        #    every sync.
        loose = {}
        for f, digest in iter_files(root, exclude):
            if f in claimed or any(c in f.parents for c in claimed) or f.name == "manifest.json" or f.name.endswith(".meta.json"):
                continue
            loose[rel_key(f, root)] = digest
        if loose:
            store("loose:" + label, label, {"kind": "loose", "name": label, "path": str(root),
                                             "version": None, "source": None, "updatedAt": None, "files": loose})

    version = tool_version()
    for u in units.values():
        # Hash over all entries: lets a unit that moved but is identical in
        # content be recognised as unchanged.
        u["unit_hash"] = hashlib.sha256(json.dumps(u["files"], sort_keys=True).encode()).hexdigest()
        u["file_count"] = len(u["files"])
        u["doc_id"] = doc_id_for(u["id"])
        u["tool_version"] = version
    return {"created": datetime.now(timezone.utc).isoformat(timespec="seconds"), "tool_version": version, "units": units}


def load_snapshot(path):
    snap = read_json(path)
    if not isinstance(snap.get("units"), dict) or not snap["units"]:
        fail("%s is not a snapshot or contains no units" % path)
    return snap


def load_baseline_dir(d):
    """Reads baseline documents from a folder, subfolders included. Stores
    that wrap the document ({"data": {...}}) are unwrapped. Documents
    without 'files' (e.g. configuration) are ignored."""
    base = {}
    for p in sorted(Path(d).rglob("*.json")):
        doc = read_json(p)
        if isinstance(doc.get("data"), dict):
            doc = doc["data"]
        if isinstance(doc.get("files"), dict) and "id" in doc:
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
                # Same content under another name/path: no new review.
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

    current_hashes = {u["unit_hash"] for u in cur.values()}
    for uid in sorted(set(baseline) - set(cur)):
        if baseline[uid].get("unit_hash") not in current_hashes:
            result["removed"].append(uid)

    # Units cleared under older rules were never looked at with the new
    # ones; their hashes will not change on their own. A baseline document
    # without tool_version predates 1.2.0 and counts as older.
    now = snap.get("tool_version")
    old = sorted({str(b.get("tool_version") or "unknown") for b in baseline.values()} - {now})
    result["tool_version"] = now
    result["baseline_tool_versions"] = old
    result["rescan_all"] = bool(old)
    result["rescan_units"] = sorted(u["path"] for u in cur.values()) if old else []
    return result


def skill_names(snap):
    """Names of all installed skills: stand-alone ones and those inside
    plugins (the folder that holds a SKILL.md)."""
    names = set()
    for u in snap["units"].values():
        if u.get("kind") == "skill":
            names.add(u["name"].lower())
        for f in u.get("files", {}):
            parts = Path(f).parts
            if parts and parts[-1] == "SKILL.md" and len(parts) >= 2:
                names.add(parts[-2].lower())
    return sorted(names)


def parse_expectations(text):
    """Accepts "HASH:PATH" (comma or newline separated) and the output of
    sha256sum ("HASH  PATH"). Returns {file name: hash}; paths are matched
    by file name because the three checked names are distinct and the
    install folder differs between sessions."""
    want = {}
    for item in re.split(r"[,\n]", text):
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        m = re.match(r"^(?:sha256:)?([0-9a-fA-F]{64})(?::|\s+\*?)(.+)$", item)
        if not m:
            fail("cannot parse expected hash entry: %r" % item[:80])
        want[Path(m.group(2).strip()).name] = m.group(1).lower()
    return want


def selfcheck(want):
    skill_dir = Path(__file__).resolve().parent.parent
    ok = True
    for rel in SELF_FILES:
        p = skill_dir / rel
        try:
            have = sha256_file(p)
        except OSError as e:
            print("MISSING   %s (%s)" % (rel, e))
            ok = False
            continue
        exp = want.get(p.name)
        if exp is None:
            # No expectation is not a pass: the caller believes all three
            # files were verified.
            print("NO HASH   %s  (current %s)" % (rel, have))
            ok = False
        elif exp != have:
            print("MISMATCH  %s  expected %s, found %s" % (rel, exp, have))
            ok = False
        else:
            print("ok        %s" % rel)
    return ok


def main():
    ap = argparse.ArgumentParser(description="Record and compare the reviewed state of installed skills and plugins")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="record the current state")
    s.add_argument("roots", nargs="*", help="folders to record (alternative to --auto)")
    s.add_argument("--auto", action="store_true", help="discover the install locations of this session")
    s.add_argument("--root", action="append", default=[], help="additional folder for --auto (repeatable)")
    s.add_argument("--out", required=True)
    e = sub.add_parser("export", help="write one baseline document per unit")
    e.add_argument("--snapshot", required=True)
    e.add_argument("--out-dir", required=True)
    e.add_argument("--reviewed-by", default="skillbouncer")
    e.add_argument("--verdict", default="CLEAN")
    e.add_argument("--only", nargs="*", help="export only these unit IDs")
    d = sub.add_parser("diff", help="compare a snapshot with the baseline")
    d.add_argument("--baseline-dir", required=True)
    d.add_argument("--snapshot", required=True)
    d.add_argument("--out", required=True)
    n = sub.add_parser("names", help="list installed skill names for the scanner's --known-names")
    n.add_argument("--snapshot", required=True)
    n.add_argument("--out", required=True)
    c = sub.add_parser("selfcheck", help="verify this tool against hashes kept elsewhere")
    c.add_argument("--expect", help="HASH:PATH[,HASH:PATH ...]")
    c.add_argument("--expect-file", help="file with HASH:PATH lines or sha256sum output")
    c.add_argument("--print", action="store_true", dest="show", help="print the current hashes and exit")
    a = ap.parse_args()

    if a.cmd == "snapshot":
        if a.auto and a.roots:
            fail("give either --auto (with optional --root) or explicit roots, not both")
        if a.auto:
            roots, missing = discover_roots(a.root)
            for path, label, _ in roots:
                print("root      %s  (%s)" % (path, label))
            for path in missing:
                print("not here  %s" % path)
            for path in AUTO_SKIPPED:
                print("skipped   %s  (not installed)" % path)
        else:
            if a.root:
                fail("--root only works together with --auto")
            if not a.roots:
                fail("no roots given; use --auto or list the folders")
            roots = []
            for r in a.roots:
                if not Path(r).is_dir():
                    fail("root does not exist: %s" % r)
                # Label from the path as given, not from its resolved
                # target: that can be a sync folder with a changing name.
                roots.append((r, Path(r).name, ()))
        snap = snapshot(roots)
        if not snap["units"]:
            fail("no skills or plugins found under %d root(s); refusing to write an empty snapshot" % len(roots))
        Path(a.out).write_text(json.dumps(snap, indent=1), "utf-8")
        print("snapshot: %d units, %d entries, scanner %s -> %s" % (
            len(snap["units"]), sum(u["file_count"] for u in snap["units"].values()), snap["tool_version"], a.out))

    elif a.cmd == "export":
        snap = load_snapshot(a.snapshot)
        unknown = sorted(set(a.only or []) - set(snap["units"]))
        if unknown:
            fail("--only names units that are not in the snapshot: %s" % ", ".join(unknown))
        out = Path(a.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        count = 0
        for uid, u in snap["units"].items():
            if a.only and uid not in a.only:
                continue
            doc = dict(u)
            doc.pop("path", None)  # paths depend on the session and are not part of the baseline
            doc.update({"reviewed_at": now, "reviewed_by": a.reviewed_by, "verdict": a.verdict,
                        "tool_version": snap.get("tool_version") or tool_version()})
            (out / (u["doc_id"] + ".json")).write_text(json.dumps(doc, indent=1), "utf-8")
            count += 1
        print("%d baseline documents written to %s" % (count, out))

    elif a.cmd == "diff":
        if not Path(a.baseline_dir).is_dir():
            fail("baseline folder does not exist: %s" % a.baseline_dir)
        base = load_baseline_dir(a.baseline_dir)
        snap = load_snapshot(a.snapshot)
        r = diff(base, snap)
        Path(a.out).write_text(json.dumps(r, indent=1), "utf-8")
        print("baseline: %d units | current: %d" % (len(base), len(snap["units"])))
        if not base:
            print("warning: the baseline folder holds no baseline documents; every unit counts as new")
        print("unchanged: %d | new: %d | changed: %d | removed: %d | entries to review: %d" % (
            len(r["unchanged"]), len(r["new"]), len(r["changed"]), len(r["removed"]), len(r["to_review"])))
        for item in r["new"]:
            print("  NEW      %s (version %s, source %s, %d entries)" % (item["id"], item["version"], item["source"], item["files"]))
        for item in r["changed"]:
            print("  CHANGED  %s (%s -> %s): +%d ~%d -%d" % (item["id"], item["old_version"], item["new_version"], len(item["added"]), len(item["modified"]), len(item["removed"])))
        for uid in r["removed"]:
            print("  REMOVED  %s" % uid)
        if r["rescan_all"]:
            print("scanner rules changed since baseline: full rescan recommended (baseline %s, now %s)" % (
                ", ".join(r["baseline_tool_versions"]), r["tool_version"]))
        # Exit code 1 signals "there is something to review".
        sys.exit(1 if (r["new"] or r["changed"] or r["rescan_all"]) else 0)

    elif a.cmd == "names":
        names = skill_names(load_snapshot(a.snapshot))
        Path(a.out).write_text("\n".join(names) + "\n", "utf-8")
        print("%d skill names -> %s" % (len(names), a.out))

    elif a.cmd == "selfcheck":
        if a.show:
            skill_dir = Path(__file__).resolve().parent.parent
            for rel in SELF_FILES:
                print("%s  %s" % (sha256_file(skill_dir / rel), rel))
            return
        text = a.expect or ""
        if a.expect_file:
            try:
                text += "\n" + Path(a.expect_file).read_text("utf-8")
            except OSError as err:
                fail("cannot read --expect-file: %s" % err)
        if not text.strip():
            fail("selfcheck needs --expect, --expect-file or --print")
        if not selfcheck(parse_expectations(text)):
            fail("selfcheck failed: this copy of skillbouncer is not the reviewed one; do not trust its results")
        print("selfcheck passed")


if __name__ == "__main__":
    main()
