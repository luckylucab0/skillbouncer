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
Units that would get an ID already taken by a differing unit are tracked
as <id>@<root>, <id>@<root>-2 and so on; none replaces another.

Subcommands
-----------
  snapshot (--auto [--root DIR ...] | ROOT [ROOT ...]) --out snap.json
      Records the current state. --auto discovers the install locations
      at runtime; they differ between Claude products and sessions. Exits
      2 when a root given explicitly does not exist, when no skill or
      plugin at all is found or when something cannot be read: an empty or
      partial snapshot would read as "nothing changed" forever.
  export --snapshot snap.json --out-dir DIR [--only ID ...] [--verdict V]
      Writes one JSON document per unit into DIR. How those documents get
      into the user's baseline store (a database, a private repository) is
      not this script's business; it only ever sees JSON directories.
      --only without an ID is an error, not "all units".
  diff --baseline-dir DIR --snapshot snap.json --out diff.json
      Compares. DIR holds the baseline documents as JSON, directly or in
      subfolders (DIR/baseline/<id>.json works too). Prints a readable
      summary and writes the absolute paths of everything to review into
      diff.json. Exit 1 = something to review: new or changed units, units
      of the baseline that are gone ("removed"), symlinks whose target the
      snapshot does not cover ("uncovered_links"), or "the scanner rules
      changed since the baseline was written". 0 = nothing. 2 = error,
      there is no result.
  names --snapshot snap.json --out names.txt
      Writes the names of all installed skills, one per line, for the
      scanner's --known-names option: folder names and the names the
      SKILL.md files declare.
  selfcheck (--expect HASH:PATH[,HASH:PATH ...] | --expect-file FILE | --print)
      Hashes this script, the scanner and SKILL.md and compares them with
      hashes kept outside the sandbox. Exit 2 on any mismatch, on a missing
      expectation and on an expectation it cannot check (another file, two
      hashes for one file).

What is hashed
--------------
Every file below a root, hidden files and folders such as .git and
__pycache__ included. Left out are only files Claude's own bookkeeping
rewrites at runtime, each in the one place where it belongs and only while
its content has the expected harmless shape (see runtime_marker and
sync_sidecar). Anything else of that name is hashed like every other file.

Symlinks are never followed: a link is an entry of its own (a hash of its
target text), so a new or retargeted link is a change. Two additions keep a
link from hiding content. A symlink to a skill or plugin folder outside the
recorded folders is recorded as a unit, read at its target. Every other
link whose target is not part of the snapshot is listed under
"uncovered_links", and diff reports it on every run, because nothing
compares what it points to. Add that folder as a root to cover it.

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
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

# Characters allowed in document IDs of common document stores.
DOC_ID_SAFE = re.compile(r"[^A-Za-z0-9_\-.~:@+]")

try:
    HOME = Path.home()
except (RuntimeError, KeyError):
    # No home folder (bare container user). Importing must still work:
    # diff and selfcheck do not need it, and a traceback would exit with 1.
    HOME = None
# Where Claude products keep installed skills and plugins. Checked at
# runtime because no single session has all of them. Folders with a
# "synced" child are expanded: each sync folder becomes its own root.
AUTO_CANDIDATES = ([HOME / ".claude" / "plugins" / "synced",
                    HOME / ".claude" / "plugins" / "cache",
                    HOME / ".claude" / "skills"] if HOME else []) + [
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

# plugin.json, manifest.json and the sidecars are a few KB. A scanned
# package controls them, so reading stops well before memory matters.
META_LIMIT = 4 * 1024 * 1024

# Same frontmatter shape the scanner accepts, so both tools agree on the
# name a skill declares.
FRONTMATTER = re.compile(r"\A\ufeff?---\r?\n(.*?)\r?\n---\s*(\r?\n|$)", re.S)

# A number or a timestamp and nothing else.
MARKER_TEXT = re.compile(r"[0-9T:.Z+\-\s]*\Z")

SPECIAL_KINDS = {stat.S_IFIFO: "fifo", stat.S_IFSOCK: "socket", stat.S_IFCHR: "chardev", stat.S_IFBLK: "blockdev"}


def fail(msg):
    """Exit 2 with a message. Used wherever silence would look like a pass."""
    print("error: " + shown(msg, 2000), file=sys.stderr)
    sys.exit(2)


def shown(value, limit=200):
    """Text for one output line. Names, versions and paths come from the
    packages under review; a line break in a plugin name would otherwise
    let that plugin write its own lines into the summary the reviewer
    reads."""
    text = str(value)
    if len(text) > limit:
        text = text[:limit] + "..."
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)


def to_bytes(text):
    """File names and link targets are bytes that need not be UTF-8.
    Python hands them over with surrogate escapes; this restores the
    original bytes for hashing where a plain encode would raise."""
    return text.encode("utf-8", "surrogateescape")


def scalar(value):
    """Metadata from foreign JSON is kept only as plain text or number. A
    nested structure in a version field has no use and could be made deep
    enough to break writing the snapshot."""
    return value if isinstance(value, (str, int, float)) and not isinstance(value, bool) else None


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


def files_hash(files):
    """One hash over all entries of a unit: lets a unit that moved or was
    relabelled but is identical in content be recognised as unchanged."""
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def doc_id_for(unit_id):
    """Unit -> valid document ID (max. 200 characters, allowed characters)."""
    return DOC_ID_SAFE.sub("_", unit_id)[:200]


def entry_digest(path, kind):
    """Hash of one directory entry. A symlink is hashed as an entry of its
    own (the target as text) and never followed. Pipes, sockets and device
    nodes cannot be hashed, but one that appears is a change, so its kind
    stands in for the hash."""
    try:
        if kind == "link":
            # Path() normalises the target ("./a" equals "a"), as earlier
            # versions did; existing baselines stay comparable.
            return "symlink:" + hashlib.sha256(to_bytes(str(Path(os.readlink(path))))).hexdigest()
        if kind == "file":
            return sha256_file(path)
    except OSError as err:
        fail("cannot read %s: %s; without it the snapshot would be incomplete" % (path, err))
    return kind


def walk(top, skip=frozenset()):
    """Everything below top: (set of directories, list of (parts, kind))
    with parts relative to top and kind "file", "link" or "special:<type>".
    Symlinks are not followed. One pass per root, so that every later
    step works on this list instead of searching the tree again per file
    (that was quadratic). A stack instead of recursion, because a hostile
    tree can be deeper than the recursion limit."""
    dirs, entries = {top}, []
    stack = [(top, ())]
    while stack:
        cur, parts = stack.pop()
        try:
            with os.scandir(cur) as it:
                listing = list(it)
            for e in listing:
                here = parts + (e.name,)
                if e.is_symlink():
                    entries.append((here, "link"))
                elif e.is_dir(follow_symlinks=False):
                    if e.path not in skip:
                        dirs.add(e.path)
                        stack.append((e.path, here))
                elif e.is_file(follow_symlinks=False):
                    entries.append((here, "file"))
                else:
                    mode = stat.S_IFMT(e.stat(follow_symlinks=False).st_mode)
                    entries.append((here, "special:" + SPECIAL_KINDS.get(mode, "other")))
        except OSError as err:
            fail("cannot list %s: %s; without it the snapshot would be incomplete" % (cur, err))
    return dirs, entries


def file_map(items):
    """items: (parts relative to the unit, digest). Returns the unit's
    file map. Each node_modules/<package>/ directory becomes a single
    "dir:..." entry instead of one entry per file; its key gets a trailing
    slash so it cannot be mistaken for a file of that name."""
    files, packages = {}, {}
    for parts, digest in items:
        if "node_modules" in parts[:-1]:
            i = parts.index("node_modules")
            # @scope/name packages sit one level deeper.
            depth = i + 3 if parts[i + 1].startswith("@") else i + 2
            if len(parts) > depth:
                packages.setdefault(parts[:depth], []).append("%s\0%s\n" % ("/".join(parts[depth:]), digest))
                continue
        files[os.sep.join(parts)] = digest
    for pkg, lines in packages.items():
        files[os.sep.join(pkg) + "/"] = "dir:" + hashlib.sha256(to_bytes("".join(sorted(lines)))).hexdigest()
    return files


def read_json(path, limit=None):
    """A JSON object from path, or {} for anything else. RecursionError is
    caught because a file of nothing but "[" is enough to raise it."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read() if limit is None else fh.read(limit + 1)
        if limit is not None and len(raw) > limit:
            return {}
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


def read_meta(path):
    """read_json for the small metadata files inside a scanned tree. Only
    regular files: a link would be followed out of the tree and opening a
    pipe would block for good."""
    if os.path.islink(path) or not os.path.isfile(path):
        return {}
    return read_json(path, META_LIMIT)


def runtime_marker(path):
    """True if the file holds what Claude's lock and round markers hold: at
    most a few numbers or timestamps, bare or as a flat JSON object like
    {"pid":105,"procStart":"145"}. These files change in every session, so
    hashing them would raise a false alarm on every run. Checking the
    content keeps the exception from becoming a hiding place: what passes
    is too small and too plain to be code."""
    try:
        if os.path.getsize(path) > 256:
            return False
        with open(path, "rb") as fh:
            text = fh.read(257).decode("ascii")
    except (OSError, ValueError):
        return False
    if MARKER_TEXT.match(text):
        return True
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return False
    return isinstance(data, dict) and all(
        re.match(r"[A-Za-z_]{1,32}\Z", k) and (type(v) in (int, float) or (isinstance(v, str) and MARKER_TEXT.match(v)))
        for k, v in data.items())


def sync_sidecar(root, name):
    """True for manifest.json and <plugin folder>.meta.json directly in a
    root: the sync writes them there and puts a new timestamp into them on
    every round. Deeper down, or without the folder a sidecar belongs to,
    a file of that name is not the sync's and gets hashed."""
    folder = name[:-len(".meta.json")] if name.endswith(".meta.json") else ""
    if name != "manifest.json" and not (folder and os.path.isdir(os.path.join(root, folder))):
        return False
    # Both are JSON objects; anything else under that name is not a sidecar.
    return bool(read_meta(os.path.join(root, name)))


def declared_names(path):
    """The names a SKILL.md declares in its frontmatter. Claude registers a
    skill under that name, which can differ from the folder name."""
    try:
        with open(path, "rb") as fh:
            m = FRONTMATTER.match(fh.read(1024 * 1024).decode("utf-8", "replace"))
    except OSError:
        return []
    found = []
    for line in m.group(1).splitlines() if m else []:
        km = re.match(r"^name\s*:\s*(.*)$", line)
        if km and km.group(1).strip().strip("\"'"):
            found.append(km.group(1).strip().strip("\"'"))
    return found


def load_manifest_info(root):
    """Reads version and origin from the manifest.json files that Claude
    places next to installed skills and plugins. That helps later to judge
    a change ("vendor update on 2026-11-03" versus "unexpected")."""
    info = {}
    m = read_meta(os.path.join(root, "manifest.json"))

    def rows(key):
        value = m.get(key)
        return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []

    for s in rows("skills"):
        info["skill:" + str(s.get("name", ""))] = {"source": scalar(s.get("source")), "updatedAt": scalar(s.get("updatedAt"))}
    for p in rows("plugins"):
        info["plugin:" + str(p.get("name", ""))] = {"source": scalar(p.get("marketplaceName")), "version": scalar(p.get("version")),
                                                    "updatedAt": scalar(p.get("updatedAt"))}
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
        # A sync folder that is a symlink is a root like any other. Left
        # out, its plugins would be neither recorded nor missed.
        sync_dirs = sorted(d for d in sync_parent.iterdir() if d.is_dir()) if sync_parent.is_dir() else []
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
    seen_dirs, seen_files = set(), set()  # everything recorded, to judge where a symlink leads
    links = []  # (link path, units holding it, label of its root, may be a unit folder)

    def store(uid, label, unit):
        # The same unit can be installed in several roots. Identical copies
        # count once; a differing copy gets the root label appended and is
        # tracked separately, because exactly that difference is suspicious.
        # Every further differing copy gets a number, so that none silently
        # takes the place of another. Returns the unit that is kept.
        taken, n = uid, 0
        while taken in units:
            if units[taken]["files"] == unit["files"]:
                return units[taken]
            n += 1
            taken = "%s@%s" % (uid, label) if n == 1 else "%s@%s-%d" % (uid, label, n)
        unit["id"] = taken
        units[taken] = unit
        return unit

    def record(root, label, skip, link_name=None):
        """Records one root. link_name is set when root is the target of a
        symlinked unit folder: the unit is then named after the link, the
        name under which it is installed."""
        dirs, entries = walk(root, skip)
        seen_dirs.update(dirs)
        kinds = dict(entries)
        meta = load_manifest_info(root)

        def full(parts):
            return os.path.join(root, *parts)

        def folder_name(d):
            return link_name if link_name and not d else os.path.basename(full(d))

        # Plugins first, so that skills inside a plugin are not counted
        # again as units of their own. Nothing inside node_modules is a
        # unit; those folders are covered as packages.
        plugin_dirs = sorted({p[:-2] for p in kinds if p[-2:] == (".claude-plugin", "plugin.json") and "node_modules" not in p})
        unit_dirs = set(plugin_dirs)
        skill_dirs = []
        for p in sorted(p for p in kinds if p[-1] == "SKILL.md" and "node_modules" not in p):
            d = p[:-1]
            if kinds[p] != "file" and not (kinds[p] == "link" and os.path.isfile(full(p))):
                continue
            if any(d[:k] in unit_dirs for k in range(len(d) + 1)):
                continue
            unit_dirs.add(d)
            skill_dirs.append(d)

        held = {d: [] for d in unit_dirs}
        loose, links_here, names = [], [], {}
        for p, kind in entries:
            path = full(p)
            owners = [p[:k] for k in range(len(p)) if p[:k] in unit_dirs]
            if kind == "file":
                # Runtime markers only where Claude writes them: the lock
                # files in <unit>/.in_use/ and a .last-complete-round at
                # the top of a unit or root. Elsewhere the name means
                # nothing and the file is hashed.
                in_use = len(p) >= 2 and p[-2] == ".in_use" and p[:-2] in unit_dirs
                round_marker = p[-1] == ".last-complete-round" and (len(p) == 1 or p[:-1] in unit_dirs)
                if (in_use or round_marker) and runtime_marker(path):
                    continue
                if not owners and len(p) == 1 and sync_sidecar(root, p[0]):
                    continue
                # The empty marker next to a sync folder is named after
                # it. Hashed under that name, a changed account ID would
                # look like a changed unit.
                if (not owners and p[-1].startswith(".bucket-") and os.path.join(os.path.dirname(path), p[-1][len(".bucket-"):]) in skip
                        and os.path.getsize(path) == 0):
                    continue
                if p[-1] == "SKILL.md":
                    names[p] = declared_names(path)
            digest = entry_digest(path, kind)
            seen_files.add(path)
            if kind == "link":
                links_here.append((path, p, owners))
            for d in owners:
                held[d].append((p[len(d):], digest))
            if not owners:
                loose.append((p, digest))

        def names_below(d):
            return sorted({n for p, found in names.items() if p[:len(d)] == d for n in found})

        stored = {}
        for d in plugin_dirs:
            manifest = d + (".claude-plugin", "plugin.json")
            pj = read_json(full(manifest), META_LIMIT) if kinds[manifest] == "file" else {}
            name = str(pj.get("name") or folder_name(d))
            uid = "plugin:" + name
            sidecar = read_meta(os.path.join(os.path.dirname(full(d)), os.path.basename(full(d)) + ".meta.json"))
            stored[d] = store(uid, label, {
                "kind": "plugin", "name": name, "path": full(d),
                "version": scalar(pj.get("version")) or meta.get(uid, {}).get("version"),
                "source": scalar(sidecar.get("marketplace_name")) or meta.get(uid, {}).get("source"),
                "updatedAt": meta.get(uid, {}).get("updatedAt"),
                "files": file_map(held[d]), "skill_names": names_below(d), "uncovered_links": {},
            })
        for d in skill_dirs:
            name = folder_name(d)
            m = meta.get("skill:" + name, {})
            stored[d] = store("skill:" + name, label, {
                "kind": "skill", "name": name, "path": full(d),
                "version": None, "source": m.get("source"), "updatedAt": m.get("updatedAt"),
                "files": file_map(held[d]), "skill_names": names_below(d), "uncovered_links": {},
            })
        # Loose files (archives, foreign objects): whatever no unit holds.
        if loose:
            stored[None] = store("loose:" + label, label, {
                "kind": "loose", "name": label, "path": root, "version": None, "source": None, "updatedAt": None,
                "files": file_map(loose), "skill_names": [], "uncovered_links": {}})
        for path, p, owners in links_here:
            links.append((path, [stored[d] for d in owners or [None]], label,
                          link_name is None and not owners and "node_modules" not in p))

    def covered(real):
        if real in seen_dirs or real in seen_files:
            return True
        # A link to nothing is no gap while the place it names lies in a
        # recorded folder: whatever appears there later is hashed as a new
        # file. Names the walk may skip are the exception.
        parent, name = os.path.split(real)
        skippable = (name in ("manifest.json", ".last-complete-round") or name.endswith(".meta.json")
                     or name.startswith(".bucket-") or os.path.basename(parent) == ".in_use")
        return not os.path.lexists(real) and parent in seen_dirs and not skippable

    for root_arg, label, exclude in roots:
        record(str(Path(root_arg).resolve()), label, frozenset(str(e) for e in exclude))

    # A skill or plugin installed as a symlink to a folder elsewhere would
    # otherwise be one link entry and nothing behind it ever compared. The
    # target is read as a unit; links inside it are not followed further.
    for path, _, label, unit_folder in sorted(links, key=lambda item: item[0]):
        real = os.path.realpath(path)
        if unit_folder and not covered(real) and os.path.isdir(real) and (
                os.path.isfile(os.path.join(real, "SKILL.md")) or os.path.lexists(os.path.join(real, ".claude-plugin", "plugin.json"))):
            record(real, label, frozenset(), os.path.basename(path))
    for path, holders, _, _ in links:
        if not covered(os.path.realpath(path)):
            for unit in holders:
                unit["uncovered_links"][path] = os.readlink(path)

    version = tool_version()
    doc_ids = set()
    # Two IDs can map to one document ID ("a b" and "a_b", or long names
    # with a common start). IDs that need no replacement go first and keep
    # the plain form; a later one gets a piece of its own hash appended.
    for uid in sorted(units, key=lambda i: (doc_id_for(i) != i, i)):
        u = units[uid]
        u["unit_hash"] = files_hash(u["files"])
        u["file_count"] = len(u["files"])
        doc_id = doc_id_for(uid)
        if doc_id in doc_ids:
            doc_id = "%s~%s" % (doc_id[:187], hashlib.sha256(to_bytes(uid)).hexdigest()[:12])
        if doc_id in doc_ids:
            fail("no free document ID for unit %s" % uid)
        doc_ids.add(doc_id)
        u["doc_id"] = doc_id
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
    without 'files' (e.g. configuration) are ignored. If two documents
    carry the same unit ID (the document ID of a unit can change when a
    unit with a similar name comes or goes), the later review counts."""
    base = {}
    for p in sorted(Path(d).rglob("*.json")):
        doc = read_json(p)
        if isinstance(doc.get("data"), dict):
            doc = doc["data"]
        if not isinstance(doc.get("files"), dict) or not isinstance(doc.get("id"), str):
            continue
        other = base.get(doc["id"])
        if other is None or str(doc.get("reviewed_at") or "") >= str(other.get("reviewed_at") or ""):
            base[doc["id"]] = doc
    return base


def diff(baseline, snap):
    cur = snap["units"]
    # Hashes are computed here, not taken from the documents: the files
    # map is what was reviewed.
    base_hash = {uid: files_hash(b["files"]) for uid, b in baseline.items()}
    cur_hash = {uid: files_hash(u["files"]) for uid, u in cur.items()}
    known, present = set(base_hash.values()), set(cur_hash.values())
    result = {"new": [], "removed": [], "changed": [], "unchanged": [], "to_review": [], "uncovered_links": []}

    for uid, u in sorted(cur.items()):
        b = baseline.get(uid)
        if b is None:
            if cur_hash[uid] in known:
                # Same content under another name/path: no new review.
                result["unchanged"].append(uid)
                continue
            result["new"].append({"id": uid, "version": u.get("version"), "source": u.get("source"), "files": len(u["files"])})
            result["to_review"] += [str(Path(u["path"]) / f) for f in u["files"]]
            continue
        bf, cf = b["files"], u["files"]
        added = sorted(set(cf) - set(bf))
        removed = sorted(set(bf) - set(cf))
        modified = sorted(f for f in set(cf) & set(bf) if cf[f] != bf[f])
        # Two units that only traded IDs (root labels are positions in a
        # sorted list of sync folders) are unchanged: each content is known
        # and the content this ID had before is still installed.
        swapped = cur_hash[uid] in known and base_hash[uid] in present
        if (added or removed or modified) and not swapped:
            result["changed"].append({
                "id": uid, "old_version": b.get("version"), "new_version": u.get("version"),
                "source": u.get("source"), "added": added, "modified": modified, "removed": removed,
            })
            result["to_review"] += [str(Path(u["path"]) / f) for f in added + modified]
        else:
            result["unchanged"].append(uid)

    for uid in sorted(set(baseline) - set(cur)):
        if base_hash[uid] not in present:
            result["removed"].append(uid)

    # Nothing compares what such a link points to, so it is reported on
    # every run, whether the link itself changed or not.
    listed = set(result["to_review"])
    for uid, u in sorted(cur.items()):
        for link, target in sorted((u.get("uncovered_links") or {}).items()):
            result["uncovered_links"].append({"id": uid, "link": link, "target": target})
            if link not in listed:
                listed.add(link)
                result["to_review"].append(link)

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
    plugins, by folder (the one that holds a SKILL.md) and by the name the
    SKILL.md declares. A new skill collides with an installed one if it
    reuses either."""
    names = set()
    for u in snap["units"].values():
        if u.get("kind") == "skill":
            names.add(str(u.get("name", "")))
        names.update(str(n) for n in u.get("skill_names") or [])
        for f in u.get("files", {}):
            parts = Path(f).parts
            if parts and parts[-1] == "SKILL.md" and len(parts) >= 2:
                names.add(parts[-2])
    # One name per line: a line break inside a folder name must not turn
    # into a second name.
    return sorted({shown(n.strip().lower(), 1000) for n in names} - {""})


def parse_expectations(text):
    """Accepts "HASH:PATH" (comma or newline separated) and the output of
    sha256sum ("HASH  PATH"). Returns {file name: hash}; paths are matched
    by file name because the three checked names are distinct and the
    install folder differs between sessions."""
    want = {}
    checked = {Path(rel).name for rel in SELF_FILES}
    for item in re.split(r"[,\n]", text):
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        m = re.match(r"^(?:sha256:)?([0-9a-fA-F]{64})(?::|\s+\*?)(.+)$", item)
        if not m:
            fail("cannot parse expected hash entry: %r" % item[:80])
        name, digest = Path(m.group(2).strip()).name, m.group(1).lower()
        # An entry that is never compared would still end in "passed", and
        # the caller would take that file for verified.
        if name not in checked:
            fail("selfcheck cannot verify %s; it covers only %s" % (m.group(2).strip(), ", ".join(SELF_FILES)))
        if want.get(name, digest) != digest:
            fail("two different hashes given for %s" % name)
        want[name] = digest
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
    for stream in (sys.stdout, sys.stderr):
        # Paths with bytes that are not UTF-8 must not turn a message into
        # a traceback.
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")

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
                print("root      %s  (%s)" % (shown(path, 2000), shown(label)))
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
        # Stray files alone are a "loose:" unit, but a snapshot without a
        # single skill or plugin means the install locations were missed.
        if not any(u["kind"] in ("plugin", "skill") for u in snap["units"].values()):
            fail("no skills or plugins found under %d root(s); refusing to write an empty snapshot" % len(roots))
        Path(a.out).write_text(json.dumps(snap, indent=1), "utf-8")
        for uid, u in sorted(snap["units"].items()):
            for link, target in sorted(u["uncovered_links"].items()):
                print("uncovered %s -> %s  (%s; the target is not part of the snapshot)" % (
                    shown(link, 2000), shown(target), shown(uid)))
        print("snapshot: %d units, %d entries, scanner %s -> %s" % (
            len(snap["units"]), sum(u["file_count"] for u in snap["units"].values()), snap["tool_version"], shown(a.out, 2000)))

    elif a.cmd == "export":
        snap = load_snapshot(a.snapshot)
        # nargs="*" accepts "--only" with nothing after it. Read as "no
        # filter" that would write a clean verdict for every unit.
        if a.only is not None and not a.only:
            fail("--only was given without a unit ID; nothing exported")
        unknown = sorted(set(a.only or []) - set(snap["units"]))
        if unknown:
            fail("--only names units that are not in the snapshot: %s" % ", ".join(unknown))
        chosen = [(uid, u) for uid, u in snap["units"].items() if a.only is None or uid in a.only]
        doc_ids = [str(u.get("doc_id", "")) for _, u in chosen]
        # The document ID becomes a file name. Two units with one ID would
        # overwrite each other while the count below still looked right.
        if len(set(doc_ids)) != len(doc_ids) or any(not i or DOC_ID_SAFE.search(i) for i in doc_ids):
            fail("snapshot holds missing, unsafe or duplicate document IDs; take a new snapshot")
        out = Path(a.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for uid, u in chosen:
            doc = dict(u)
            # Paths depend on the session and are not part of the baseline;
            # the other two are only needed for the snapshot at hand.
            for key in ("path", "skill_names", "uncovered_links"):
                doc.pop(key, None)
            doc.update({"reviewed_at": now, "reviewed_by": a.reviewed_by, "verdict": a.verdict,
                        "tool_version": snap.get("tool_version") or tool_version()})
            (out / (u["doc_id"] + ".json")).write_text(json.dumps(doc, indent=1), "utf-8")
        print("%d baseline documents written to %s" % (len(chosen), shown(out, 2000)))

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
            print("  NEW      %s (version %s, source %s, %d entries)" % (
                shown(item["id"]), shown(item["version"]), shown(item["source"]), item["files"]))
        for item in r["changed"]:
            print("  CHANGED  %s (%s -> %s): +%d ~%d -%d" % (
                shown(item["id"]), shown(item["old_version"]), shown(item["new_version"]),
                len(item["added"]), len(item["modified"]), len(item["removed"])))
        for uid in r["removed"]:
            print("  REMOVED  %s" % shown(uid))
        for item in r["uncovered_links"]:
            print("  LINK     %s: %s -> %s" % (shown(item["id"]), shown(item["link"], 2000), shown(item["target"])))
        if r["removed"]:
            print("removed: %d unit(s) of the baseline are missing; confirm each was uninstalled and that no install location "
                  "is missing from the snapshot" % len(r["removed"]))
        if r["uncovered_links"]:
            print("links: %d symlink(s) lead to content the snapshot does not hold; review the targets or add their folder "
                  "as a root" % len(r["uncovered_links"]))
        if r["rescan_all"]:
            print("scanner rules changed since baseline: full rescan recommended (baseline %s, now %s)" % (
                shown(", ".join(r["baseline_tool_versions"])), shown(r["tool_version"])))
        # Exit code 1 signals "there is something to review". Removed units
        # count: a location the snapshot no longer covers looks the same as
        # an uninstall, and only a person can tell which it is.
        sys.exit(1 if (r["new"] or r["changed"] or r["removed"] or r["uncovered_links"] or r["rescan_all"]) else 0)

    elif a.cmd == "names":
        names = skill_names(load_snapshot(a.snapshot))
        Path(a.out).write_text("\n".join(names) + "\n", "utf-8")
        print("%d skill names -> %s" % (len(names), shown(a.out, 2000)))

    elif a.cmd == "selfcheck":
        if a.show:
            # Printing compares nothing. Together with expectations it
            # would end in exit 0 without having checked them.
            if a.expect or a.expect_file:
                fail("--print compares nothing; use it without --expect and --expect-file")
            skill_dir = Path(__file__).resolve().parent.parent
            for rel in SELF_FILES:
                print("%s  %s" % (sha256_file(skill_dir / rel), rel))
            return
        text = a.expect or ""
        if a.expect_file:
            try:
                text += "\n" + Path(a.expect_file).read_text("utf-8")
            except (OSError, ValueError) as err:
                fail("cannot read --expect-file: %s" % err)
        if not text.strip():
            fail("selfcheck needs --expect, --expect-file or --print")
        if not selfcheck(parse_expectations(text)):
            fail("selfcheck failed: this copy of skillbouncer is not the reviewed one; do not trust its results")
        print("selfcheck passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:  # exit 1 means "changes to review" and must never come from a crash
        fail("internal error, no result: %s: %s" % (type(err).__name__, err))
