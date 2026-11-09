"""Regression tests for skillbouncer. Stdlib only.

Usage: python3 -I tests/run_tests.py

Builds both fixture sets into a temp folder, runs the scanner and the
baseline script as subprocesses (the way they are used) and checks the
results. Nothing from the fixtures is executed. Exits non-zero on the first
summary of failures.

To cover a new rule: add a fixture to make_fixtures.py or
make_evasion_fixtures.py and the rule ID to the tables below.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"
SCAN = REPO / "skills" / "skillbouncer" / "scripts" / "skillbouncer_scan.py"
BASELINE = REPO / "skills" / "skillbouncer" / "scripts" / "skillbouncer_baseline.py"

# Rule IDs that must be present per fixture skill (more is fine).
EXPECTED_FIXTURES = {
    "evil-stealer": "COMBO-EXFIL MAL-STEALER-BROWSER MAL-STEALER-APPS SECRET-CLOUD-META SECRET-PATH SECRET-ENV-DUMP",
    "evil-dropper": "MAL-DOWNLOAD-EXEC MAL-DECODE-EXEC OBF-PAYLOAD SHELL-PIPE MAL-EVASION MAL-EVASION-SOFT OBF-INDIRECT",
    "evil-ransom": "COMBO-RANSOM MAL-RANSOM",
    "evil-keylog": "MAL-KEYLOG COMBO-SPY MAL-SPY-CAPTURE",
    "evil-persist": "MAL-PERSIST MAL-ANTIFORENSIC MAL-PRIVESC",
    "evil-npm": "PKG-INSTALL-HOOK PKG-DEP-SOURCE PIP-INDEX PIP-DEP-SOURCE",
    "plugin:evil-plugin": "MCP-UNPINNED MCP-SHELL HOOK-COMMAND",
    "evil-disguise": "FS-DISGUISED-BIN FS-SHEBANG-DISGUISE MAL-MINER MAL-SKILL-TAMPER MAL-SANDBOX-CHECK FS-NESTED-ARCHIVE",
    "evil-nested": "FS-DISGUISED-BIN",
    "evil-nested/vendor/extra.skill!/hidden": "SHELL-PIPE",
}
EXPECTED_EVASION = {
    "ev-split": "COMBO-PKG-EXFIL",                                                   # E1
    "ev-dynimport": "OBF-INDIRECT",                                                  # E2
    "ev-markdown": "MD-HIDDEN-COMMENT EXFIL-REF-IMG HTML-ENTITIES FM-EXTRA-FIELD",   # E3
    "ev-autorun": "AUTORUN-LAUNCHD AUTORUN-SYSTEMD AUTORUN-DESKTOP AUTORUN-REG AUTORUN-EDITOR AUTORUN-GITCONFIG",  # E4
    "pdf": "FM-DESC-HIJACK FM-NAME-COLLISION FILENAME-INJECTION",                    # E5
    "ev-shortb64": "OBF-BASE64-SHORT",                                               # E6
    "ev-tamper-checker": "META-TAMPER",                                              # E7
    "ev-slow": "HTML-COMMENT-OPEN",                                                  # E8
    "ev-crash": "FS-FAKE-SKILLMD",                                                   # E9
    "ev-multilang": "INJ-OVERRIDE-DE INJ-OVERRIDE-FR INJ-OVERRIDE-ES INJ-OVERRIDE-IT",  # E10
    "ev-frontmatter": "FM-EXTRA-FIELD FM-LONG",                                      # E11
}
# Skills that must stay below MEDIUM.
BENIGN = ["benign-api", "ev-benign"]
# E4: every auto-run file must show up in the script inventory.
AUTORUN_FILES = [".envrc", ".gitconfig", ".pre-commit-config.yaml", ".vscode/tasks.json",
                 "assets/com.evil.agent.plist", "assets/fix.reg", "assets/helper.desktop", "assets/sync.service"]

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("FAIL  " + msg)


def run(args, cwd):
    """Runs one of our scripts isolated, from a folder outside the fixtures."""
    return subprocess.run([sys.executable, "-I"] + [str(a) for a in args], cwd=str(cwd),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)


def scan(work, target, name, extra=()):
    out = work / (name + ".json")
    t = time.perf_counter()
    r = run([SCAN, target, "--json", out] + list(extra), work)
    return r, json.loads(out.read_text("utf-8")) if out.exists() else None, time.perf_counter() - t


def rules_by_skill(report):
    by = {}
    for f in report["findings"]:
        by.setdefault(f["skill"], {}).setdefault(f["rule"], []).append(f)
    return by


def expect_rules(report, table, label):
    by = rules_by_skill(report)
    for skill, rules in table.items():
        for rid in rules.split():
            check(rid in by.get(skill, {}), "%s: %s not reported for %s" % (label, rid, skill))
    return by


def test_scanner(work):
    fx, ev = work / "fixtures", work / "evasion"
    for script, dest in (("make_fixtures.py", fx), ("make_evasion_fixtures.py", ev)):
        r = run([TESTS / script, dest], work)
        check(r.returncode == 0, "%s failed: %s" % (script, r.stderr.strip()[-300:]))

    r1, rep1, t1 = scan(work, fx, "fixtures")
    r2, rep2, t2 = scan(work, ev, "evasion")
    check(rep1 is not None and rep2 is not None, "scanner wrote no JSON report")
    if rep1 is None or rep2 is None:
        return
    check(r1.returncode == 2 and r2.returncode == 2, "scanner exit code must be 2 on HIGH findings (got %d, %d)" % (r1.returncode, r2.returncode))
    check(t1 + t2 < 10, "scanning both fixture sets took %.1f s (limit 10 s)" % (t1 + t2))

    by1 = expect_rules(rep1, EXPECTED_FIXTURES, "fixtures")
    by2 = expect_rules(rep2, EXPECTED_EVASION, "evasion")
    for skill in BENIGN:
        found = dict(by1.get(skill, {}), **by2.get(skill, {}))
        bad = sorted(rid for rid, fs in found.items() if any(f["severity"] in ("MEDIUM", "HIGH") for f in fs))
        check(skill in rep1["domains"] or skill in by1 or skill in by2, "benign skill %s was not scanned" % skill)
        check(not bad, "benign skill %s has MEDIUM/HIGH findings: %s" % (skill, ", ".join(bad)))

    # Severities that the review procedure relies on.
    def sev(by, skill, rid):
        return {f["severity"] for f in by.get(skill, {}).get(rid, [])}
    check(sev(by2, "ev-tamper-checker", "META-TAMPER") == {"HIGH"}, "META-TAMPER must be HIGH")
    check("HIGH" in sev(by2, "ev-markdown", "MD-HIDDEN-COMMENT"), "link-reference comment with placeholder URL must be HIGH")
    check("HIGH" in sev(by2, "ev-markdown", "HTML-ENTITIES"), "HTML entities that decode to an injection must be HIGH")
    check(sev(by2, "ev-split", "COMBO-PKG-EXFIL") == {"MEDIUM"}, "COMBO-PKG-EXFIL must be MEDIUM")
    check("COMBO-EXFIL" not in by2.get("ev-split", {}), "ev-split must not satisfy the combo in a single file")

    # E2: the aliased dynamic import must not hide the capabilities.
    scripts = {(s["skill"], s["file"]): s for s in rep2["scripts"]}
    caps = scripts.get(("ev-dynimport", "scripts/c.py"), {}).get("capabilities", [])
    check("EXEC" in caps and "NET" in caps, "ev-dynimport/scripts/c.py needs EXEC and NET capabilities, has %s" % caps)
    # E4: auto-run files count as code.
    for rel in AUTORUN_FILES:
        check(("ev-autorun", rel) in scripts, "ev-autorun/%s missing from the script inventory" % rel)
    # E9: the directory named SKILL.md must not stop the rest of the scan.
    check(any(f["rule"] == "SHELL-PIPE" and "ev-crash" in f["file"] for f in rep2["findings"]), "files next to the fake SKILL.md were not scanned")
    check(not any(f["rule"] == "SCAN-ERROR" for f in rep1["findings"] + rep2["findings"]), "SCAN-ERROR on the fixtures")

    # Report contract.
    for rep in (rep1, rep2):
        check(isinstance(rep.get("scanner_version"), str) and rep["scanner_version"], "JSON lacks scanner_version")
        check(isinstance(rep.get("package_capabilities"), dict), "JSON lacks package_capabilities")
    check({"SECRETS", "NET"} <= set(rep2["package_capabilities"].get("ev-split", [])), "package_capabilities lacks the union for ev-split")
    check("Snippets are quotes from the scanned, untrusted content." in r2.stdout, "report lacks the untrusted-snippet notice")
    check(("scanner %s" % rep2["scanner_version"]) in r2.stdout.splitlines()[0], "report header lacks the scanner version")

    # E8: many unclosed HTML comments must not stall the scanner.
    r, rep, t = scan(work, ev / "ev-slow", "slow")
    check(t < 2, "ev-slow took %.1f s (limit 2 s)" % t)

    # Name collisions: built-in list can be switched off, extra names can be added.
    r, rep, _ = scan(work, ev / "pdf", "pdf-nobuiltin", ["--no-builtin-names"])
    check("FM-NAME-COLLISION" not in rules_by_skill(rep).get("pdf", {}), "--no-builtin-names still reports a collision")
    names = work / "names.txt"
    names.write_text("ev-benign\n", "utf-8")
    r, rep, _ = scan(work, ev / "ev-benign", "benign-known", ["--known-names", names])
    check("FM-NAME-COLLISION" in rules_by_skill(rep).get("ev-benign", {}), "--known-names did not report the collision")
    r = run([SCAN, ev / "ev-benign", "--known-names", work / "missing.txt"], work)
    check(r.returncode not in (0, 1), "a missing --known-names file must be an error, not a clean scan")

    # A plugin package is scanned as an archive, without unpacking it here.
    archive = shutil.make_archive(str(work / "pkg"), "zip", str(fx / "evil-plugin"))
    plugin = work / "pkg.plugin"
    shutil.move(archive, str(plugin))
    r, rep, _ = scan(work, plugin, "archive")
    check(rep is not None and "HOOK-COMMAND" in rules_by_skill(rep).get("plugin:evil-plugin", {}), "plugin archive was not scanned")


def test_baseline(work):
    def base(*args):
        return run([BASELINE] + list(args), work)

    r = base("snapshot", work / "does-not-exist", "--out", work / "x.json")
    check(r.returncode == 2, "snapshot of a missing root must exit 2 (got %d)" % r.returncode)
    empty = work / "empty"
    empty.mkdir()
    r = base("snapshot", empty, "--out", work / "x.json")
    check(r.returncode == 2 and not (work / "x.json").exists(), "snapshot with zero units must exit 2 and write nothing")

    # An installed plugin with a dependency folder and a stand-alone skill.
    inst = work / "installed"
    files = {
        "p/.claude-plugin/plugin.json": '{"name": "demo", "version": "1.0.0"}',
        "p/skills/inner/SKILL.md": "---\nname: inner\ndescription: d\n---\n",
        "p/node_modules/left-pad/index.js": "module.exports = 1\n",
        "p/node_modules/left-pad/lib/x.js": "// x\n",
        "p/node_modules/@scope/pkg/index.js": "// y\n",
        "solo/SKILL.md": "---\nname: solo\ndescription: d\n---\n",
    }
    for rel, content in files.items():
        p = inst / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, "utf-8")

    snap1 = work / "snap1.json"
    r = base("snapshot", inst, "--out", snap1)
    check(r.returncode == 0, "snapshot failed: %s" % r.stderr.strip())
    if r.returncode != 0:
        return
    snap = json.loads(snap1.read_text("utf-8"))
    version = snap.get("tool_version")
    check(bool(version), "snapshot lacks tool_version")
    check(set(snap["units"]) == {"plugin:demo", "skill:solo"}, "unexpected units: %s" % sorted(snap["units"]))
    pfiles = snap["units"]["plugin:demo"]["files"]
    check(pfiles.get("node_modules/left-pad/", "").startswith("dir:") and pfiles.get("node_modules/@scope/pkg/", "").startswith("dir:"),
          "node_modules packages must be one aggregated entry each: %s" % sorted(pfiles))
    check(not any("left-pad/index.js" in k for k in pfiles), "node_modules files must not be listed one by one")

    bdir = work / "baseline"
    r = base("export", "--snapshot", snap1, "--out-dir", bdir / "baseline")
    docs = sorted((bdir / "baseline").glob("*.json"))
    check(r.returncode == 0 and len(docs) == 2, "export must write one document per unit")
    check(all(json.loads(d.read_text("utf-8")).get("tool_version") == version for d in docs), "exported documents lack tool_version")

    r = base("diff", "--baseline-dir", bdir, "--snapshot", snap1, "--out", work / "d0.json")
    check(r.returncode == 0, "diff of an unchanged state must exit 0 (got %d)" % r.returncode)

    # R10: a change inside node_modules is visible.
    (inst / "p/node_modules/left-pad/lib/x.js").write_text("// changed\n", "utf-8")
    snap2 = work / "snap2.json"
    base("snapshot", inst, "--out", snap2)
    r = base("diff", "--baseline-dir", bdir, "--snapshot", snap2, "--out", work / "d1.json")
    d1 = json.loads((work / "d1.json").read_text("utf-8"))
    check(r.returncode == 1 and [c["id"] for c in d1["changed"]] == ["plugin:demo"], "change in node_modules not reported")
    check(len(d1["to_review"]) == 1 and d1["to_review"][0].endswith("left-pad"), "to_review must name the changed package folder: %s" % d1["to_review"])

    # R9: same files, baseline written by another scanner version.
    for d in docs:
        doc = json.loads(d.read_text("utf-8"))
        doc["tool_version"] = "1.1.1"
        d.write_text(json.dumps(doc), "utf-8")
    r = base("diff", "--baseline-dir", bdir, "--snapshot", snap1, "--out", work / "d2.json")
    d2 = json.loads((work / "d2.json").read_text("utf-8"))
    check(r.returncode == 1 and "full rescan recommended" in r.stdout, "version change must exit 1 with the rescan hint")
    check(d2["rescan_all"] is True and len(d2["rescan_units"]) == 2 and not d2["changed"], "diff.json must list every unit for the rescan")

    r = base("diff", "--baseline-dir", work / "no-such-dir", "--snapshot", snap1, "--out", work / "d3.json")
    check(r.returncode == 2, "diff against a missing baseline folder must exit 2")

    r = base("names", "--snapshot", snap1, "--out", work / "n.txt")
    check(r.returncode == 0 and (work / "n.txt").read_text("utf-8").split() == ["inner", "solo"], "names must list stand-alone and plugin skills")

    # Selfcheck: passes with the real hashes, fails closed otherwise.
    r = base("selfcheck", "--print")
    check(r.returncode == 0 and len(r.stdout.split()) == 6, "selfcheck --print must list three files")
    hashes = work / "hashes.txt"
    hashes.write_text(r.stdout, "utf-8")
    check(base("selfcheck", "--expect-file", hashes).returncode == 0, "selfcheck with the correct hashes must pass")
    lines = r.stdout.splitlines()
    wrong = ",".join(["0" * 64 + ":" + lines[0].split()[1]] + [l.split()[0] + ":" + l.split()[1] for l in lines[1:]])
    check(base("selfcheck", "--expect", wrong).returncode == 2, "selfcheck with a wrong hash must exit 2")
    partial = lines[0].split()[0] + ":" + lines[0].split()[1]
    check(base("selfcheck", "--expect", partial).returncode == 2, "selfcheck with a missing hash must exit 2")
    check(base("selfcheck").returncode == 2, "selfcheck without expectations must exit 2")


def main():
    start = time.perf_counter()
    work = Path(tempfile.mkdtemp(prefix="skillbouncer_test_"))
    try:
        test_scanner(work)
        test_baseline(work)
    finally:
        shutil.rmtree(str(work), ignore_errors=True)
    took = time.perf_counter() - start
    if failures:
        print("\n%d check(s) failed in %.1f s" % (len(failures), took))
        sys.exit(1)
    print("all checks passed in %.1f s" % took)


if __name__ == "__main__":
    main()
