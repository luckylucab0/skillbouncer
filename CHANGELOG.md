# Changelog

## 1.2.0

Renamed from skillcheck to skillbouncer, translated to English, and hardened
after a security review of 1.1.1 and a second review of the finished 1.2.0
code (see `docs/security-review-2026-11.md`).

After updating, produce new selfcheck hashes for the monthly task
(`sha256sum skills/skillbouncer/scripts/*.py skills/skillbouncer/SKILL.md`).
The first monthly run with 1.2.0 reports "scanner rules changed since
baseline" and scans every unit once. Against a baseline written by 1.1.1 it
also shows what the baseline did not cover before: `.git`, `__pycache__` and
`.DS_Store` entries as added files, and `loose:` units that held nothing but
a sync marker as removed.

### Changed

- Plugin, skill directory and scripts are named `skillbouncer`
  (`skillbouncer_scan.py`, `skillbouncer_baseline.py`); the references are
  `review-prompt.md`, `monthly-run.md` and `script-analysis.md`.
- All skill texts, rule descriptions, report headings, messages and comments
  are English. The skill answers in the user's language. The German override
  and concealment rules stay: they detect German-language injection.
- No personal names; the baseline store is configurable (an artifact
  database by default, a JSON directory in a private repository as the
  alternative). The scripts only read and write JSON directories.
- The Swiss-law items in the review prompt are labelled as an example of a
  jurisdiction check.
- Verdict words are APPROVED, APPROVED WITH NOTES and BLOCKED.

### Scanner

- `META-TAMPER` (HIGH): text aimed at the review tooling (baseline,
  allowlist, verdict, scanner).
- Markdown that renders as nothing: `MD-HIDDEN-COMMENT`, `EXFIL-REF-IMG`,
  `HTML-ENTITIES`, `FM-EXTRA-FIELD`, `FM-LONG`.
- Files that run on their own count as code and appear in the script
  inventory: `.envrc`, shell profiles, launchd plists, systemd units,
  `.desktop`, `.reg`, editor and devcontainer tasks, git configuration,
  `.pre-commit-config.yaml`, everything under `.github/workflows/`, and more
  script and build formats. New rules `AUTORUN-LAUNCHD`, `AUTORUN-SYSTEMD`,
  `AUTORUN-DESKTOP`, `AUTORUN-REG`, `AUTORUN-EDITOR`, `AUTORUN-GITCONFIG`.
- `COMBO-PKG-*` (MEDIUM): HIGH capability combinations that only add up
  across the files of one skill or plugin.
- Dynamic imports count as `EXEC` and `OBF-INDIRECT`; a method call with a
  URL literal counts as network access.
- `OBF-BASE64-SHORT` (HIGH): a short Base64 string that decodes to a command
  or URL, in a file that decodes at runtime.
- `FILENAME-INJECTION`, `FM-DESC-HIJACK`, `FM-NAME-COLLISION`, with
  `--known-names FILE` and `--no-builtin-names`.
- `INJ-OVERRIDE-FR`, `INJ-OVERRIDE-ES`, `INJ-OVERRIDE-IT`.
- `VERSION`, shown in the report header and written to the JSON as
  `scanner_version`; `package_capabilities` in the JSON; a notice that
  snippets are quotes from untrusted content; `--version`.
- Fail closed: a path that does not exist (`SCAN-TARGET`), a file with an
  archive extension that is not a ZIP (`ARCHIVE-ERROR`) and a scan of zero
  files (`SCAN-EMPTY`) are HIGH findings; an unreadable file is HIGH
  (`IO-ERROR`, was LOW); usage errors exit with 2. A single file can be
  given as target.

From the second review:

- Nothing is skipped by name or extension any more. Files under `.git` are
  scanned. A file with an image, font, PDF or media extension that is plain
  text is reported as `FS-DISGUISED-TEXT` (MEDIUM) and scanned as text.
- Binary files (pictures, fonts, files that are mostly NUL bytes) get the
  rules over their readable text, one finding per rule and file, marked
  "readable text inside a binary file". A shell runs script lines inside a
  file whatever its first bytes are.
- Text is decoded before the rules run: a byte order mark, UTF-16
  (`FS-ENCODING`, LOW), stray NUL bytes and every kind of line break.
- Content that was not read in full is a finding: `FS-TRUNCATED` (HIGH)
  beyond 5 MB, `FS-UNKNOWN-BIN` (HIGH) for a binary behind a text or code
  extension, `ARCHIVE-ERROR` for a single archive entry that cannot be
  extracted (the others are still scanned) and for a `.tgz` or `.7z` given
  as target, `IO-ERROR` for a folder that cannot be listed, `SCAN-EMPTY`
  per target.
- `ARCHIVE-POLYGLOT` (HIGH): a script with a ZIP appended. The part in front
  of the first archive entry is scanned as code.
- A pattern wrapped over two lines is found (the description says so).
- Frontmatter fields are read with their continuation lines, `name` is
  normalised before the collision check, and a lone `SKILL.md` given as
  target gets the frontmatter checks.
- A package is the outermost plugin or skill, so a `SKILL.md` dropped next
  to one half of a split stealer no longer defeats `COMBO-PKG-*`. Skills
  with the same folder name are listed separately, with their path.
- `FILENAME-INJECTION` covers folder names. `MD-HIDDEN-COMMENT` is MEDIUM at
  least and covers `[Comment]:` and `.markdown` files.
- No stalls: bounded quantifiers (also in `SECRET-ENV`, `SHELL-REVERSE` and
  `SHELL-DESTRUCT`) and a line index. Hostile inputs that took minutes are
  timed in the tests. A pipe in place of a file is `IO-ERROR` and is never
  opened.
- Every internal error exits 2, and the report is written even when a file
  name or snippet cannot be encoded.

### Baseline script

- `snapshot --auto` discovers the install locations of the session and
  prints them. A missing root or zero units exits 2. Before, missing roots
  were skipped silently and an empty snapshot read as "no changes".
- `tool_version` in snapshots and baseline documents; `diff` exits 1 with a
  rescan hint when the baseline was written by another scanner version.
- `selfcheck` compares both scripts and SKILL.md with hashes kept outside
  the sandbox.
- `node_modules` is covered, one aggregated hash per package folder.
- `names` lists installed skill names for `--known-names`.
- A plugin installed in two roots with differing content is tracked as a
  second unit.

From the second review:

- Every file is hashed, including `.git`, `__pycache__` and `.DS_Store`.
  Claude's own runtime files are left out only in the one place where they
  belong and only with the expected content. Pipes, sockets and device
  nodes are entries (`special:<type>`).
- A skill or plugin installed as a symlink is recorded as a unit at its
  target. Any other symlink to content outside the snapshot is listed under
  `uncovered_links`, and `diff` reports it on every run.
- `diff` exits 1 for removed units as well, and 2 for any error. It lists
  the units to rescan after a scanner update in `rescan_ids` (unchanged
  units only, so the list empties once they are exported again) and the
  units that wait for the user under `pending`.
- `snapshot` exits 2 when no skill or plugin is found, even with stray
  files, and when something cannot be read. `export --only` without an ID
  exits 2. `selfcheck` exits 2 for a hash of a file it does not cover, for
  two hashes for one file and for `--print` together with expectations.
- Further copies of a unit name get `<id>@<root>-2` and so on; document IDs
  that would collide are made distinct.
- `names` also lists the name each SKILL.md declares.
- Names from packages are printed on one line. Large installs are walked
  once per root instead of once per file.

### Procedure

- The monthly run starts with a selfcheck and reports with the caveat that
  hooks of installed plugins ran before the check; a new or changed hook is
  always PENDING.
- Test and eval files are false alarms only if nothing references or
  executes them.
- A sub-agent's CLEAN never dispositions a scanner HIGH; every HIGH gets a
  written reason.
- Name collisions with installed skills are checked before install.
- An archive is extracted for reading with `python3 -I -m zipfile -e`, after
  the scan. The baseline of a new install is taken from the package that
  gets installed, not from the clone.
- `ACCEPTED` records a unit the user approved with notes; `FAILED` records a
  run that did not complete.
- The monthly run says how to judge new `.pyc` entries, removed units and
  symlinks to content outside the snapshot.

### Tests and repository

- `tests/run_tests.py` with expected rule IDs per fixture, new evasion
  fixtures (E1 to E19), hardening checks for the fail-closed paths and for
  stalls, a CI workflow for Python 3.9 and 3.13.
- README in English and German, `docs/` with the review findings and the
  development notes.

### Corpus check before release

The same set of installed plugins and skills was scanned with 1.1.1 and with
1.2.0: 3644 files in 260 skill folders (194 distinct names). Every finding of
1.1.1 is still reported by 1.2.0.

|          | 1.1.1 | 1.2.0 |
|----------|------:|------:|
| Findings |  3519 |  3620 |
| HIGH     |    55 |    59 |
| MEDIUM   |  1225 |  1295 |
| LOW      |  1206 |  1211 |
| INFO     |  1033 |  1055 |

Where the 101 additional findings come from:

- `FM-NAME-COLLISION` (30): the bundled skills themselves, which carry the
  names the rule protects. None are left with `--no-builtin-names`.
- `MAL-SKILL-TAMPER` (+28), `MAL-PUBLISH` (+3), `CODE-*` and `COMBO-ENV-NET`
  (+29 together, LOW and INFO except two `CODE-HOME`): mostly CI workflow
  files and other auto-run files, which now count as code. One
  `MAL-SKILL-TAMPER` is the readable text of a coverage database that
  holds paths of skill folders.
- `META-TAMPER` (4, the only new HIGH): three in the installed 1.1.1 copy of
  this tool, which describes its own baseline and verdicts, and one changelog
  entry of another plugin that mentions an allowlist. All four are false
  alarms and stay visible on purpose: text about the review tooling is what
  the rule is for.
- `COMBO-PKG-EXFIL` (2) and `OBF-INDIRECT` (2): test and maintenance scripts
  of two plugins. Read and found unremarkable.
- `FM-DESC-HIJACK` (1): a skill whose description tells the model to use it
  before any other work. Correct hit, kept as MEDIUM.
- `FM-EXTRA-FIELD` (2): two skills with a frontmatter field that addresses
  the assistant. Read and found unremarkable; kept as MEDIUM.

The other new rules did not fire on this corpus. The 1.2.0 scan took about
75 seconds.

## 1.1.1

- The scanner no longer fails open: a directory named `SKILL.md` used to
  crash it (`FS-FAKE-SKILLMD`), and every per-file exception now becomes a
  `SCAN-ERROR` HIGH finding.
- Many unclosed HTML comments no longer stall the scan for minutes
  (`HTML-COMMENT-OPEN`).

## 1.1.0

- Script analysis: malware rules (`MAL-*`), capabilities per script with
  dangerous combinations (`COMBO-*`), the script inventory, checks of
  manifests that run or download code (`PKG-*`, `PIP-*`, `MCP-*`, `HOOK-*`),
  signatures of embedded binaries (`OBF-PAYLOAD`, `FS-DISGUISED-BIN`).
- `references/script-analysis.md` (then in German) as the checklist for
  reading code.

## 1.0.0

- Initial version: static scanner for prompt injection, exfiltration,
  credential access, dangerous shell commands and obfuscation; hash baseline
  with `snapshot`, `export` and `diff`; review procedure with the two modes.
