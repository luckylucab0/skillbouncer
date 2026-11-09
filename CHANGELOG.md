# Changelog

## 1.2.0

Renamed from skillcheck to skillbouncer, translated to English, and hardened
after a security review of 1.1.1 (see `docs/security-review-2026-11.md`).

After updating, produce new selfcheck hashes for the monthly task
(`sha256sum skills/skillbouncer/scripts/*.py skills/skillbouncer/SKILL.md`).
The first monthly run with 1.2.0 reports "scanner rules changed since
baseline" and scans every unit once.

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

### Procedure

- The monthly run starts with a selfcheck and reports with the caveat that
  hooks of installed plugins ran before the check; a new or changed hook is
  always PENDING.
- Test and eval files are false alarms only if nothing references or
  executes them.
- A sub-agent's CLEAN never dispositions a scanner HIGH; every HIGH gets a
  written reason.
- Name collisions with installed skills are checked before install.

### Tests and repository

- `tests/run_tests.py` with expected rule IDs per fixture, new evasion
  fixtures, a CI workflow for Python 3.9 and 3.13.
- README in English and German, `docs/` with the review findings and the
  development notes.

### Corpus check before release

The same set of installed plugins and skills was scanned with 1.1.1 and with
1.2.0: 3644 files in 194 skills and plugins. Every finding of 1.1.1 is still
reported by 1.2.0.

|          | 1.1.1 | 1.2.0 |
|----------|------:|------:|
| Findings |  3519 |  3617 |
| HIGH     |    55 |    59 |
| MEDIUM   |  1225 |  1292 |
| LOW      |  1206 |  1211 |
| INFO     |  1033 |  1055 |

Where the 98 additional findings come from:

- `FM-NAME-COLLISION` (30): the bundled skills themselves, which carry the
  names the rule protects. None are left with `--no-builtin-names`.
- `MAL-SKILL-TAMPER` (+27), `MAL-PUBLISH` (+3), `CODE-*` and `COMBO-ENV-NET`
  (+29 together, LOW and INFO except two `CODE-HOME`): mostly CI workflow
  files and other auto-run files, which now count as code.
- `META-TAMPER` (4, the only new HIGH): three in the installed 1.1.1 copy of
  this tool, which describes its own baseline and verdicts, and one changelog
  entry of another plugin that mentions an allowlist. All four are false
  alarms and stay visible on purpose: text about the review tooling is what
  the rule is for.
- `COMBO-PKG-EXFIL` (2) and `OBF-INDIRECT` (2): test and maintenance scripts
  of two plugins. Read and found unremarkable.
- `FM-DESC-HIJACK` (1): a skill whose description tells the model to use it
  before any other work. Correct hit, kept as MEDIUM.

The other new rules did not fire on this corpus. The 1.2.0 scan took about
70 seconds.

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
