# Security review of version 1.1.1 (November 2026)

Version 1.2.0 exists because of this review. It looked at the tool the way an
attacker would: what gets past the scanner, and what can be done to the
review itself. Each finding below has a fixture in
`tests/make_evasion_fixtures.py` (case numbers E1 to E12) and an expected
detection in `tests/run_tests.py`, so a regression shows up as a failing test.

## Findings and how 1.2.0 closes them

| # | Finding in 1.1.1 | Severity | Closed by |
|---|------------------|----------|-----------|
| R1 | The monthly run assumed fixed install folders. Where they did not exist, `snapshot` skipped them silently and covered only a fraction of what was installed. The run would have reported "no changes" forever. | critical | `snapshot --auto` discovers the install locations at runtime and prints them. A missing root or zero units exits 2. |
| R2 | Attacks on the reviewer were not detected: prose telling Claude to update the baseline so a plugin shows as clean, or to add a domain to an allowlist in the scanner. The monthly run also used the scripts from the install folder, which other plugins can modify, without checking them. | high | `META-TAMPER` (HIGH). `selfcheck` against hashes kept in the scheduled task's prompt. The procedure treats snippets as quotes and never lets a scanned text change the baseline. |
| R3 | Markdown hiding places were not flagged: link-reference comments (`[//]: # (...)`), reference-style image definitions with placeholders, runs of HTML entities, extra frontmatter fields carrying instructions. | high | `MD-HIDDEN-COMMENT`, `EXFIL-REF-IMG`, `HTML-ENTITIES`, `FM-EXTRA-FIELD`, `FM-LONG`. |
| R4 | Files that execute automatically but have no code extension were treated as prose: `.envrc`, launchd plists, systemd units, `.desktop`, `.reg`, `.vscode/tasks.json`, `.gitconfig`, `.pre-commit-config.yaml`. A plist or unit file without a suspicious keyword was silent and missing from the script inventory. | high | These files count as code and appear in the inventory. `AUTORUN-*` rules. |
| R5 | Capability combinations were per file. A stealer split into one file that reads credentials and another that uploads them triggered nothing. | medium | `COMBO-PKG-*` on the union of capabilities per package. |
| R6 | A dynamic import under an alias hid the network capability. | medium | Dynamic imports count as `EXEC` and `OBF-INDIRECT`; a method call with a URL literal counts as `NET`. |
| R7 | Base64 shorter than 120 characters was never decoded, so a short encoded shell command next to a decoder was only MEDIUM. | medium | `OBF-BASE64-SHORT` (HIGH) in files that decode at runtime. |
| R8 | Trigger hijacking produced nothing: a third-party skill named like a bundled one with a description claiming to replace it, and a file name phrased as an instruction. | medium | `FM-NAME-COLLISION`, `FM-DESC-HIJACK`, `FILENAME-INJECTION`, `--known-names`. |
| R9 | The baseline recorded no scanner version. Units cleared under old rules were never rescanned with new rules unless their hashes changed. | medium | `tool_version` in every baseline document; `diff` exits 1 with a rescan hint when it differs. |
| R10 | `node_modules/` was ignored by the baseline, so a compromised dependency update was invisible to the monthly diff. | medium | Covered, one aggregated hash per package folder. |
| R11 | Process gaps: "tests are false alarms" was exploitable; a sub-agent's CLEAN could override a scanner HIGH; hooks of installed plugins have already run when the monthly session starts; scanner snippets quote attacker text; name collisions were not checked. | medium | SKILL.md and `references/monthly-run.md` state each of these as a rule. |

Two further fail-open paths were fixed in 1.1.1 already (a directory named
`SKILL.md` crashed the scanner; twenty thousand unclosed HTML comments stalled
it for minutes), and three more turned up while 1.2.0 was written: a path
that does not exist, a file with an archive extension that is not a ZIP, and
an empty folder each ended in an empty report with exit code 0. They now end
in `SCAN-TARGET`, `ARCHIVE-ERROR` and `SCAN-EMPTY` (HIGH, exit code 2).

## What the review did not solve

- The monthly run starts after the hooks of all installed plugins have run.
  It reports changes on disk; it cannot vouch for the session it runs in.
- `selfcheck` is run by one of the files it checks. The procedure therefore
  compares `sha256sum` output with the prompt first and uses `selfcheck` as a
  second line.
- Pattern matching stays evadable. The rules above close the techniques that
  were found, not the class. Reading every file in full remains the control
  that matters.
