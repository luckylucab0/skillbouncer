# Security review of version 1.1.1 (November 2026)

Version 1.2.0 exists because of this review. It looked at the tool the way an
attacker would: what gets past the scanner, and what can be done to the
review itself. The scanner findings (R2 to R8) have a fixture in
`tests/make_evasion_fixtures.py` (case numbers E1 to E12) and an expected
detection in `tests/run_tests.py`. R1, R9 and R10 concern the baseline
script and are tested with a small tree built in `test_baseline`. R11 is a
set of rules in the procedure texts and has no test.

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

## Second round: review of 1.2.0 before release

The finished 1.2.0 code was reviewed once more by independent reviewers, and
every reported finding was reproduced by a second one before it counted.
All 44 held: 24 in the scanner, 12 in the baseline script, 8 in the
documentation. Most scanner gaps were already in 1.1.1. They are closed in
1.2.0; the scanner cases are fixtures E13 to E18 and the checks in
`test_hardening`, the baseline cases are checks in `test_baseline`.

| # | Finding | Severity | Closed by |
|---|---------|----------|-----------|
| S1 | Files under a folder named `.git` were skipped without a trace. | critical | Scanned like any other file. |
| S2 | A file with an image, font, PDF or media extension was never read as text: a shell script named `logo.png` gave an empty report. | critical | Skipped only when it starts with a media signature; otherwise `FS-DISGUISED-TEXT` and scanned as text. |
| S3 | A script with a ZIP appended was extracted as an archive and never scanned itself. | high | `ARCHIVE-POLYGLOT` (HIGH); the part in front of the ZIP data is scanned as code. |
| S4 | Content after the first 5 MB of a file was not scanned, with only a LOW note about size. | high | `FS-TRUNCATED` (HIGH). |
| S5 | An encrypted or corrupt archive entry, deeply nested JSON or a lone surrogate ended the scan in a traceback with exit status 1, which reads as "at most MEDIUM". | high | Per-entry `ARCHIVE-ERROR`, the rest is scanned; output with `backslashreplace`; every internal error exits 2. |
| S6 | Inputs of a few hundred KB stalled the scan for minutes: blank lines against rules anchored with `^\s*`, repeated `curl `, `http://`, `>` or `![` against unbounded quantifiers, and per-finding line counting. | high | Bounded quantifiers, a narrowed prefilter anchor, a line index. Timed in `test_hardening`. |
| S7 | Unread content was MEDIUM or silent: a NUL byte in a script, a binary tail after 8 KB of text, a `.tgz` as target, an empty target next to a full one, a folder that cannot be listed. | medium | Text with stray NUL bytes is scanned, binaries under text or code extensions are HIGH, `SCAN-EMPTY` per target, `IO-ERROR` for folders. |
| S8 | A byte order mark on line 1 switched off the rules anchored at the line start; UTF-16 files (the native encoding of `.reg`) skipped every content rule. | high | Text is decoded first (`FS-ENCODING` for UTF-16). |
| S9 | The prefilter dropped text written with dotless i or long s, which the exact rules match. | medium | The prefilter folds these letters; the proof runs over both fixture sets. |
| S10 | A pattern split over two lines was seen by the prefilter and lost in the per-line pass. | medium | Adjacent lines are tried as a pair when no single line matches. |
| S11 | Frontmatter checks read one line per key: nested maps, block scalars, quoted or dotted keys and YAML spellings of `name` got past `FM-EXTRA-FIELD` and `FM-NAME-COLLISION`. A lone `SKILL.md` as target got no frontmatter check at all. | medium | Fields are read with their continuation lines; `name` is normalised; a lone `SKILL.md` is checked like a skill folder. |
| S12 | `COMBO-PKG-*` was defeated by a `SKILL.md` or `plugin.json` dropped next to one half of a split stealer, and same-named skill folders overwrote each other in the inventory. | medium | A package is the outermost plugin or skill; labels of same-named folders carry their path. |
| S13 | `FILENAME-INJECTION` never saw folder names; `MD-HIDDEN-COMMENT` was LOW without an imperative word and missed `[Comment]:` and `.markdown` files. | medium | Folder names are checked; the comment rule is MEDIUM at least. |
| S14 | The baseline skipped `.git`, `__pycache__`, `.DS_Store` and `.in_use` at any depth, and `manifest.json` and `*.meta.json` anywhere: a payload under such a name never changed a hash. | critical | Every file is hashed. Claude's runtime files are left out only in their one place and only with the expected content. |
| S15 | A skill or plugin installed as a symlink was one link entry; nothing behind it was compared. Symlinked sync folders were not roots. | high | Recorded as a unit at its target. Other links to content outside the snapshot are reported by `diff` on every run. |
| S16 | A third copy of a unit name replaced the second one in the snapshot, and two unit IDs could share one document ID and overwrite each other at export. | high | Further copies get `<id>@<root>-2` and so on; document IDs are made distinct and `export` refuses duplicates. |
| S17 | `diff` exited 0 when units of the baseline were gone, `snapshot` passed with stray files and no skill or plugin, `export --only` without an ID exported everything as CLEAN, and `selfcheck` passed with a hash for a file it never compared. | high | Each of these exits 1 or 2 now. |
| S18 | Deeply nested JSON, file names that are not UTF-8 and wrong types in `manifest.json` ended the run in a traceback with exit code 1, which reads as "changes to review". A line break in a plugin name wrote a forged line into the summary. | medium | Hostile input is hashed and the run goes on; any internal error exits 2; names are printed on one line. |
| S19 | `names` listed folder names only, so a skill registered under another `name` in its frontmatter was missing from `--known-names`. Finding the unit of each file was quadratic and took minutes on large installs. | medium | Declared names are listed; one walk per root. |
| S20 | The procedure texts could not be followed in places: the rescan after a scanner update never came to an end once a unit was removed or left PENDING, step 8 of the install review could not be done for an archive and recorded other hashes than the installed package for a clone, a failed run had no value in the `runs` format, and the two procedure files disagreed on a missing plugin folder. | medium | `diff` looks only at unchanged units for the rescan and lists PENDING ones; SKILL.md and `monthly-run.md` name the extraction command, the `ACCEPTED` and `FAILED` values and one answer for the missing folder. |

## What the review did not solve

- The monthly run starts after the hooks of all installed plugins have run.
  It reports changes on disk; it cannot vouch for the session it runs in.
- `selfcheck` is run by one of the files it checks. The procedure therefore
  compares `sha256sum` output with the prompt first and uses `selfcheck` as a
  second line.
- Pattern matching stays evadable. The rules above close the techniques that
  were found, not the class. Reading every file in full remains the control
  that matters.
