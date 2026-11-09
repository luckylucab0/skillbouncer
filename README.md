# skillbouncer

English | [Deutsch](README.de.md)

skillbouncer is a Claude plugin that reviews third-party Claude skills and
plugins before they are installed, and re-checks the installed ones once a
month for changes that arrived through updates. It consists of one skill (the
review procedure Claude follows) and two Python scripts that need nothing but
the standard library: a static pattern scanner and a hash baseline tool.

The skill texts, the messages of the scripts and the rest of the
documentation are English. Claude still answers in the user's language.

## What it does and does not do

It does:

- Scan a package for known patterns of prompt injection, data exfiltration,
  credential access, malware in bundled scripts, install hooks, MCP server
  configurations, files that start on their own, disguised binaries and
  Markdown that renders as nothing but is still read by the model.
- Give Claude a fixed procedure for reading the package in full, tracing data
  flows in scripts and writing a verdict with a reason for every serious hit.
- Record a SHA-256 hash per file of the reviewed state and report later which
  files are new, changed or gone.

It does not:

- Run anything. The analysis is static only. The scanner never executes,
  imports or fetches what it scans, so there is no behavioural analysis and
  nothing is observed at runtime.
- Deliver a verdict on its own. The scanner is a filter. It finds candidates
  that Claude or a human must read in context. An empty report means "no
  known patterns", not "safe".
- Sandbox or monitor installed plugins. Once a plugin is installed,
  skillbouncer only notices that its files changed, and only at the next
  monthly run.

## Install

Each release has a plugin file attached, for example
`skillbouncer-v1.2.0.plugin`. A `.plugin` file is a ZIP archive with
`.claude-plugin/plugin.json` at its root. Download it from the releases page
of this repository and upload it in the Claude app under Customize > Plugins.

To build the file from a checkout, run this in the repository root:

```bash
zip -r skillbouncer-v1.2.0.plugin . \
    -x '.git/*' '.github/*' 'tests/*' 'docs/*' 'README.md' 'README.de.md' \
       'CHANGELOG.md' 'CLAUDE.md' '.gitignore' '*__pycache__*' '*.plugin'
```

The exclusions keep tests, repository metadata and development documents out
of the package. `__pycache__` folders appear after running the tests and
would be reported as binaries by the scanner, and `*.plugin` keeps earlier
builds out. The result contains `.claude-plugin/`, `skills/` and `LICENSE`.

After installing, set up the monthly task (see below) if you want mode B.

## The two modes

**Mode A: review before install.** Claude fetches the package without using
it, takes an inventory, runs the scanner, reads every SKILL.md, reference
file and script in full, analyses the scripts for malicious behaviour and
reports a verdict: APPROVED, APPROVED WITH NOTES or BLOCKED. An approved
package is installed from exactly the reviewed state and added to the
baseline. The procedure is in `skills/skillbouncer/SKILL.md`; the script
checklist is in `skills/skillbouncer/references/script-analysis.md`.

**Mode B: monthly check against a hash baseline.** A scheduled task verifies
skillbouncer's own files first, records the current hashes of everything
installed, compares them with the baseline and reviews only what is new or
changed. Unremarkable changes update the baseline; everything else is marked
PENDING and waits for the user's decision. When the scanner version differs
from the one recorded in the baseline, every unit is scanned again, because
units cleared under older rules have never been seen by the new ones. The
procedure is in `skills/skillbouncer/references/monthly-run.md`.

## Severity levels and exit codes

| Level | Meaning | Examples |
|-------|---------|----------|
| HIGH | Blocks the install unless each hit is explained in writing as a false alarm. | Hidden instructions, instructions aimed at the review itself (`META-TAMPER`), credentials plus network access in one script (`COMBO-EXFIL`), binaries, symlinks, a file the scanner could not process (`SCAN-ERROR`) |
| MEDIUM | Needs a decision by the user. | Hooks and install scripts, auto-run configuration (`AUTORUN-*`), unpinned MCP servers (`MCP-UNPINNED`), a skill name that collides with an installed skill (`FM-NAME-COLLISION`) |
| LOW | Worth knowing, rarely a problem alone. | Detached background processes (`CODE-BACKGROUND`), network access plus process start (`COMBO-FETCH-EXEC`) |
| INFO | Inventory, no judgement. | A file contains code (`CODE-FILE`), a declared MCP server (`MCP-SERVER`), a nested archive that was unpacked and scanned (`ARCHIVE-SCANNED`) |

The full list of what counts as a finding at each level is in SKILL.md.

Scanner exit codes:

| Code | Meaning |
|------|---------|
| 0 | No finding above LOW |
| 1 | At least one MEDIUM finding |
| 2 | At least one HIGH finding |

The exit code is computed from all findings. `--min-severity` only filters
the text output. A file that crashes a check becomes a HIGH finding
(`SCAN-ERROR`), so a partly failed scan cannot exit 0.

## Running the scanner standalone

Requirements: Python 3.9 or newer, no packages. Two rules apply to every
call:

- Start the scripts with `python3 -I`. In isolated mode Python loads no
  modules from the current directory or the script's directory, so a planted
  `json.py` in the package under review is not imported.
- Use a working directory outside the scanned tree.

```bash
cd "$(mktemp -d)"
S=/path/to/skillbouncer/skills/skillbouncer/scripts

# Optional: names of the skills already installed, for the collision check.
python3 -I $S/skillbouncer_baseline.py snapshot --auto --out snap.json
python3 -I $S/skillbouncer_baseline.py names --snapshot snap.json --out names.txt

python3 -I $S/skillbouncer_scan.py /path/to/package \
    --json scan.json --min-severity MEDIUM --known-names names.txt
```

The path may be a folder with many skills, a single skill folder or a
ZIP-based archive (`.zip`, `.skill`, `.plugin`, `.whl`, `.vsix`, `.xpi`,
`.egg`). Archives are extracted safely into a temporary folder that is
deleted afterwards; nested ZIP-based archives are followed two levels deep.
Other archive formats such as `.tar.gz` or `.7z` are reported as
`FS-NESTED-ARCHIVE` and not unpacked.

Options:

| Option | Effect |
|--------|--------|
| `--json FILE` | Also write all findings, the script inventory and the domain inventory as JSON. |
| `--min-severity {INFO,LOW,MEDIUM,HIGH}` | Lowest severity shown in the text report. Default `LOW`. |
| `--max-per-rule N` | Lines shown per rule and skill in the text report. Default 8; the JSON holds all hits. |
| `--known-names FILE` | File with one installed skill name per line. A scanned skill that reuses one is reported. |
| `--no-builtin-names` | Skip the built-in list of bundled skill names. Use it when scanning the bundled skills themselves. |
| `--version` | Print the scanner version. |

Read the "Files scanned" count in the report header. A path that does not
exist, a broken archive or an empty folder ends in a HIGH finding
(`SCAN-TARGET`, `ARCHIVE-ERROR`, `SCAN-EMPTY`) and exit code 2, never in a
clean report. The same holds for content the scanner could not read in
full: a file over 5 MB (`FS-TRUNCATED`), a binary under a text or code
extension (`FS-UNKNOWN-BIN`), an archive entry that cannot be extracted, a
folder that cannot be listed (`IO-ERROR`). Usage errors and internal errors
exit with 2 as well. Snippets in the report
are quotes from the scanned, untrusted content. When skillbouncer scans
itself it reports its own search patterns and documentation as HIGH; that is
expected.

The baseline script `skillbouncer_baseline.py` has five subcommands:

| Subcommand | Purpose |
|------------|---------|
| `snapshot --auto [--root DIR ...] --out snap.json` | Find the install locations of this session and record a hash per file and unit. Explicit folders can be given instead of `--auto`. Every file counts, `.git` and `__pycache__` included; a skill or plugin installed as a symlink is recorded at its target. Exits 2 when a given folder does not exist, no skill or plugin is found or something cannot be read. |
| `export --snapshot snap.json --out-dir DIR [--only ID ...] [--verdict V]` | Write one baseline document per unit into a folder as JSON. `--only` without an ID is an error. |
| `diff --baseline-dir DIR --snapshot snap.json --out diff.json` | Compare a snapshot with the baseline documents in a folder. Exits 1 when something needs review: new, changed or removed units, a symlink to content the snapshot does not hold, or unchanged units last reviewed under another scanner version. Exits 0 otherwise and 2 on an error. Units marked PENDING are listed without changing the exit code. |
| `names --snapshot snap.json --out names.txt` | Write the names of all installed skills, one per line, for `--known-names`: folder names and the names the SKILL.md files declare. |
| `selfcheck (--expect HASH:PATH[,HASH:PATH ...] \| --expect-file FILE \| --print)` | Hash both scripts and SKILL.md and compare them with the expected hashes. Exits 2 on a mismatch, a missing hash or a hash for any other file. `--print` shows the current hashes. |

## Setting up the monthly scheduled task

Mode B runs as a scheduled task: a fresh Claude session once a month, usually
with nobody watching. The task prompt must contain two things:

1. **Where the baseline store is** (see the next section). Without it Claude
   has to ask and cannot run unattended.
2. **The three selfcheck hashes**: SHA-256 of `skillbouncer_scan.py`,
   `skillbouncer_baseline.py` and `SKILL.md`.

Produce the hashes from the source you reviewed, in the repository root (or
in the unpacked plugin file, which has the same layout):

```bash
sha256sum skills/skillbouncer/scripts/*.py skills/skillbouncer/SKILL.md
```

Where `sha256sum` is missing, `shasum -a 256` prints the same format. A
prompt can look like this:

```text
Run the skillbouncer monthly check (mode B, references/monthly-run.md).

Baseline store: <location of the artifact database or of the private repository>

Selfcheck hashes (SHA-256):
<hash>  skillbouncer_scan.py
<hash>  skillbouncer_baseline.py
<hash>  SKILL.md
```

**Refresh the hashes after every skillbouncer update.** They change with
every version. With stale hashes the next run stops at the selfcheck and
reports a mismatch, which is what it is built to do.

Why the hashes live in the prompt: the installed scripts sit in a folder that
other plugins in the same sandbox can write to. A check that reads its
expected values from that same place proves nothing. The task prompt is
stored outside the sandbox, so a tampered scanner cannot also supply matching
hashes.

Standing caveat: the hooks of all installed plugins have already executed by
the time the monthly session starts. A compromised plugin had its chance
before the check began. The run can show what changed on disk; it cannot show
that the session is untouched. Every result carries that caveat, and a new or
changed hook is always marked PENDING, whatever it looks like.

With an empty baseline, every installed unit counts as new and is reviewed
once.

## Baseline store

Where the baseline lives is the user's choice:

- **Default suggestion:** a Claude artifact database with the collections
  `baseline` (one document per unit) and `runs` (one document per review
  run).
- **Alternative:** a JSON directory in a private repository, one file per
  unit under `baseline/` and one per run under `runs/`.

The scripts never talk to a store. They only read and write JSON
directories: `export` writes one document per unit into a folder and `diff`
reads such a folder. Moving the documents between that folder and the store
is Claude's job during the run.

A baseline document holds hashes, version, source and verdict, not the
reviewed content. A `node_modules/<package>/` directory is stored as one
combined hash to keep documents small, so a changed dependency is reported
as a whole folder.

## Known limitations

- **Semantic manipulation in fluent prose is only caught by reading.** Text
  that steers the assistant without any trigger word passes the scanner.
  That is why the procedure requires reading every file in full.
- **Injection phrasing is covered for a few languages only.** "Ignore your
  instructions" is matched in English, German, French, Spanish and Italian
  (`INJ-OVERRIDE`, `INJ-OVERRIDE-DE`, `-FR`, `-ES`, `-IT`); "hide this from
  the user" in English and German (`DECEPT-HIDE`, `DECEPT-HIDE-DE`). The
  remaining injection rules are English. Other languages are not covered.
- **No execution-based analysis.** Behaviour that only shows at runtime
  (code fetched later, obfuscation that does not resolve statically) is not
  observed. The procedure treats such a package as not reviewable and blocks
  it.
- **Capability detection is regex-based and can be evaded.** The script
  inventory lists what the patterns recognise. Unusual libraries, string
  assembly and indirection can hide a capability or a network target.
- **Package-level combinations are a pointer, not proof.** `COMBO-PKG-*`
  says that one file reads something sensitive and another has network
  access. Whether data flows between them has to be traced by reading.
- **The monthly run sees changes on disk, not what already ran.** It also
  sees only the places where it finds installed skills and plugins. Code a
  plugin downloads at runtime or an MCP server it starts from an unpinned
  package is outside the baseline.

## Development

The scanner stays a single file, standard library only, with syntax that
runs on Python 3.9. Run the checks from the repository root:

```bash
python3 -m py_compile skills/skillbouncer/scripts/*.py
python3 -I tests/run_tests.py

python3 -I tests/make_fixtures.py tests/fixtures-out
python3 -I tests/verify_prefilter.py skills/skillbouncer/scripts/skillbouncer_scan.py tests/fixtures-out
```

`tests/run_tests.py` builds both fixture sets into a temporary folder, runs
the scanner and the baseline script on them and checks the results against
the expected rule IDs per fixture.
The run takes about half a minute; most of that are inputs that used to
stall the scanner.
`tests/verify_prefilter.py` proves that the scanner's fast whole-file
prefilter loses no per-line hit; its last line must end in `lost 0`.
`tests/profile_rules.py <scanner.py> <folder>` shows which rules cost the
most time.

Fixtures are inert text. Nothing in them is executed, hosts use `.invalid`
or `.example`,
and "binaries" are magic bytes followed by zeros. `tests/fixtures-out/` is
generated and ignored by git.

### Adding a rule

1. Add a tuple `(id, severity, description, regex, code_only)` to `RULES` in
   `skills/skillbouncer/scripts/skillbouncer_scan.py`. The ID must be
   unique. Set `code_only` to `True` when the pattern would cause false
   alarms in prose.
2. Add an inert fixture that triggers it to `tests/make_fixtures.py`, or to
   `tests/make_evasion_fixtures.py` when it models an evasion technique.
3. Add the rule ID to the expected IDs of that fixture in
   `tests/run_tests.py`, and check that the benign fixtures (`benign-api`,
   `ev-benign`, `ev-benign-meta`) still have no MEDIUM or HIGH finding.
4. Run the tests and `verify_prefilter.py`.

Leave existing regexes as they are unless you mean to change a rule; they
are tuned against a large corpus of real skills.

Performance matters because one scan covers thousands of files. Two lessons
are built into the scanner:

- No `re.IGNORECASE` on whole files. It makes Python's regex engine about
  four times slower, so the scanner lower-cases each file once and searches
  it with a lower-cased copy of every rule before checking line by line. See
  the comments at `lower_pattern` and `prefilter_rx`.
- Bounded quantifiers only. Write `[^\n]{0,200}`, not `[^\n]*`: an unbounded
  quantifier turns quadratic on minified lines of a megabyte. For the same
  reason HTML comments are found with `str.find` and not with a regex; see
  the comment at `iter_html_comments`.

More lessons of this kind, each of them paid for with a false alarm or a
stalled scan, are collected in `docs/development-notes.md`. The security
review that led to version 1.2.0 is in `docs/security-review-2026-11.md`.

## License

MIT. See `LICENSE`.
