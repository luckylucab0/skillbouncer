# Development notes

Lessons that cost a false alarm, a missed detection or a stalled scan. Each
one is also a comment at the code it concerns; this list is the overview.
Check a change against it before touching the rules.

## Performance

- `re.IGNORECASE` makes Python's regex engine about four times slower. The
  scanner lower-cases each file once and searches it with a lower-cased copy
  of every rule (the prefilter) before checking line by line.
  `lower_pattern()` must leave escapes such as `\S`, `\W` and `\B`
  untouched, because their upper-case letter has a meaning of its own.
  `tests/verify_prefilter.py` proves the prefilter loses no hit; run it after
  every rule change.
- An unbounded `[^\n]*` inside a rule turns quadratic on minified lines of a
  megabyte. Use `[^\n]{0,200}`.
- `<!--(.*?)-->` is quadratic with many unclosed comments.
  `iter_html_comments` uses `str.find`. Do not reintroduce a regex there.
- Three per-file checks are short-circuited because almost no file needs
  them: the invisible-character loop (one regex search first), the
  mixed-script check (ASCII lines are skipped) and the lookup of the skill a
  file belongs to (string prefixes, not `Path.relative_to`). Together they
  were a quarter of the runtime on a tree of 2 800 files.

## Precision

- Sleep thresholds differ by unit: Python and shell `sleep` count seconds
  (flag from 100), JavaScript `sleep()` and `setTimeout` count milliseconds
  (flag from 1 000 000 and 10 000 000).
- `"Login Data"` is matched case-sensitively with a path separator in front.
  Otherwise prose like "login data is stored" is HIGH.
- `MAL-SKILL-TAMPER` is MEDIUM, not HIGH: legitimate installers touch
  `.claude/skills`. `nohup` and `disown` are LOW (`CODE-BACKGROUND`): local
  preview servers use them.
- Launcher arguments: `uvx --python 3.12 pkg` must not read `3.12` as the
  package; for `-p`, `--package` and `--from` the value is the package.
- Base64 that decodes to a ZIP is MEDIUM, not HIGH: test fixtures embed
  ZIPs. PE, ELF and Mach-O stay HIGH.
- `AUTORUN-GITCONFIG` only runs on git configuration files. `name = !value`
  is ordinary code in most languages. `AUTORUN-SYSTEMD` and
  `AUTORUN-DESKTOP` are case-sensitive for the same reason (`exec = ...`).
- The French, Spanish and Italian override rules require the article after
  the verb. Without it, English "ignore ... instructions" matches twice.
- `FM-DESC-HIJACK` is checked per frontmatter field. On the joined block a
  match can straddle two fields ("instead of a guess" followed by
  `allowed-tools`).
- The frontmatter checks skip `allowed-tools` for the "reads like an
  instruction" test: `Bash(npm run *)` contains "run".

## Never fail open

- Every per-file exception becomes a `SCAN-ERROR` HIGH finding. A file that
  cannot be read is HIGH too: unread means unreviewed.
- A directory named `SKILL.md` is `FS-FAKE-SKILLMD`.
- A target that yields nothing (missing path, broken archive, empty folder)
  is a HIGH finding, and usage errors exit with 2, the code of a HIGH
  finding. A gate that only looks at the exit code stays closed.
- The baseline script exits 2 wherever silence would read as "no changes":
  a missing root, zero units, a missing baseline folder, a selfcheck without
  expectations.

## Environment

- Where installed skills and plugins live differs between Claude products
  and sessions. `AUTO_CANDIDATES` in the baseline script is the list; sync
  folders carry account IDs in their names, so unit labels must not be
  derived from them.
- Run every scanner call with `python3 -I` and from a working directory
  outside the scanned tree.
- A scan of about 2 800 files (40 MB) takes between one and two minutes. Use
  generous timeouts.
