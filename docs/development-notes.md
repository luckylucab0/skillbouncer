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
  megabyte. Use `[^\n]{0,200}`. The same holds for `\S*`, `\w*` and
  `[^\]]*` after a prefix that can repeat inside the run: `curl ` twenty
  thousand times on one line took 23 seconds, a few hundred KB of `http://`
  more than a minute. Bound every one of them.
- With `re.M` a leading `^\s*` is quadratic on blank lines: the anchor
  matches at every line start and `\s*` runs across all blank lines that
  follow. The prefilter narrows it to blanks within the line.
- Line numbers come from an index built once per file (`LineIndex`).
  `text.count("\n", 0, pos)` per finding is quadratic with many findings.
  `visible_snippet` cuts before it loops, frontmatter lines are collected in
  lists, and the package a file belongs to is found by walking up its
  parents, not by comparing with every root.
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
  (flag from 100 000 and 1 000 000).
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

- The prefilter text must be folded the way `re.IGNORECASE` compares, not
  with `str.lower()` alone: dotless i, dotted capital I and long s match "i"
  and "s" in the exact rule. Line separators are unified to `\n` first, or
  the prefilter and the per-line pass disagree on where a line starts.
- A pattern can be split over two lines (JSON between key and value, a
  Markdown reference definition, wrapped prose). When the prefilter matches
  and no single line does, pairs of adjacent lines are tried. On the corpus
  this added no finding, so it costs nothing in noise.
- Frontmatter is read per field including continuation lines. A value is
  checked per line and capped in total, because an ordinary `metadata` map
  is longer than 200 characters when joined. `compatibility` names products
  ("Claude Code"), so there only text that addresses the model counts.
- Two folders with the same name get their path appended to the label. The
  script inventory and the package grouping are keyed by label; with the
  bare folder name one entry overwrote the other, in an order that differed
  between Python versions.

## Never fail open

- Every per-file exception becomes a `SCAN-ERROR` HIGH finding. A file that
  cannot be read is HIGH too: unread means unreviewed.
- A directory named `SKILL.md` is `FS-FAKE-SKILLMD`.
- A target that yields nothing (missing path, broken archive, empty folder)
  is a HIGH finding, and usage errors exit with 2, the code of a HIGH
  finding. A gate that only looks at the exit code stays closed.
- Nothing is skipped by name or extension. Files under `.git` are scanned.
  A file with a media extension is skipped only when it starts with a media
  signature; otherwise it is read as text (`FS-DISGUISED-TEXT`). An archive
  that does not start with ZIP data is also scanned as a script
  (`ARCHIVE-POLYGLOT`).
- Text is decoded before the rules run: a byte order mark is removed, UTF-16
  is decoded, a few NUL bytes are dropped. A file that is mostly NUL under a
  text or code extension is HIGH, because it was not read.
- A file over the read limit is `FS-TRUNCATED` HIGH. `FS-LARGE` alone did
  not say that content was left out.
- `zipfile` raises more than `BadZipFile` (encrypted entry, unknown
  compression method, corrupt stream, recursion). One bad entry is a finding
  and the others are still extracted. Any other internal error ends in exit
  code 2: a traceback exits with 1, which reads as "at most MEDIUM".
- `Path.rglob` skips a folder it may not list without a word. The tree is
  walked with `os.walk` and an error callback.
- Output is written with `backslashreplace`. A lone surrogate from a JSON
  escape or a file name cannot be encoded and ended the report in a
  traceback.
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
