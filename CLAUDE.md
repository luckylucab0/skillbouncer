# skillbouncer

Security review plugin for Claude skills and plugins (static scanner + review
procedure + monthly supply-chain baseline). Stdlib-only Python, run with
`python3 -I`. The scanner must never execute, import or fetch anything it
scans, and must never fail open.

Before every commit:

```
python3 -m py_compile skills/skillbouncer/scripts/*.py
python3 -I tests/run_tests.py
python3 -I tests/make_fixtures.py tests/fixtures-out
python3 -I tests/verify_prefilter.py skills/skillbouncer/scripts/skillbouncer_scan.py tests/fixtures-out   # "lost 0"
```

Read `docs/development-notes.md` before changing a rule; every entry there
was a real false alarm, miss or stall.

Conventions:
- Comments explain why, not what.
- No em dashes in prose. Plain, natural wording.
- Keep every existing regex byte-for-byte unless the change is about that
  rule; run `tests/verify_prefilter.py` after any rule change.
- A new rule needs a fixture and an expected ID in `tests/run_tests.py`.
- Fixtures are inert text only; hosts use `.invalid` or `.example`.
- Single-file scanner, Python 3.9 syntax (no `match`, no `X | Y` unions).
- Everything is English except `README.de.md`, the German copy of the
  README. Change both together.
- Nothing personal or environment-specific in committed files (no user
  names, hostnames, internal paths, IDs).
- The scanner's `VERSION` and `version` in `.claude-plugin/plugin.json`
  change together; a new version means new selfcheck hashes for users.
