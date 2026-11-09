# skillbouncer

Security review for Claude skills and plugins before they get installed, and a
monthly re-check of installed ones for supply-chain changes.

**Status: work in progress.** The code here is the 1.1.1 state of the tool
(still named `skillcheck` internally, documentation in German). The migration
to `skillbouncer` 1.2.0 with English documentation and the fixes from the
November 2026 security review is described in `HANDOFF.md`. A proper README
replaces this one with 1.2.0.

Scanner: `skills/skillcheck/scripts/skillcheck_scan.py` (static, stdlib-only,
`python3 -I`). Baseline: `skills/skillcheck/scripts/skillcheck_baseline.py`.
Tests: `tests/`.

License: MIT.
