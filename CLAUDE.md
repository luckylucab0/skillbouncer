# skillbouncer

Security review plugin for Claude skills and plugins (static scanner + review
procedure + monthly supply-chain baseline). Stdlib-only Python, run with
`python3 -I`. The scanner must never execute, import or fetch anything it
scans, and must never fail open.

**Current work order: `HANDOFF.md`** (1.1.1 → 1.2.0: rename from skillcheck,
translate to English, close the review findings). Work through its tasks in
order and run the regression gate in its section "Task 8" before every commit.

Conventions:
- Comments explain why, not what.
- No em dashes in prose. Plain, natural wording.
- Keep every existing regex byte-for-byte unless a task says otherwise; run
  `tests/verify_prefilter.py` after any rule change.
- Fixtures are inert text only; hosts use `.invalid`.
- Nothing personal or environment-specific in committed files (no user
  names, hostnames, internal paths, IDs).
