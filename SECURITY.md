# Security policy

skillbouncer is a review tool. A way around it matters more than an ordinary
bug, because a clean report is what people act on.

## What to report privately

- A package that the scanner reports as clean, or below HIGH, although it
  carries something an existing rule is meant to find.
- Any input that makes the scanner or the baseline script end with exit code
  0 or 1 without having read everything it was given.
- A way to change the baseline, a verdict or the scripts from inside a
  package under review.
- Input that stalls or crashes either script.

The limits listed under "Known limitations" in the README are not
vulnerabilities: prose without any trigger word, languages the rules do not
cover, behaviour that only shows at runtime. Ideas for narrowing them are
welcome as ordinary issues.

## How to report

Use "Report a vulnerability" under the Security tab of this repository. Do
not open a public issue for a gap that is still open.

A useful report has:

- the version (`python3 -I skills/skillbouncer/scripts/skillbouncer_scan.py --version`),
- the smallest input that shows the problem, as inert text only: hosts end
  in `.invalid` or `.example`, and nothing in it works as malware,
- the command you ran, what came out and what you expected.

## What happens then

A gap is fixed first and described afterwards. The fix comes with a fixture
and a test, and only then do the changelog and `docs/` say what was wrong.

This project is maintained in spare time. Reports are read, but there is no
guaranteed response time.

## Supported versions

Only the latest release gets fixes.
