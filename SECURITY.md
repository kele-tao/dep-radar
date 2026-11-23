# Security policy

## Supported versions

| Version | Supported |
| --- | :---: |
| 1.x | yes |
| < 1.0 | no |

## Reporting a vulnerability

Please **do not** open a public issue for a vulnerability in dep-radar itself.

Use GitHub's private vulnerability reporting on
https://github.com/kele-tao/dep-radar/security/advisories/new, or email the maintainer
listed on the GitHub profile. Include:

- the affected version and platform,
- a minimal manifest or lockfile that reproduces it,
- what an attacker gains (code execution, data exfiltration, denial of service).

You can expect an acknowledgement within 7 days and a fix or a documented decision within
30 days.

## Scope

dep-radar parses untrusted input: lockfiles and manifests from arbitrary repositories.
That makes these classes of bug security-relevant:

- **Resource exhaustion** while parsing a hostile lockfile (deep nesting, pathological
  ranges, huge files). Files above 2 MB are skipped by the source scanner; parsers are
  linear in input size.
- **Terminal escape injection** through package names or licence strings rendered by the
  terminal report. If you find a path where untrusted text reaches an ANSI escape
  sequence, that is a bug worth reporting.
- **HTML injection** in the `--html` report, which is meant to be archived and shared.
  All interpolated values are escaped with `html.escape`; a bypass is a vulnerability.

Out of scope:

- The accuracy or freshness of the committed advisory snapshot
  (`src/dep_radar/data/advisories.json`) - it is a curated snapshot, and gaps are
  documented in `docs/ROADMAP.md`. Report missing entries as a regular issue.
- False positives or negatives in typosquat detection: report them as issues with the
  package names involved.
- Anything requiring dep-radar to execute the code of a scanned project. It never
  imports, installs or runs the packages it audits, and it makes no network calls.
