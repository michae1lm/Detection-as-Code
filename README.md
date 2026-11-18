# Detection-as-Code Security Pipeline

[![Detection-as-Code CI](https://github.com/michae1lm/Detection-as-Code/actions/workflows/detection-ci.yml/badge.svg)](https://github.com/michae1lm/Detection-as-Code/actions/workflows/detection-ci.yml)

A **personal cybersecurity learning lab** demonstrating how Sigma detection rules can be version-controlled, validated, and tested automatically with GitHub Actions.

**Current status:** Working **offline proof of concept**, tested locally on Windows (November 18, 2026) and in [GitHub Actions](https://github.com/michae1lm/Detection-as-Code/actions/runs/44422863761). The initial starter was assembled with AI assistance; it is a learning and testing exercise, not evidence of an enterprise deployment or earlier work.

## At a glance

| Component | Verified scope |
| --- | --- |
| Detection rules | 3 experimental Sigma-format Windows rules |
| Example events | 6 synthetic positive and negative cases |
| Unit tests | 5 tests passed locally |
| Continuous integration | GitHub Actions validation and tests **passed** |
| Runtime | Python 3.9+ and PyYAML; no SIEM or cloud account required |

The CI badge links to the repository's workflow. [View a successful run](https://github.com/michae1lm/Detection-as-Code/actions/runs/44422863761).

## What it detects

| Rule | Detection condition | Triage caveat |
| --- | --- | --- |
| **Windows Security Audit Log Cleared** | Security Event ID **1102** | Authorized administrators may clear logs |
| **PowerShell Encoded Command Execution** | `powershell.exe` launched with `-EncodedCommand` or `-enc` | Encoded PowerShell may be legitimate automation |
| **Certutil URLCache Download Command** | `certutil.exe` invoked with `-urlcache` | Certificate workflows and tests may trigger |

All three rules are marked **experimental**. A rule match is a candidate for investigation, **not proof of malicious activity**.

## Try it on Windows

Open PowerShell or Command Prompt in the repository root and install the dependency:

```powershell
py -m pip install -r requirements.txt
py scripts/validate_rules.py
py scripts/check_fixtures.py
py -m unittest discover -s tests -v
```

On Linux or macOS, replace `py` with `python3` (or your available Python command).

Expected final summaries on the supplied files:

```text
3 rules passed structural checks
6 synthetic fixtures passed
Ran 5 tests
OK
```

The tests use **synthetic fixtures** in `fixtures/events.json`; they do not execute the suspicious commands or connect to a real Windows endpoint.

## How the pipeline works

```text
rules/windows/*.yml --------> scripts/validate_rules.py
           |                          |
           v                          v
fixtures/events.json -------> scripts/check_fixtures.py
                                      |
                                      v
                             tests/test_pipeline.py
                                      |
                                      v
                           GitHub Actions workflow
```

1. **Rule validation:** `validate_rules.py` loads YAML and checks required fields, UUID IDs, duplicate IDs, selection structure, and the supported field modifiers.
2. **Fixture matching:** `check_fixtures.py` evaluates each event against the three rule selections and compares the matched rule IDs to expected IDs.
3. **Unit testing:** `tests/test_pipeline.py` checks valid/invalid rules, case-insensitive matching, missing fields, and the six fixtures.
4. **CI:** `.github/workflows/detection-ci.yml` runs the checks on pushes and pull requests.

**Matching model:** Conditions currently require every selected field to match (**AND** across fields). A list of values for one field uses **OR**. The matcher supports equality plus `contains`, `endswith`, and `startswith` modifiers, using case-insensitive text comparison.

For example, the encoded PowerShell rule requires **both** an executable path ending in `\powershell.exe` **and** a command line containing ` -EncodedCommand ` or ` -enc `. Ordinary PowerShell commands lacking the option should not match.

## Repository layout

```text
.github/workflows/detection-ci.yml    CI checks
rules/windows/                        Three experimental Sigma YAML rules
scripts/validate_rules.py             Rule structure validation
scripts/check_fixtures.py             Minimal offline rule evaluator
fixtures/events.json                  Synthetic positive/negative examples
tests/test_pipeline.py                Five Python unit tests
requirements.txt                      Python dependency
```

## Add your own rule

1. Copy an existing file in `rules/windows/` and give the new rule a distinct UUID and descriptive title.
2. Define its `logsource`, `detection.selection`, `condition: selection`, MITRE tags, and possible false positives.
3. Add **one matching event and one non-matching event** to `fixtures/events.json` with the correct `expected_rule_ids`.
4. Update the hard-coded rule/fixture counts in `tests/test_pipeline.py`, then run all three commands above.
5. Commit your changes and confirm GitHub Actions passes. Explain why your chosen rule may have false positives.

## Limitations

- This is **not** a complete Sigma engine and does not support arbitrary Sigma expressions, backend conversion, correlations, regular expressions, or real SIEM field mappings.
- It does **not** ingest live Windows logs, deploy to Splunk/Sentinel, or automatically investigate incidents.
- Sample events are synthetic, so detection accuracy, false-positive rates, and performance on real telemetry have **not** been measured.
- The simple command-line patterns will miss some variations, and some legitimate activity can produce matches.
- The pipeline demonstrates repeatable **testing**, not a production detection deployment.

## References

- [Sigma rules specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma rule fundamentals](https://sigmahq.io/docs/basics/rules.html)
- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)

**Portfolio note:** This lab is an AI-assisted starter that was run and verified as a personal learning exercise. Discuss and extend the implementation before describing its rules or test harness as independently authored.
