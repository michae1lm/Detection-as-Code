# Detection-as-Code Security Pipeline — Personal Portfolio Starter

**Status: new, locally testable starter implementation (2026-11-18).** This scaffold was created with AI assistance to help establish verifiable portfolio evidence. It is **not proof** of an earlier implementation or a deployed enterprise detection stack. The repository should only be presented as independently maintained once you have run, understood, and improved it.

## What it demonstrates

- Three original example **Sigma YAML detection rules**: Windows Security log clearing (Event ID 1102), suspicious PowerShell encoded-command arguments, and certutil URLCache usage.
- Rules in version control with IDs, log sources, levels, references to false positives, and MITRE technique tags.
- A lightweight Python structural validator that blocks missing required keys, duplicate rule IDs, and unsupported expressions.
- Six **synthetic test events** with expected positive and negative matches, plus unit tests.
- A GitHub Actions workflow to execute the checks on each push or pull request.

## Quick start

Requirements: Python 3.9+ and PyYAML.

```bash
python -m pip install -r requirements.txt
python scripts/validate_rules.py
python scripts/check_fixtures.py
python -m unittest discover -s tests -v
```

## Architecture

```text
Sigma YAML rules --> structural validation --> local fixture match checks
          |                                        |
          +-------------- GitHub Actions CI ------+
```

## Scope and limitations

This is a **minimal offline test harness**, not a full Sigma engine. It currently supports one `selection`, `condition: selection`, simple `AND` field matching, scalar/list `OR` values, and selected `contains` / `endswith` / `startswith` modifiers. It does not evaluate arbitrary Sigma boolean conditions, backend conversion, regex, correlations, or full field mappings.

The events in `fixtures/` are entirely synthetic. A passing test does not prove accurate detection on real telemetry, and not every possible command-line representation is covered. No SIEM integration or production detection rates are claimed. For standards-compliant parsing and conversion, consider [pySigma / sigma-cli](https://github.com/SigmaHQ/sigma-cli) and its backend plugins as a later extension.

## Suggested next personal contribution

Run the pipeline locally, add a fourth rule of your own, generate at least one negative test case, and explain a false-positive scenario. Then publish a screenshot of a successful CI run and document your results in the README.

## Reference

- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma rules fundamentals](https://sigmahq.io/docs/basics/rules.html)
- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)
