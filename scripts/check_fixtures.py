"""Minimal offline fixture evaluator supporting only simple Sigma selection logic.

It does not implement full Sigma specifications, correlation rules, field mappings,
processing pipelines, or SIEM translation.
"""
import json
import sys
from pathlib import Path
from validate_rules import load_rule

def _matches_one(actual, expected, modifier):
    if actual is None:
        return False
    if modifier is None:
        if isinstance(actual, int) and isinstance(expected, int):
            return actual == expected
        return str(actual).casefold() == str(expected).casefold()
    value, query = str(actual).casefold(), str(expected).casefold()
    if modifier == 'contains':
        return query in value
    if modifier == 'endswith':
        return value.endswith(query)
    if modifier == 'startswith':
        return value.startswith(query)
    raise ValueError(f'Unknown modifier: {modifier}')

def matches(rule, event):
    for key, expected in rule['detection']['selection'].items():
        field, *mods = key.split('|')
        modifier = mods[0] if mods else None
        values = expected if isinstance(expected, list) else [expected]
        if not any(_matches_one(event.get(field), x, modifier) for x in values):
            return False
    return True

def run_fixtures(rules_dir=Path('rules'), fixture_path=Path('fixtures/events.json')):
    rules = [load_rule(p) for p in sorted(rules_dir.rglob('*.yml'))]
    fixtures = json.loads(fixture_path.read_text(encoding='utf-8'))
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError('fixtures must be a nonempty JSON array')
    count = 0
    for case in fixtures:
        actual = {rule['id'] for rule in rules if matches(rule, case['event'])}
        expected = set(case['expected_rule_ids'])
        if actual != expected:
            raise AssertionError(f'{case["name"]}: expected {expected}, got {actual}')
        count += 1
        print(f'PASS {case["name"]} expected={len(expected)} detected={len(actual)}')
    print(f'{count} synthetic fixtures passed')
    return count

if __name__ == '__main__':
    sys.exit(0 if run_fixtures() else 1)
