"""Structural validation for a documented, intentionally small Sigma rule subset.

This is NOT a complete Sigma parser or substitute for pySigma validation.
"""
from pathlib import Path
import argparse
import sys
import uuid
import yaml

ALLOWED_MODIFIERS = {'contains', 'endswith', 'startswith'}
REQUIRED = {'title', 'id', 'status', 'description', 'logsource', 'detection', 'level'}

class RuleValidationError(ValueError):
    pass

def load_rule(path: Path) -> dict:
    rule = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(rule, dict):
        raise RuleValidationError(f'{path}: root must be a mapping')
    absent = REQUIRED - set(rule)
    if absent:
        raise RuleValidationError(f'{path}: missing fields: {sorted(absent)}')
    try:
        uuid.UUID(str(rule['id']))
    except ValueError as exc:
        raise RuleValidationError(f'{path}: id must be a UUID') from exc
    if not all(isinstance(rule[k], str) and rule[k].strip() for k in ('title', 'description', 'status', 'level')):
        raise RuleValidationError(f'{path}: title, description, status and level require nonempty text')
    if not isinstance(rule['logsource'], dict) or not rule['logsource']:
        raise RuleValidationError(f'{path}: logsource must be a nonempty mapping')
    detection = rule['detection']
    if not isinstance(detection, dict) or detection.get('condition') != 'selection':
        raise RuleValidationError(f'{path}: this test harness supports condition: selection only')
    selection = detection.get('selection')
    if not isinstance(selection, dict) or not selection:
        raise RuleValidationError(f'{path}: selection must contain fields')
    for name, expected in selection.items():
        parts = name.split('|')
        if len(parts) > 2 or (len(parts) == 2 and parts[1] not in ALLOWED_MODIFIERS):
            raise RuleValidationError(f'{path}: unsupported modifier: {name}')
        values = expected if isinstance(expected, list) else [expected]
        if not values or any(not isinstance(x, (str, int)) for x in values):
            raise RuleValidationError(f'{path}: expected scalar/list values for {name}')
    return rule

def validate_tree(directory: Path) -> int:
    files = sorted(directory.rglob('*.yml'))
    if not files:
        raise RuleValidationError(f'No .yml rules found under {directory}')
    ids = set()
    for file in files:
        rule = load_rule(file)
        if rule['id'] in ids:
            raise RuleValidationError(f'Duplicate ID: {rule["id"]}')
        ids.add(rule['id'])
        print(f'PASS {file}: {rule["title"]}')
    print(f'{len(files)} rules passed structural checks')
    return len(files)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('rules_dir', nargs='?', type=Path, default=Path('rules'))
    args = parser.parse_args()
    try:
        validate_tree(args.rules_dir)
    except (RuleValidationError, OSError, yaml.YAMLError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise SystemExit(1)
