import sys
import unittest
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from validate_rules import load_rule, validate_tree, RuleValidationError
from check_fixtures import matches, run_fixtures

class PipelineTests(unittest.TestCase):
    def test_three_rules_valid(self):
        self.assertEqual(validate_tree(ROOT / 'rules'), 3)

    def test_six_synthetic_events(self):
        self.assertEqual(run_fixtures(ROOT / 'rules', ROOT / 'fixtures' / 'events.json'), 6)

    def test_invalid_rule_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'bad.yml'
            p.write_text('title: Incomplete\nid: not-uuid\n')
            with self.assertRaises(RuleValidationError):
                load_rule(p)

    def test_contains_case_insensitive(self):
        rule = {'detection': {'selection': {'CommandLine|contains': ' -urlcache '}}}
        self.assertTrue(matches(rule, {'CommandLine': 'certutil.exe -URLCACHE -split test'}))

    def test_missing_field_not_matched(self):
        rule = {'detection': {'selection': {'EventID': 1102}}}
        self.assertFalse(matches(rule, {}))

if __name__ == '__main__':
    unittest.main()
