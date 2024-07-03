import unittest
from main.PatternMatching import PatternMatching


class TestPatternMatching(unittest.TestCase):

    def setUp(self):
        # Mock elements for pattern matching
        self.pattern_matching = PatternMatching([])

    def test_perform_pattern_matching(self):
        self.pattern_matching.perform_pattern_matching(web=False)
        # Test results after running pattern matching
        self.assertEqual(len(self.pattern_matching.get_detected_threats()), 0)

    def test_get_ceri(self):
        self.assertEqual(self.pattern_matching.get_ceri(), [])


if __name__ == '__main__':
    unittest.main()
