import unittest
from main.ActivityParser import ActivityParser


class TestActivityParser(unittest.TestCase):

    def setUp(self):
        self.parser = ActivityParser('test.xmi')

    def test_parse_xmi(self):
        result = self.parser.parse_xmi()
        self.assertEqual(result, 0)

    def test_get_elements(self):
        elements = self.parser.get_elements()
        self.assertIsInstance(elements, list)
        self.assertEqual(len(elements), 0)


if __name__ == '__main__':
    unittest.main()
