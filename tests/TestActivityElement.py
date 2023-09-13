import unittest

from backend.ActivityElement import ActivityElement


class TestActivityElement(unittest.TestCase):

    def setUp(self):
        # This method will run before each test case.
        self.activity_element_default = ActivityElement()
        self.activity_element_data = ActivityElement(
            [('{http://schema.omg.org/spec/XMI/2.1}id', 'test_id'),
             ('name', 'Test%20Me'), ('visibility', 'public'),
             ('{http://schema.omg.org/spec/XMI/2.1}type', 'uml:test')],
            parent="parent_test")

    def test_default_constructor(self):
        # Test the default constructor.
        self.assertEqual(self.activity_element_default.get_uml_type(), "empty")
        self.assertEqual(self.activity_element_default.get_name(), "empty")
        self.assertEqual(self.activity_element_default.get_id(), "empty")
        self.assertEqual(self.activity_element_default.get_parent(), "empty")

    def test_data_constructor(self):
        # The the constructor once parameters are supplied.
        self.assertEqual(self.activity_element_data.get_uml_type(), "test")
        self.assertEqual(self.activity_element_data.get_name(), "Test Me")
        self.assertEqual(self.activity_element_data.get_id(), "test_id")
        self.assertEqual(self.activity_element_data.get_parent(),
                         "parent_test")

    def test_set_get_uml_type(self):
        # Test the UML type setter and getter.
        self.activity_element_default.set_uml_type("test")
        self.assertEqual(self.activity_element_default.get_uml_type(),
                         "test")

    def test_set_get_parent(self):
        # Test the parent setter and getter.
        self.activity_element_default.set_parent("parent_test")
        self.assertEqual(self.activity_element_default.get_parent(),
                         "parent_test")

    def test_set_get_source(self):
        # Test the source setter and getter.
        self.activity_element_default.set_source("source_test")
        self.assertEqual(self.activity_element_default.get_source(),
                         ["source_test"])

    def test_set_get_destination(self):
        # Test the destination setter and getter.
        self.activity_element_default.set_destination("dest_test")
        self.assertEqual(self.activity_element_default.get_destination(),
                         ["dest_test"])

    def test_set_get_name(self):
        # Test the name setter and getter.
        self.activity_element_default.set_name("New Name")
        self.assertEqual(self.activity_element_default.get_name(), "New Name")

    def test_set_get_id(self):
        # Test the ID setter and getter.
        self.activity_element_default.set_id("id_test")
        self.assertEqual(self.activity_element_default.get_id(), "id_test")

    def test_to_json(self):
        # Test the JSON representation creation method.
        expected_json = '{\n\t"uml_type": "test",\n\t"parent": ' \
                        '"parent_test",\n\t"name": "Test Me",' \
                        '\n\t"id": "test_id"\n}'
        self.assertEqual(self.activity_element_data.to_json(), expected_json)

    def test_to_string(self):
        # Test the String representation creation method.
        expected_str = "Name: Test Me, Source: [], Destination: []"
        self.assertEqual(self.activity_element_data.to_string(), expected_str)


if __name__ == '__main__':
    unittest.main()
