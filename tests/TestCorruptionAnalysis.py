import os
import sys
import unittest

from backend.CorruptionAnalysis import CorruptionAnalysis
from backend.ActivityElement import ActivityElement
from collections import Counter


class TestCorruptionAnalysis(unittest.TestCase):
    TEST_FILE_NAME = "test.xmi"

    def setUp(self):
        # Create a test XMI file.
        xmi_content = """<root>
            <groups id="group1" name="Swimlane1"/>
            <node id="node1" name="Activity1"/>
            <node id="node2" name="Activity2"/>
            <edge id="edge1" source="node1" destination="node2"/>
        </root>"""

        with open(self.TEST_FILE_NAME, 'w') as file:
            file.write(xmi_content)

    def tearDown(self):
        # Delete the test XMI file.
        if os.path.exists(self.TEST_FILE_NAME):
            os.remove(self.TEST_FILE_NAME)

    def test_parse_xmi(self):
        # Test the XMI parsing method
        analysis = CorruptionAnalysis(self.TEST_FILE_NAME)

        result = analysis._parse_xmi()
        self.assertEqual(result, 1,
                         "Parsing should succeed with proper file format.")
        self.assertEqual(len(analysis._elements), 2,
                         "There should be two ActivityElement objects.")

        ele1 = analysis._get_element_by_id("node1")
        ele2 = analysis._get_element_by_id("node2")

        # Validate attributes of parsed elements
        self.assertEqual(ele1.get_name(), "Activity1",
                         "Element name mismatch.")
        self.assertEqual(ele2.get_name(), "Activity2",
                         "Element name mismatch.")

        self.assertEqual(ele1.get_destination(), ["node2"],
                         "Element destination mismatch.")
        self.assertEqual(ele2.get_source(), ["node1"],
                         "Element source mismatch.")

    def test_get_element_by_id(self):
        # Test method that fetches ActivityElement by ID.
        analysis = CorruptionAnalysis(self.TEST_FILE_NAME)
        analysis._parse_xmi()

        ele = analysis._get_element_by_id("node1")
        self.assertIsNotNone(ele, "Should find an element for 'node1'")
        self.assertEqual(ele.get_name(), "Activity1", "Element name mismatch.")

        ele = analysis._get_element_by_id("nonexistent")
        self.assertIsNone(ele, "Should not find any element for 'nonexistent'")

    def test_analyze_datastore_single(self):
        # Setup for a single datastore scenario
        xmi_content = """<root>
            <node id="activity1" name="Activity1" type="Activity"/>
            <node id="datastore1" name="DataStore1" type="DataStoreNode"/>
            <edge id="edge1" source="activity1" destination="datastore1"/>
        </root>"""

        with open(self.TEST_FILE_NAME, 'w') as file:
            file.write(xmi_content)

        analysis = CorruptionAnalysis(self.TEST_FILE_NAME)
        analysis._parse_xmi()

        # Analyze the datastore
        analysis._analyze_datastore()

        # We expect the result to have two elements: the activity and the datastore
        self.assertEqual(len(analysis._protect_stores), 2)
        self.assertEqual(analysis._protect_stores[0][1], "Activity1")
        self.assertEqual(analysis._protect_stores[1][1], "DataStore1")

    def test_analyze_datastore_multiple(self):
        # Setup for multiple datastores scenario
        xmi_content = """<root>
            <node id="activity1" name="Activity1" type="Activity"/>
            <node id="datastore1" name="DataStore1" type="DataStoreNode"/>
            <node id="datastore2" name="DataStore2" type="DataStoreNode"/>
            <edge id="edge1" source="activity1" destination="datastore1"/>
            <edge id="edge2" source="activity1" destination="datastore2"/>
        </root>"""

        with open(self.TEST_FILE_NAME, 'w') as file:
            file.write(xmi_content)

        analysis = CorruptionAnalysis(self.TEST_FILE_NAME)
        analysis._parse_xmi()

        # Analyze the datastore
        analysis._analyze_datastore()

        # We expect the result to have two elements: the activity (as it's common for both datastores)
        self.assertEqual(len(analysis._protect_stores), 2)
        self.assertEqual(analysis._protect_stores[0][1], "Activity1")

    def test_analyze_entry(self):
        # Setup for an entry analysis scenario
        xmi_content = """<root>
            <node id="initial1" name="Initial1" type="InitialNode"/>
            <node id="activity1" name="Activity1" type="Activity"/>
            <edge id="edge1" source="initial1" destination="activity1"/>
        </root>"""

        with open(self.TEST_FILE_NAME, 'w') as file:
            file.write(xmi_content)

        analysis = CorruptionAnalysis(self.TEST_FILE_NAME)
        analysis._parse_xmi()

        # Analyze the entry
        analysis._analyze_entry()

        # We expect two elements: the initial node and its connecting activity
        self.assertEqual(len(analysis._protect_entry), 2)
        self.assertEqual(analysis._protect_entry[0][1], "Initial1")
        self.assertEqual(analysis._protect_entry[1][1], "Activity1")

    def test_analyze_whole(self):
        # Setup for a complex scenario with multiple paths
        xmi_content = """<root>
            <node id="initial1" name="Initial1" type="InitialNode"/>
            <node id="activity1" name="Activity1" type="Activity"/>
            <node id="activity2" name="Activity2" type="Activity"/>
            <node id="activity3" name="Activity3" type="Activity"/>
            <node id="activity4" name="Activity4" type="Activity"/>
            <node id="final1" name="Final1" type="FinalNode"/>
            <edge id="edge1" source="initial1" destination="activity1"/>
            <edge id="edge2" source="activity1" destination="activity2"/>
            <edge id="edge3" source="activity2" destination="activity3"/>
            <edge id="edge4" source="activity3" destination="activity4"/>
            <edge id="edge5" source="activity4" destination="final1"/>
        </root>"""

        with open(self.TEST_FILE_NAME, 'w') as file:
            file.write(xmi_content)

        analysis = CorruptionAnalysis(self.TEST_FILE_NAME)
        analysis._parse_xmi()

        # Analyze the whole diagram
        analysis._analyze_whole()

        # The longest path in the given XMI content is:
        # Initial1 -> Activity1 -> Activity2 -> Activity3 -> Activity4 -> Final1
        # Thus, the middle elements are Activity2 and Activity3

        # We expect two elements: Activity2 and its next element Activity3
        self.assertEqual(len(analysis._protect_whole), 2)
        self.assertEqual(analysis._protect_whole[0][1], "Activity2")
        self.assertEqual(analysis._protect_whole[1][1], "Activity3")


if __name__ == "__main__":
    unittest.main()
