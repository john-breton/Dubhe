import lxml
from lxml import etree

from ActivityElement import ActivityElement


class ActivityParser:
    # Constants needed to access target XMI tags.
    PARENT_DESCRIPTOR = "groups"
    CHILD_DESCRIPTOR = "node"
    EDGE_DESCRIPTOR = "edge"

    def __init__(self, path):
        self._path = path
        self._elements = []

    def parse_xmi(self):
        """
        Parse an XMI file and create ActivityElements.

        We can abuse XML inheritance to know the parent of a given
        UML Activity Diagram element, i.e., which actions belong
        to which swimlanes, because those actions will always come
        after the declaration of the swimlane.

        :return: 1 if the file was successfully parsed, 0 otherwise.
        """
        curr_parent = None
        with open(self._path, 'r') as file:
            try:
                tree = etree.parse(file)
            except lxml.etree.XMLSyntaxError:
                # The XMI is malformed
                return 0
            for element in tree.iter():
                if element.tag == ActivityParser.PARENT_DESCRIPTOR:
                    # Working with a swimlane, grab the Object name.
                    curr_parent = element.items()[1][1]
                elif element.tag == ActivityParser.CHILD_DESCRIPTOR:
                    # Working with an element under a swimlane.
                    # Build the ActivityElement and add it to the list.
                    self._elements.append(
                        ActivityElement(element.items(), curr_parent))
                elif element.tag == ActivityParser.EDGE_DESCRIPTOR:
                    # Working with an edge, update the elements
                    # Some edges have names (labels), and they push the
                    # indexing down, so we check for that here.
                    curr_items = element.items()
                    if len(curr_items) == 6:
                        curr_source = curr_items[3][1]
                        curr_dest = curr_items[4][1]
                    else:
                        curr_source = curr_items[2][1]
                        curr_dest = curr_items[3][1]
                    source_ele = None
                    dest_ele = None
                    # Set the source for one ActivityElement while
                    # simultaneously setting the destination for another.
                    for ele in self._elements:
                        if ele.get_id() == curr_source:
                            source_ele = ele
                        elif ele.get_id() == curr_dest:
                            dest_ele = ele
                    if source_ele is not None and dest_ele is not None:
                        source_ele.set_destination(dest_ele.get_id())
                        dest_ele.set_source(source_ele.get_id())
        return 1

    def get_elements(self):
        return self._elements
