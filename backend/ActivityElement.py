class ActivityElement:
    """
    The ActivityElement class is a data structure that holds information
    related to UML Activity Diagram elements. This includes its type,
    parent (if it exists), its name, its ID, and its edge source
    and edge destination (if they exist).
    """

    def __init__(self, items=None, parent=None):
        """
        Constructor for the ActivityElement class.

        :param items: These are the XML attributes used to
                      construct the ActivityElement.
        :param parent: This is the ID of the parent group for a given
                       ActivityElement. In this case, parent refers to
                       the swimlane to which this ActivityElement
                       belongs to.
        """
        if items is None:
            # Default case constructor.
            self._uml_type = "empty"
            self._name = "empty"
            self._id = "empty"
        else:
            # We have data to populate the ActivityElement.
            if items[2][0].find("source") != -1:
                self._uml_type = items[4][1].strip("uml:")
            else:
                self._uml_type = items[3][1].strip("uml:")
            self._name = items[1][1].replace("%20", " ")
            self._id = items[0][1]

        # Not every ActivityElement will have a parent (per XMI 2.X).
        if parent is None:
            self._parent = "empty"
        else:
            self._parent = parent

        # ActivityElements can have multiple sources (incoming edges)
        # and destinations (outgoing edges) so these are lists.
        self._source = []
        self._destination = []

    def set_uml_type(self, uml_type):
        self._uml_type = uml_type

    def get_uml_type(self):
        return self._uml_type

    def set_parent(self, parent):
        self._parent = parent

    def get_parent(self):
        return self._parent

    def set_source(self, source):
        self._source.append(source)

    def get_source(self):
        return self._source

    def set_destination(self, destination):
        self._destination.append(destination)

    def get_destination(self):
        return self._destination

    def set_name(self, name):
        self._name = name

    def get_name(self):
        return self._name

    def set_id(self, uml_id):
        self._id = uml_id

    def get_id(self):
        return self._id

    def to_json(self):
        """
        Currently unused. Encapsulates the ActivityElement within JSON
        without the source and destination lists.

        :return: A JSON representation of the ActivityElement
        """
        return '{\n\t"uml_type": "' + self.get_uml_type() \
               + '",\n\t"parent": "' + self.get_parent() \
               + '",\n\t"name": "' + self.get_name() \
               + '",\n\t"id": "' + self.get_id() + '"\n}'

    def to_string(self):
        """
        Currently unused. Forms a String to represent the name,
        source(s), and destination(s) of the ActivityElement.

        :return: A String representation of the ActivityElement
        """
        return f"Name: {self.get_name()}, Source: {self.get_source()}," \
               f" Destination: {self.get_destination()}"
