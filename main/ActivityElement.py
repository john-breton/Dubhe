class ActivityElement:
    """
    The ActivityElement class is a data structure that holds information
    related to UML Activity Diagram elements. This includes its type,
    parent (if it exists), its name, its ID, and its edge source
    and edge destination (if they exist).
    """

    # Constants needed to access target XMI tags.
    UML_PREFIX = "uml:"
    XMI_BLANK_SPACE = "%20"
    XMI_NEW_LINE = "%A0"

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
            self._uml_type = None
            self._name = None
            self._id = None
        else:
            # We have data to populate the ActivityElement.
            if items[2][0].find("source") != -1:
                self._uml_type = items[4][1].strip(self.UML_PREFIX)
            else:
                self._uml_type = items[3][1].strip(self.UML_PREFIX)
            self._name = items[1][1].replace("%20", " ")
            self._id = items[0][1]

        # Not every ActivityElement will have a parent (per XMI 2.X).
        if parent is None:
            self._parent = None
        else:
            self._parent = parent

        # ActivityElements do not need to have any constraints, but if
        # we encounter any, we can parse them here.
        self._pre_conditions = []
        self._post_conditions = []

        # Like with constraints, Actions do not need to have a language
        # and body specified, but if they do, parse them here
        self._language = None
        self._body = []

        # ActivityElements can have multiple sources (incoming edges)
        # and destinations (outgoing edges) so these are lists.
        self._source = []
        self._destination = []

    def set_uml_type(self, uml_type):
        """
        Set the UML type for this ActivityElement.

        :param uml_type: The UML type to be set.
        """
        self._uml_type = uml_type

    def get_uml_type(self):
        """
        Get the UML type of this ActivityElement.

        :return: The UML type.
        """
        return self._uml_type

    def set_parent(self, parent):
        """
        Set the parent for this ActivityElement.

        :param parent: The parent to be set.
        """
        self._parent = parent

    def get_parent(self):
        """
        Get the parent of this ActivityElement.

        :return: The parent.
        """
        return self._parent

    def set_source(self, source):
        """
        Add a source to the list of sources for this ActivityElement.

        :param source: The source to be added.
        """
        self._source.append(source)

    def get_source(self):
        """
        Get the list of sources for this ActivityElement.

        :return: The list of sources.
        """
        return self._source

    def set_destination(self, destination):
        """
        Add a destination to the list of destinations for this ActivityElement.

        :param destination: The destination to be added.
        """
        self._destination.append(destination)

    def get_destination(self):
        """
        Get the list of destinations for this ActivityElement.

        :return: The list of destinations.
        """
        return self._destination

    def set_name(self, name):
        """
        Set the name for this ActivityElement.

        :param name: The name to be set.
        """
        self._name = name

    def get_name(self):
        """
        Get the name of this ActivityElement.

        :return: The name.
        """
        return self._name

    def set_id(self, uml_id):
        """
        Set the ID for this ActivityElement.

        :param uml_id: The ID to be set.
        """
        self._id = uml_id

    def get_id(self):
        """
        Get the ID of this ActivityElement.

        :return: The ID.
        """
        return self._id

    def to_json(self):
        """
        Currently unused. Encapsulates the ActivityElement within JSON
        without the source and destination lists.

        :return: A JSON representation of the ActivityElement.
        """
        return '{\n\t"uml_type": "' + self.get_uml_type() \
               + '",\n\t"parent": "' + self.get_parent() \
               + '",\n\t"name": "' + self.get_name() \
               + '",\n\t"id": "' + self.get_id() + '"\n}'

    def to_string(self):
        """
        Currently unused. Forms a String to represent the name,
        source(s), and destination(s) of the ActivityElement.

        :return: A String representation of the ActivityElement.
        """
        return f"Name: {self.get_name()}, Source: {self.get_source()}," \
               f" Destination: {self.get_destination()}"
