import ast


class ThreatInfo:
    """
    The ThreatInfo class represents information related to a specific threat,
    including the technique used, mitigation strategies, detection patterns,
    and mitigation patterns. Each ThreatInfo object is capable of capturing
    a single threat.
    """

    def __init__(self):
        """
        Constructor for the ThreatInfo class.
        """
        self._technique = None
        self._technique_num = None
        self._mitigation = None
        self._mitigation_num = None
        self._detect_pattern = []
        self._mitigation_pattern = []
        self._mitigation_index = None

    def populate_threat(self, threat_info):
        """
        Populate the ThreatInfo object with data.

        :param threat_info: List containing threat information,
                            received from a .dubhe file.
        """
        self._technique = threat_info[0].split(": ")[-1].strip()
        self._technique_num = threat_info[1].split(": ")[-1].strip()
        self._mitigation = threat_info[2].split(": ")[-1].strip()
        self._mitigation_num = threat_info[3].split(": ")[-1].strip()
        self._detect_pattern = self._parse_pattern(threat_info[4].split(": ")[-1])
        self._mitigation_pattern = self._parse_pattern(threat_info[5].split(": ")[-1])
        self._mitigation_index = int(threat_info[6].split(": ")[-1].strip())

    def _parse_pattern(self, pattern_str):
        """
        Parse a pattern string into a list of tuples or elements.

        :param pattern_str: The pattern string to parse.
        :return: A list representing the parsed pattern.
        """
        pattern_list = ast.literal_eval(pattern_str)
        parsed_pattern = []
        for item in pattern_list:
            if isinstance(item, list):
                parsed_pattern.append(tuple(item))
            else:
                parsed_pattern.append(item)
        return parsed_pattern

    def get_technique(self):
        """
        Get the technique name.

        :return: The technique name.
        """
        return self._technique

    def get_technique_num(self):
        """
        Get the technique number.

        :return: The technique number.
        """
        return self._technique_num

    def get_mitigation(self):
        """
        Get the mitigation name.

        :return: The mitigation name.
        """
        return self._mitigation

    def get_mitigation_num(self):
        """
        Get the mitigation number.

        :return: The mitigation number.
        """
        return self._mitigation_num

    def get_detect_pattern(self):
        """
        Get the detection pattern.

        :return: The detection pattern as a list.
        """
        return self._detect_pattern

    def get_mitigation_pattern(self):
        """
        Get the mitigation pattern.

        :return: The mitigation pattern as a list.
        """
        return self._mitigation_pattern

    def get_mitigation_index(self):
        """
        Get the mitigation index.

        :return: The mitigation index.
        """
        return self._mitigation_index

    def to_string(self):
        """
        Return a string representation of the threat info.

        :return: A string representing the threat info.
        """
        return f"{self._technique} - {self._technique_num}"
