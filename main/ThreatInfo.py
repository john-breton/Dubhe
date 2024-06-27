"""

"""
import ast


class ThreatInfo:
    def __init__(self):
        """

        """
        self._technique = None
        self._technique_num = None
        self._mitigation = None
        self._mitigation_num = None
        self._detect_pattern = []
        self._mitigation_pattern = []
        self._mode = None

    def populate_threat(self, threat_info):
        """

        """
        self._technique = threat_info[0].split(": ")[-1]
        self._technique_num = threat_info[1].split(": ")[-1]
        self._mitigation = threat_info[2].split(": ")[-1]
        self._mitigation_num = threat_info[3].split(": ")[-1]
        self._detect_pattern = ast.literal_eval(threat_info[4].split(": ")[-1])
        self._mitigation_pattern = ast.literal_eval(
            threat_info[5].split(": ")[-1])
        self._mode = ast.literal_eval(
            threat_info[6].split(": ")[-1])

    def get_technique(self):
        """

        """
        return self._technique

    def get_technique_num(self):
        """

        """
        return self._technique_num

    def get_mitigation(self):
        """

        """
        return self._mitigation

    def get_mitigation_num(self):
        """

        """
        return self._mitigation_num

    def get_detect_pattern(self):
        """

        """
        return self._detect_pattern

    def get_mitigate_pattern(self):
        """

        """
        return self._mitigation_pattern

    def get_mode(self):
        """

        """
        return self._mode

    def to_string(self):
        """

        """
        return f"{self._technique} - {self._technique_num}"
