import ast


class ThreatInfo:
    def __init__(self):
        self._technique = None
        self._technique_num = None
        self._mitigation = None
        self._mitigation_num = None
        self._detect_pattern = []
        self._mitigation_pattern = []
        self._mitigation_index = None

    def populate_threat(self, threat_info):
        self._technique = threat_info[0].split(": ")[-1].strip()
        self._technique_num = threat_info[1].split(": ")[-1].strip()
        self._mitigation = threat_info[2].split(": ")[-1].strip()
        self._mitigation_num = threat_info[3].split(": ")[-1].strip()
        self._detect_pattern = self._parse_pattern(threat_info[4].split(": ")[-1])
        self._mitigation_pattern = self._parse_pattern(threat_info[5].split(": ")[-1])
        self._mitigation_index = int(threat_info[6].split(": ")[-1].strip())

    def _parse_pattern(self, pattern_str):
        pattern_list = ast.literal_eval(pattern_str)
        parsed_pattern = []
        for item in pattern_list:
            if isinstance(item, list):
                parsed_pattern.append(tuple(item))
            else:
                parsed_pattern.append(item)
        return parsed_pattern

    def get_technique(self):
        return self._technique

    def get_technique_num(self):
        return self._technique_num

    def get_mitigation(self):
        return self._mitigation

    def get_mitigation_num(self):
        return self._mitigation_num

    def get_detect_pattern(self):
        return self._detect_pattern

    def get_mitigation_pattern(self):
        return self._mitigation_pattern

    def get_mitigation_index(self):
        return self._mitigation_index

    def to_string(self):
        return f"{self._technique} - {self._technique_num}"
