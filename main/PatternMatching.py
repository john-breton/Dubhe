import os
import threading
import spacy
from enum import Enum
from ActivityParser import ActivityParser
from ThreatInfo import ThreatInfo


def contains_in_order_with_wildcards(path, pattern, nlp, check_semantic=True):
    """
    Checks if elements in the path match the pattern with possible wildcards.

    :param path: List of path elements.
    :param pattern: List of pattern elements which may contain wildcards.
    :param nlp: Spacy NLP model for semantic similarity.
    :param check_semantic: Boolean indicating whether to check semantic similarity.
    :return: Boolean indicating if the path matches the pattern.
    """
    path_idx = 0
    pattern_idx = 0

    while path_idx < len(path) and pattern_idx < len(pattern):
        pattern_element = pattern[pattern_idx]
        path_element = path[path_idx]

        if pattern_element == "...":
            # Skip wildcard and try to match subsequent elements
            pattern_idx += 1
            if pattern_idx == len(pattern):
                return True
            next_pattern_elem = pattern[pattern_idx]
            while path_idx < len(path):
                if isinstance(next_pattern_elem, tuple):
                    if path[path_idx][0] == next_pattern_elem[0]:
                        if check_semantic:
                            name_similarity = nlp(path[path_idx][1]).similarity(nlp(next_pattern_elem[1]))
                            if name_similarity >= 0.7:
                                break
                        else:
                            break
                else:
                    if path[path_idx][0] == next_pattern_elem:
                        break
                path_idx += 1
            if path_idx == len(path):
                return False

        elif isinstance(pattern_element, tuple):
            # Check for semantic similarity if tuple
            if path_element[0] == pattern_element[0]:
                if len(pattern_element) > 1 and check_semantic:
                    name_similarity = nlp(path_element[1]).similarity(nlp(pattern_element[1]))
                    if name_similarity < 0.7:
                        path_idx += 1
                        continue
                pattern_idx += 1
                path_idx += 1
            else:
                path_idx += 1

        elif path_element[0] == pattern_element:
            # Direct match of UML type
            pattern_idx += 1
            path_idx += 1
        else:
            path_idx += 1

    return pattern_idx == len(pattern)


class StrideClassification(str, Enum):
    """
    Enum for STRIDE classification types.
    """
    SPOOF = "spoofing"
    TAMPER = "tampering"
    REFUTE = "repudiation"
    INFO = "information_disclosure"
    DENY = "denial_of_service"
    ELEVATE = "elevation_of_privilege"


class PatternMatching:
    """
    The PatternMatching class is responsible for detecting potential security threats
    in a UML Activity Diagram by matching patterns to detect threats and their mitigations.
    """
    FILE_TYPE = ".dubhe"
    SIMILARITY_THRESHOLD = 0.7

    def __init__(self, elements):
        """
        Constructor for the PatternMatching class.

        :param elements: The parsed elements that will be analyzed.
        """
        self._pattern_path = os.path.join("..", "common", "STRIDE")
        self._elements = elements
        self._detected_patterns = []
        self._detection_elements = {}
        self._potential_threats = []
        self._mitigated_threats = []
        self._ceri = []
        self._nlp = spacy.load('en_core_web_md')

    def _detect_patterns(self, threat_type):
        """
        Detect patterns for a specific threat type.

        :param threat_type: The threat type to detect patterns for.
        """
        curr_path = os.path.join(self._pattern_path, threat_type + PatternMatching.FILE_TYPE)

        with open(curr_path, 'r') as f:
            curr_threats = []
            to_build = []
            for line in f:
                if '%' in line:
                    # End of a threat pattern definition
                    if to_build:
                        curr_threat = ThreatInfo()
                        curr_threat.populate_threat(to_build)
                        curr_threats.append(curr_threat)
                        to_build = []
                else:
                    to_build.append(line.strip())
            if to_build:
                curr_threat = ThreatInfo()
                curr_threat.populate_threat(to_build)
                curr_threats.append(curr_threat)

        for threat in curr_threats:
            detect_pattern = threat.get_detect_pattern()[0]
            mitigation_patterns = threat.get_mitigation_pattern()
            mitigation_index = threat.get_mitigation_index()
            detected = False
            path_detected = []

            for element in self._elements:
                paths = self._collect_paths_from_element(element)
                for path in paths:
                    if self._match_path_with_pattern(path, detect_pattern):
                        detected = True
                        path_detected = path
                        self._record_detection(threat, path, detect_pattern)
                        if self._check_mitigation(path, mitigation_patterns, detect_pattern, mitigation_index):
                            self._update_ceri_values(path, mitigated=True, potentially_mitigated=False)
                            self._mitigated_threats.append((threat_type, threat))
                        elif self._check_potential_mitigation(path, mitigation_patterns, detect_pattern, mitigation_index):
                            self._update_ceri_values(path, mitigated=False, potentially_mitigated=True)
                            self._potential_threats.append((threat_type, threat))
                        break
                if detected:
                    break

            if detected and (threat_type, threat) not in self._mitigated_threats and (threat_type, threat) not in self._potential_threats:
                self._detected_patterns.append((threat_type, threat))
            elif not detected:
                pass

    def _collect_paths_from_element(self, element):
        """
        Collect all paths starting from a given element.

        :param element: The starting element.
        :return: A list of paths, each path being a list of elements.
        """
        paths = []
        to_visit = [[element]]
        while to_visit:
            current_path = to_visit.pop()
            last_element = current_path[-1]
            next_elements = last_element.get_destination()
            if not next_elements:
                paths.append(current_path)
            else:
                for dest_id in next_elements:
                    next_element = self._get_element_by_id(dest_id)
                    if next_element:
                        new_path = current_path + [next_element]
                        to_visit.append(new_path)
        return paths

    def _match_path_with_pattern(self, path, pattern):
        """
        Check if a path matches a given pattern.

        :param path: The path to check.
        :param pattern: The pattern to match.
        :return: Boolean indicating if the path matches the pattern.
        """
        path_uml_types = [(element.get_uml_type(), element.get_name()) for element in path]
        result = contains_in_order_with_wildcards(path_uml_types, pattern, self._nlp)
        return result

    def _record_detection(self, threat, path, detect_pattern):
        """
        Record detection of a pattern.

        :param threat: The detected threat.
        :param path: The path where the threat was detected.
        :param detect_pattern: The pattern that was detected.
        """
        pattern_elements = set(detect_pattern)
        for element in path:
            element_uml_type = element.get_uml_type()
            element_name = element.get_name()
            if element_uml_type in pattern_elements or any(
                    isinstance(p, tuple) and p[0] == element_uml_type and self._semantic_similarity(p[1], element_name) >= PatternMatching.SIMILARITY_THRESHOLD
                    for p in detect_pattern if isinstance(p, tuple)):
                element_id = element.get_id()
                cyclomatic_complexity = 1 + (len(element.get_source()) if isinstance(element.get_source(), list) else 0)
                if element_id not in self._detection_elements:
                    self._detection_elements[element_id] = [cyclomatic_complexity, 0, 0, 1]
                else:
                    self._detection_elements[element_id][3] += 1

    def _update_ceri_values(self, path, mitigated, potentially_mitigated):
        """
        Update the CERI values based on detection results.

        :param path: The path where the threat was detected.
        :param mitigated: Boolean indicating if the threat was mitigated.
        :param potentially_mitigated: Boolean indicating if the threat was potentially mitigated.
        """
        for element in path:
            element_id = element.get_id()
            if element_id in self._detection_elements:
                if mitigated:
                    self._detection_elements[element_id][1] += 1
                if potentially_mitigated:
                    self._detection_elements[element_id][2] += 1
                self._detection_elements[element_id][3] += 1

    def _get_element_by_id(self, target_id):
        """
        Get an element by its ID.

        :param target_id: The ID of the element.
        :return: The element with the given ID, or None if not found.
        """
        for element in self._elements:
            if element.get_id() == target_id:
                return element
        return None

    def _semantic_similarity(self, s1, s2):
        """
        Calculate semantic similarity between two strings.

        :param s1: The first string.
        :param s2: The second string.
        :return: The semantic similarity score.
        """
        doc1 = self._nlp(s1)
        doc2 = self._nlp(s2)
        similarity = doc1.similarity(doc2)
        return similarity

    def _check_mitigation(self, path, mitigation_patterns, detect_pattern, mitigation_index):
        """
        Check if the detected threat is mitigated.

        :param path: The path where the threat was detected.
        :param mitigation_patterns: The patterns for mitigations.
        :param detect_pattern: The detection pattern.
        :param mitigation_index: The index for mitigation.
        :return: Boolean indicating if the threat is mitigated.
        """
        if mitigation_index == -1:
            mitigation_position = len(detect_pattern)
        elif mitigation_index == 0:
            mitigation_position = 0
        else:
            mitigation_position = mitigation_index

        for pattern in mitigation_patterns:
            if not self._has_required_paths(path, pattern, detect_pattern, mitigation_position):
                return False
        return True

    def _check_potential_mitigation(self, path, mitigation_patterns, detect_pattern, mitigation_index):
        """
        Check if the detected threat is potentially mitigated.

        :param path: The path where the threat was detected.
        :param mitigation_patterns: The patterns for mitigations.
        :param detect_pattern: The detection pattern.
        :param mitigation_index: The index for mitigation.
        :return: Boolean indicating if the threat is potentially mitigated.
        """
        if mitigation_index == -1:
            mitigation_position = len(detect_pattern)
        elif mitigation_index == 0:
            mitigation_position = 0
        else:
            mitigation_position = mitigation_index

        for pattern in mitigation_patterns:
            if not self._has_potential_paths(path, pattern, detect_pattern, mitigation_position):
                return False
        return True

    def _has_required_paths(self, path, pattern, detect_pattern, mitigation_position):
        """
        Check if the required paths exist for mitigation.

        :param path: The path where the threat was detected.
        :param pattern: The pattern for mitigation.
        :param detect_pattern: The detection pattern.
        :param mitigation_position: The position for mitigation.
        :return: Boolean indicating if the required paths exist.
        """
        if mitigation_position == len(detect_pattern):
            for sub_path in self._collect_paths_from_element(path[-1]):
                if self._match_path_with_pattern(sub_path, pattern):
                    return True
        else:
            element = path[mitigation_position]
            sub_paths = self._collect_paths_from_element(element)
            for sub_path in sub_paths:
                if self._match_path_with_pattern(sub_path, pattern):
                    return True
        return False

    def _has_potential_paths(self, path, pattern, detect_pattern, mitigation_position):
        """
        Check if the potential paths exist for mitigation.

        :param path: The path where the threat was detected.
        :param pattern: The pattern for mitigation.
        :param detect_pattern: The detection pattern.
        :param mitigation_position: The position for mitigation.
        :return: Boolean indicating if the potential paths exist.
        """
        if mitigation_position == len(detect_pattern):
            for sub_path in self._collect_paths_from_element(path[-1]):
                if contains_in_order_with_wildcards([(elem.get_uml_type(), elem.get_name()) for elem in sub_path], pattern, self._nlp, check_semantic=False):
                    return True
        else:
            element = path[mitigation_position]
            sub_paths = self._collect_paths_from_element(element)
            for sub_path in sub_paths:
                if contains_in_order_with_wildcards([(elem.get_uml_type(), elem.get_name()) for elem in sub_path], pattern, self._nlp, check_semantic=False):
                    return True
        return False

    def _calculate_ceri(self):
        """
        Calculate the CERI (Critical Element Risk Index) values for the detected threats.

        The best case CERI will include both mitigated and potentially mitigated threats.
        The worst case CERI will only include mitigated threats.
        """
        for elem in self._detection_elements:
            full_elem = self._get_element_by_id(elem)
            ceri_vals = self._detection_elements[elem]
            if ceri_vals[3] > 0:
                ceri_worst = ceri_vals[0] * (1 - (ceri_vals[1] / ceri_vals[3]))
                ceri_best = ceri_vals[0] * (1 - ((ceri_vals[1] + ceri_vals[2]) / ceri_vals[3]))
                self._ceri.append((full_elem.get_uml_type(), full_elem.get_name(), ceri_worst, ceri_best))

    def _display_results(self, web):
        """
        Display the results of the pattern matching analysis.

        :param web: Boolean indicating if the results are being displayed on the web.
        """
        if not web:
            for entry in self._detected_patterns:
                threat_type, pattern = entry
                print(f"\nYour design may be susceptible to the following {threat_type.replace('_', ' ').title()} threats:\n")
                print(f"Threat Name: {pattern.get_technique().strip()}\nMITRE ATT&CK Reference: {pattern.get_technique_num()}")
                print(
                    f"We recommend you review the mitigations associated with the MITRE ATT&CK listing to harden your system. \n\t(E.g., {pattern.get_mitigation().strip()}, reference number: {pattern.get_mitigation_num().strip()})")

    def perform_pattern_matching(self, web=False):
        """
        Perform pattern matching analysis to detect potential threats.

        :param web: Boolean indicating if the results are being displayed on the web.
        """
        threads = []
        for threat_type in StrideClassification:
            t = threading.Thread(target=self._detect_patterns, args=(threat_type,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self._calculate_ceri()
        self._display_results(web)

    def get_ceri(self):
        """
        Get the calculated CERI values.

        :return: List of CERI values.
        """
        return self._ceri

    def get_mitigated_threats(self):
        """
        Get the list of mitigated threats.

        :return: List of mitigated threats.
        """
        return self._mitigated_threats

    def get_potential_threats(self):
        """
        Get the list of potential threats.

        :return: List of potential threats.
        """
        return self._potential_threats

    def get_detected_threats(self):
        """
        Get the list of detected threats.

        :return: List of detected threats.
        """
        return self._detected_patterns
