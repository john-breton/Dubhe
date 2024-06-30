import os
import threading
import spacy
from enum import Enum
from ActivityParser import ActivityParser
from ThreatInfo import ThreatInfo


def contains_in_order(arr1, arr2):
    i = 0
    j = 0
    while i < len(arr1) and j < len(arr2):
        pattern = arr2[j]
        if isinstance(pattern, tuple):
            pattern = pattern[0]
        if pattern == '...':
            j += 1
            if j == len(arr2):
                return True
            next_pattern = arr2[j]
            if isinstance(next_pattern, tuple):
                next_pattern = next_pattern[0]
            while i < len(arr1) and (arr1[i] != next_pattern and not (next_pattern.endswith('*') and arr1[i].endswith(next_pattern[:-1]))):
                i += 1
            continue  # Skip to the next pattern element
        elif arr1[i] == pattern or (pattern.endswith('*') and arr1[i].endswith(pattern[:-1])):
            i += 1
            j += 1
        else:
            i += 1
    return j == len(arr2)


def find_pattern_index(lst, pattern):
    for i in range(len(lst) - len(pattern) + 1):
        match = True
        k = 0
        for j in range(len(pattern)):
            pat_elem = pattern[j]
            if isinstance(pat_elem, tuple):
                pat_elem = pat_elem[0]
            if pat_elem == '...':
                k = j + 1
                continue
            if lst[i + j - k] != pat_elem and not (pat_elem.endswith('*') and lst[i + j - k].endswith(pat_elem[:-1])):
                match = False
                break
        if match:
            return i
    return -1


class StrideClassification(str, Enum):
    SPOOF = "spoofing"
    TAMPER = "tampering"
    REFUTE = "repudiation"
    INFO = "information_disclosure"
    DENY = "denial_of_service"
    ELEVATE = "elevation_of_privilege"


class PatternMatching:
    FILE_TYPE = ".dubhe"
    SIMILARITY_THRESHOLD = 0.7

    def __init__(self, elements):
        self._pattern_path = os.path.join("..", "common", "STRIDE")
        self._elements = elements
        self._detected_patterns = []
        self._detection_elements = {}
        self._potential_threats = []
        self._mitigated_threats = []
        self._ceri = []
        self._nlp = spacy.load('en_core_web_md')

    def _detect_patterns(self, threat_type):
        print(f"Detecting patterns for {threat_type}")
        to_check = []
        names = []
        temp_names = []
        ids = []
        similar = True

        curr_path = os.path.join(self._pattern_path, threat_type + PatternMatching.FILE_TYPE)
        print(f"Current path for threats: {curr_path}")
        with open(curr_path, 'r') as f:
            curr_threats = []
            to_build = []
            for line in f:
                if '%' in line:
                    if to_build:
                        curr_threat = ThreatInfo()
                        curr_threat.populate_threat(to_build)
                        curr_threats.append(curr_threat)
                        to_build = []
                else:
                    to_build.append(line)
            if to_build:
                curr_threat = ThreatInfo()
                curr_threat.populate_threat(to_build)
                curr_threats.append(curr_threat)

        for threat in curr_threats:
            print(f"Checking threat: {threat.to_string()}")
            detected = False
            mitigate_present = False
            mitigation_paths = threat.get_mitigate_pattern()
            mode = threat.get_mode()
            paths_to_check = self._build_element_paths(threat.get_detect_pattern(), mode)
            paths_to_check_uml = paths_to_check.copy()
            print(f"Paths to check: {paths_to_check}")

            for path in paths_to_check_uml:
                for i in range(len(path)):
                    temp_names.append(path[i].get_name())
                    ids.append(path[i].get_id())
                    path[i] = path[i].get_uml_type()
                if len(names) == 0 or find_pattern_index(names, temp_names) != -1:
                    for ele in temp_names:
                        names.append(ele)
                temp_names = []

            walk_elems = self._elements.copy()
            temp_emp = []
            for walk_curr in walk_elems:
                temp_emp.append(walk_curr.get_uml_type())

            index = find_pattern_index(temp_emp, threat.get_detect_pattern()[0])
            if index != -1:
                detected = True
                print(f"Pattern found in elements at index: {index}")
                for i in range(index, len(threat.get_detect_pattern()[0]) + index):
                    curr_id = walk_elems[i].get_id()
                    print(f"Adding element to detection: {curr_id} with pattern length: {len(paths_to_check)}")
                    if curr_id not in self._detection_elements:
                        self._detection_elements[curr_id] = (len(paths_to_check) + 1, 0, 0, 1)
                    else:
                        old_tup = self._detection_elements[curr_id]
                        new_tup = (old_tup[0] + len(paths_to_check) + 1, old_tup[1], old_tup[2], old_tup[3] + 1)
                        self._detection_elements[curr_id] = new_tup
                    print(f"Detection element state: {self._detection_elements[curr_id]}")

            if detected:
                for path in paths_to_check_uml:
                    for mitigation_path in mitigation_paths:
                        path_copy = list(mitigation_path)
                        print(f"Checking mitigation path: {path_copy}")
                        for i in range(len(path_copy)):
                            if isinstance(path_copy[i], tuple):
                                to_check.append((i, path_copy[i][0], path_copy[i][1]))
                                path_copy[i] = path_copy[i][0]
                        if contains_in_order(path, path_copy):
                            index = find_pattern_index(path, path_copy)
                            print(f"Mitigation path found in elements at index: {index}")
                            if len(to_check) > 0:
                                for entry in to_check:
                                    if path[index + entry[0]] == entry[1]:
                                        similarity = self._semantic_similarity(names[index + entry[0]], entry[2])
                                        print(f"Checking semantic similarity between {names[index + entry[0]]} and {entry[2]}: {similarity}")
                                        if similarity < self.SIMILARITY_THRESHOLD:
                                            similar = False
                            to_check = []
                            mitigate_present = True
                            break
                    if mitigate_present and path == paths_to_check_uml[-1] and similar:
                        detected = False
                        self._mitigated_threats.append((threat_type, threat))
                        print(f"Threat mitigated: {threat.to_string()}")
                        break
                    elif mitigate_present and path == paths_to_check_uml[-1] and not similar:
                        detected = False
                        similar = True
                        self._potential_threats.append((threat_type, threat))
                        print(f"Potential threat detected: {threat.to_string()}")
                        break
                    elif mitigate_present:
                        mitigate_present = False
                        continue
                    else:
                        break

            if detected:
                self._detected_patterns.append((threat_type, threat))
                print(f"Detected threat: {threat.to_string()}")
            else:
                print(f"Threat not detected: {threat.to_string()}")

    def _build_element_paths(self, detect_pattern, mode):
        final_paths = []
        temp_paths = []
        for xmi_element in self._elements:
            if xmi_element.get_uml_type() == detect_pattern[0][0]:
                temp_paths = [[xmi_element]]
                for curr_path in temp_paths:
                    for curr_element in curr_path:
                        if curr_path[-1] != curr_element:
                            continue
                        next_elements = curr_element.get_source() if mode == "BEFORE" else curr_element.get_destination()
                        if len(next_elements) == 0 or (curr_path.index(curr_element) != 0 and curr_element.get_uml_type() == detect_pattern[0][0]):
                            if curr_element.get_uml_type() == detect_pattern[0][0]:
                                curr_path.pop()
                            break
                        elif curr_path.index(curr_element) == 0 and len(curr_path) > 1:
                            continue
                        elif len(next_elements) == 1:
                            curr_path.append(self._get_element_by_id(next_elements[0]))
                        else:
                            for i in range(1, len(next_elements)):
                                temp_copy = curr_path.copy()
                                temp_copy.append(self._get_element_by_id(next_elements[i]))
                                temp_paths.append(temp_copy)
                            curr_path.append(self._get_element_by_id(next_elements[0]))
        for path in temp_paths:
            final_paths.append(path)
        for path in final_paths:
            path.reverse()
        print(f"Built element paths: {final_paths}")
        return final_paths

    def _get_element_by_id(self, target_id):
        for element in self._elements:
            if element.get_id() == target_id:
                return element
        return None

    def _semantic_similarity(self, s1, s2):
        doc1 = self._nlp(s1)
        doc2 = self._nlp(s2)
        return doc1.similarity(doc2)

    def _calculate_ceri(self):
        print("Calculating CERI values")
        for elem in self._detection_elements:
            full_elem = self._get_element_by_id(elem)
            print(f"Calculating CERI for element: {full_elem.get_name()} with values: {self._detection_elements[elem]}")
            ceri_vals = self._detection_elements[elem]
            ceri_worst = ceri_vals[0] * (1 - (ceri_vals[1] / ceri_vals[3]))
            ceri_best = ceri_vals[0] * (1 - ((ceri_vals[1] + ceri_vals[2]) / ceri_vals[3]))
            self._ceri.append((full_elem.get_uml_type(), full_elem.get_name(), ceri_worst, ceri_best))
        print(f"CERI values: {self._ceri}")

    def _display_results(self, web):
        if not web:
            for entry in self._detected_patterns:
                pattern = entry[-1]
                print(f"\nYour design may be susceptible to the following {(entry[0].replace('_', ' ')).title()} threats:\n")
                print(f"Threat Name: {pattern.get_technique().strip()}\nMITRE ATT&CK Reference: {pattern.get_technique_num()}")
                print(f"We recommend you review the mitigations associated with the MITRE ATT&CK listing to harden your system. \n\t(E.g., {pattern.get_mitigation().strip()}, reference number: {pattern.get_mitigation_num().strip()})")

    def perform_pattern_matching(self, web=False):
        threads = []
        for stride_class in StrideClassification:
            t = threading.Thread(target=self._detect_patterns, args=(stride_class,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self._calculate_ceri()
        self._display_results(web)

    def get_ceri(self):
        return self._ceri

    def get_mitigated_threats(self):
        return self._mitigated_threats

    def get_potential_threats(self):
        return self._potential_threats

    def get_detected_threats(self):
        return self._detected_patterns


if __name__ == '__main__':
    parser = ActivityParser(os.path.join(os.getcwd(), "..", "common", "XMI Files", "Spoofing Example Unprotected.xmi"))
    result = parser.parse_xmi()
    test = PatternMatching(parser.get_elements())
    test.perform_pattern_matching()
