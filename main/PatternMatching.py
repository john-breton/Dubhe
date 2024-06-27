import os
import threading
import spacy
from enum import Enum

from ActivityParser import ActivityParser
from ThreatInfo import ThreatInfo


def contains_in_order(arr1, arr2):
    """
    Check to see if one array contains another array in order. That
    is to say, arr2 appears exactly in arr1 with no elements
    in between.

    Example:
        arr1 = [1, 2, 3, 4]
        arr2 = [2, 3]
        The result will be True

        arr1 = [1, 2, 3, 4]
        arr2 = [2, 4, 3]
        The result will be False

    Dubhe uses this to check to see if a mitigation path exists
    within the submitted XMI paths it detected.
    """
    j = 0

    for elem in arr1:
        if elem == arr2[j]:
            j += 1
            if j == len(arr2):
                return True
        else:
            j = 0
    return False


def find_pattern_index(a, b):
    len_b = len(b)
    len_a = len(a)
    for i in range(len_a - len_b + 1):  # only go up to where B can fit in A
        if a[i:i + len_b] == b:
            return i
    return -1  # return -1 if no match is found


class StrideClassification(str, Enum):
    """ The StrideClassification enumeration is used to associate
    string representations for each of the six STRIDE categories.
    """
    SPOOF = "spoofing"
    TAMPER = "tampering"
    REFUTE = "repudiation"
    INFO = "information_disclosure"
    DENY = "denial_of_service"
    ELEVATE = "elevation_of_privilege"


class PatternMatching:
    """
    TEMP
    """

    FILE_TYPE = ".dubhe"
    SIMILARITY_THRESHOLD = 0.7

    def __init__(self, elements):
        """
        Constructor for the PatternMatching class.
        """
        self._pattern_path = os.path.join("..", "common", "STRIDE")
        self._elements = elements
        self._detected_patterns = []
        self._detection_elements = {}
        self._potential_threats = []
        self._mitigated_threats = []
        self._cepi = []
        self._nlp = spacy.load('en_core_web_md')

    def _detect_patterns(self, threat_type):
        """
        Attempts to identify potentially unsafe patterns within UML
        Activity Diagrams using a repository of patterns that correspond
        to a STRIDE classification.

        Note that just because a pattern is identified, it does not mean
        with 100% confidence the threat is unmitigated. Rather, it is
        possible that the threat exists, but there is a chance a unique
        mitigation option is being employed that does not match the
        mitigation recommendations supplied by MITRE ATT&CK. In these
        cases, detection will occur regardless.

        Dubhe uses .xmi representations of attack patterns that
        corresponds to specific techniques from MITRE sources. If a
        threat pattern is identified, a second check initiates to
        determine if a pattern that would mitigate the threat exists.

        :param threat_type: The type of threats that are being
        retrieved, corresponding to STRIDE
        """
        to_check = []
        names = []
        temp_names = []
        ids = []
        shallow_copy = []
        similar = True

        # Get the ThreatInfo objects for the threat type.
        curr_path = os.path.join(self._pattern_path,
                                 threat_type + PatternMatching.FILE_TYPE)
        with open(curr_path, 'r') as f:
            curr_threats = []
            to_build = []
            for line in f:
                if '%' in line:
                    continue
                else:
                    to_build.append(line)
                    if len(to_build) == 7:
                        curr_threat = ThreatInfo()
                        curr_threat.populate_threat(to_build)
                        curr_threats.append(curr_threat)
                        to_build = []

        # Compare each threat to the elements within the submitted XMI
        for threat in curr_threats:
            detected = True
            mitigate_present = False
            mitigation_paths = threat.get_mitigate_pattern()
            mode = threat.get_mode()
            if mode == "BEFORE":
                paths_to_check = self._build_element_path_set_before(
                    threat.get_detect_pattern())
            else:
                paths_to_check = self._build_element_path_set_after(
                    threat.get_detect_pattern())
            paths_to_check_uml = paths_to_check.copy()

            # Build the uml_type representation of the paths
            for path in paths_to_check_uml:
                for i in range(len(path)):
                    temp_names.append(path[i].get_name())
                    ids.append(path[i].get_id())
                    path[i] = path[i].get_uml_type()
                if len(names) == 0 or find_pattern_index(names,
                                                         temp_names) != -1:
                    for ele in temp_names:
                        names.append(ele)
                temp_names = []

            # Add the elements to the data set for metric purposes
            walk_elems = self._elements.copy()
            temp_emp = []
            for walk_curr in walk_elems:
                temp_emp.append(walk_curr.get_uml_type())

            index = find_pattern_index(temp_emp,
                                       threat.get_detect_pattern()[0])
            if index != -1:
                for i in range(index,
                               len(threat.get_detect_pattern()[0]) + index):
                    curr_id = walk_elems[i].get_id()
                    shallow_copy.append(curr_id)
                    if curr_id not in self._detection_elements:
                        self._detection_elements[curr_id] = (
                            len(paths_to_check), 0, 0, 1)
                    else:
                        old_tup = self._detection_elements[curr_id]
                        new_tup = (
                            old_tup[0] + len(paths_to_check), old_tup[1],
                            old_tup[2], old_tup[3] + 1)
                        self._detection_elements[curr_id] = new_tup

            for path in paths_to_check_uml:
                for mitigation_path in mitigation_paths:
                    path_copy = mitigation_path.copy()
                    for i in range(len(path_copy)):
                        if type(path_copy[i]) is tuple:
                            to_check.append(
                                (i, path_copy[i][0], path_copy[i][1]))
                            path_copy[i] = path_copy[i][0]
                    if contains_in_order(path, path_copy):
                        # Identify index where pattern is matched.
                        index = find_pattern_index(path, path_copy)
                        if len(to_check) > 0:
                            for entry in to_check:
                                if path[index + entry[0]] == entry[1]:
                                    # Check to see if the name is similar
                                    if self._semantic_similarity(
                                            names[index + entry[0]], entry[
                                                2]) < self.SIMILARITY_THRESHOLD:
                                        similar = False
                        to_check = []
                        mitigate_present = True
                        break
                if mitigate_present and path == paths_to_check_uml[
                    -1] and similar:
                    detected = False
                    self._mitigated_threats.append((threat_type, threat))
                    for curr in shallow_copy:
                        old_tup = self._detection_elements[curr]
                        new_tup = (
                            old_tup[0], old_tup[1] + 1, old_tup[2], old_tup[3])
                        self._detection_elements[curr] = new_tup
                    break
                elif mitigate_present and path == paths_to_check_uml[
                    -1] and not similar:
                    detected = False
                    similar = True
                    self._potential_threats.append((threat_type, threat))
                    for curr in shallow_copy:
                        old_tup = self._detection_elements[curr]
                        new_tup = (
                            old_tup[0], old_tup[1], old_tup[2] + 1, old_tup[3])
                        self._detection_elements[curr] = new_tup
                    break
                elif mitigate_present:
                    mitigate_present = False
                    continue
                else:
                    break

            if detected:
                self._detected_patterns.append((threat_type, threat))

    def _build_element_path_set_after(self, detect_pattern):
        """
        Builds an element path set, which is a set of paths within a UML
        Activity Diagram but only using the uml types and containing no
        additional info.
        """
        # Check for any occurrences of the detect pattern
        final_paths = []
        temp_paths = []
        for xmi_element in self._elements:
            if xmi_element.get_uml_type() == detect_pattern[0][0]:
                # Special case: The detect_pattern is more than one element
                if len(detect_pattern[0]) != 1:
                    # Check to see if the whole pattern is present.
                    if find_pattern_index(detect_pattern[0],
                                          self._elements) == -1:
                        pass  # TODO: Figure out what is going wrong here. (Empty list)
                # Build the path forwards
                temp_paths = [[xmi_element]]
                for curr_path in temp_paths:
                    for curr_element in curr_path:
                        if curr_path[-1] != curr_element:
                            # Working with one of the alternative paths we
                            # encountered when working forwards.
                            continue
                        if len(curr_element.get_destination()) == 0 or (
                                curr_path.index(
                                    curr_element) != 0 and curr_element.get_uml_type() ==
                                detect_pattern[0][0]):
                            # We reached the end of this path.
                            if (curr_element.get_uml_type() ==
                                    detect_pattern[0][0]):
                                curr_path.pop()
                            break
                        elif curr_path.index(curr_element) == 0 and len(
                                curr_path) > 1:
                            # Working with one of the alternative paths we
                            # encountered when working forwards.
                            continue
                        elif len(curr_element.get_destination()) == 1:
                            # Simple case, only one source into this element.
                            curr_path.append(self._get_element_by_id(
                                curr_element.get_destination()[0]))
                        else:
                            # Special case, multiple destination, create a
                            # copy of the path for each destination.
                            for i in range(1,
                                           len(curr_element.get_destination())):
                                temp_copy = curr_path.copy()
                                temp_copy.append(self._get_element_by_id(
                                    curr_element.get_destination()[i]))
                                temp_paths.append(temp_copy)
                            curr_path.append(self._get_element_by_id(
                                curr_element.get_destination()[0]))
        for path in temp_paths:
            final_paths.append(path)

        # We finished building the paths, now we need to flip everything
        for path in final_paths:
            path.reverse()

        return final_paths

    def _build_element_path_set_before(self, detect_pattern):
        """
        Builds an element path set, which is a set of paths within a UML
        Activity Diagram but only using the uml types and containing no
        additional info.
        """
        # Check for any occurrences of the detect pattern
        final_paths = []
        temp_paths = []
        for xmi_element in self._elements:
            if xmi_element.get_uml_type() == detect_pattern[0][0]:
                # Special case: The detect_pattern is more than one element
                if len(detect_pattern[0]) != 1:
                    # Check to see if the whole pattern is present.
                    if find_pattern_index(detect_pattern[0],
                                          self._elements) == -1:
                        break
                # Build the path backwards
                temp_paths = [[xmi_element]]
                for curr_path in temp_paths:
                    for curr_element in curr_path:
                        if curr_path[-1] != curr_element:
                            # Working with one of the alternative paths we
                            # encountered when working backwards.
                            continue
                        if len(curr_element.get_source()) == 0 or (
                                curr_path.index(
                                    curr_element) != 0 and curr_element.get_uml_type() ==
                                detect_pattern[0][0]):
                            # We reached the end of this path.
                            if (curr_element.get_uml_type() ==
                                    detect_pattern[0][0]):
                                curr_path.pop()
                            break
                        elif curr_path.index(curr_element) == 0 and len(
                                curr_path) > 1:
                            # Working with one of the alternative paths we
                            # encountered  when working backwards.
                            continue
                        elif len(curr_element.get_source()) == 1:
                            # Simple case, only one source into this element.
                            curr_path.append(self._get_element_by_id(
                                curr_element.get_source()[0]))
                        else:
                            # Special case, multiple sources, create a copy of
                            # the path for each source.
                            for i in range(1, len(curr_element.get_source())):
                                temp_copy = curr_path.copy()
                                temp_copy.append(self._get_element_by_id(
                                    curr_element.get_source()[i]))
                                temp_paths.append(temp_copy)
                            curr_path.append(self._get_element_by_id(
                                curr_element.get_source()[0]))
        for path in temp_paths:
            final_paths.append(path)

        # We finished building the paths, now we need to flip everything
        for path in final_paths:
            path.reverse()

        return final_paths

    def _get_element_by_id(self, target_id):
        """
        Get a specific ActivityElement by looking up its unique ID.

        :param target_id: The ID of the ActivityElement that is being
                          queried for.
        :return: The ActivityElement with the specific target ID if it
                 is found, None otherwise.
        """
        for element in self._elements:
            if element.get_id() == target_id:
                return element
        return None

    def _semantic_similarity(self, s1, s2):
        """
        TEMP
        """
        doc1 = self._nlp(s1)
        doc2 = self._nlp(s2)

        # Compute similarity using cosine similarity of vectors
        return doc1.similarity(doc2)

    def _calculate_cepi(self):
        """
        TEMP
        """
        for elem in self._detection_elements:
            full_elem = self._get_element_by_id(elem)
            cepi_vals = self._detection_elements[elem]
            cepi_worst = cepi_vals[0] * (1 - (cepi_vals[1] / cepi_vals[3]))
            cepi_best = cepi_vals[0] * (
                    1 - ((cepi_vals[1] + cepi_vals[2]) / cepi_vals[3]))
            self._cepi.append((full_elem.get_uml_type(), full_elem.get_name(),
                               cepi_worst, cepi_best))

    def _display_results(self, web):
        """
        TEMP

        :param web: Placeholder
        """
        if not web:
            for entry in self._detected_patterns:
                pattern = entry[-1]
                print(
                    f"\nYour design may be susceptible to the following {(entry[0].replace('_', ' ')).title()} threats:\n")
                print(
                    f"Threat Name: {pattern.get_technique().strip()}\nMITRE ATT&CK Reference: {pattern.get_technique_num()}")
                print(
                    f"We recommend you review the mitigations associated with the"
                    f" MITRE ATT&CK listing to harden your system. "
                    f"\n\t(E.g., {pattern.get_mitigation().strip()}, reference number: {pattern.get_mitigation_num().strip()})")

    def perform_pattern_matching(self, web=False):
        """
        TEMP
        """
        # Create the analysis threads for each STRIDE classification.
        t1 = threading.Thread(target=self._detect_patterns,
                              args=(StrideClassification.SPOOF,))
        # t2 = threading.Thread(target=self._detect_patterns,
        #                      args=(StrideClassification.TAMPER,))
        # t3 = threading.Thread(target=self._detect_patterns,
        #                      args=(StrideClassification.REFUTE,))
        t4 = threading.Thread(target=self._detect_patterns,
                              args=(StrideClassification.INFO,))
        t5 = threading.Thread(target=self._detect_patterns,
                              args=(StrideClassification.DENY,))
        # t6 = threading.Thread(target=self._detect_patterns,
        #                      args=(StrideClassification.ELEVATE,))

        # Start the threads.
        t1.start()
        # t2.start()
        # t3.start()
        t4.start()
        t5.start()
        # t6.start()

        # Wait for each analysis activity to finish before moving on.
        t1.join()
        # t2.join()
        # t3.join()
        t4.join()
        t5.join()
        # t6.join()

        # Calculate CEPI
        self._calculate_cepi()

        # Display the results.
        self._display_results(web)

    def get_cepi(self):
        """
        TEMP
        """
        return self._cepi

    def get_mitigated_threats(self):
        """
        TEMP
        """
        return self._mitigated_threats

    def get_potential_threats(self):
        """
        TEMP
        """
        return self._potential_threats

    def get_detected_threats(self):
        """
        TEMP
        """
        return self._detected_patterns


if __name__ == '__main__':
    parser = ActivityParser(os.path.join(os.getcwd(), "..", "common",
                                         "XMI Files",
                                         "Spoofing Example Protected.xmi"))
    result = parser.parse_xmi()
    test = PatternMatching(parser.get_elements())
    test.perform_pattern_matching()
