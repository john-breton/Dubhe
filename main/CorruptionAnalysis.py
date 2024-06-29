import os
import threading
from collections import Counter

class CorruptionAnalysis:
    """
    The CorruptionAnalysis class is responsible for performing three
    types of analysis on supplied XMI files that represent systems.

    All three types of analysis occur concurrently and results will
    only be displayed once all three have been completed.
    """

    # Constants for specific XMI types.
    INITIAL_NODE_TYPE = "InitialNode"
    STORE_NODE_TYPE = "DataStoreNode"
    FINAL_NODE_TYPE = "ActivityFinalNode"

    # Constants to check for Data Sanitizer elements.
    DATA_SANITIZER = "DataSanitizer"

    def __init__(self, elements):
        """
        Constructor for the CorruptionAnalysis class.

        :param elements: The parsed elements that will be analyzed.
        """
        self._elements = elements
        self._protect_stores = []
        self._protect_entry = []
        self._protect_whole = []
        self._longest_path = []
        self._all_paths = []

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

    def _gather_paths(self):
        """
        Gather all paths through the system, starting from initial nodes and ending at final nodes or datastores.
        """
        # Find each element without a source (path start elements)
        source_elements = [element for element in self._elements if
                           len(element.get_source()) == 0]

        # Determine the paths for each element
        all_paths = []
        for curr_source in source_elements:
            all_paths.append([curr_source])
        for curr_depth in all_paths:
            while curr_depth and len(curr_depth[-1].get_destination()) > 0:
                if len(curr_depth[-1].get_destination()) > 1:
                    # There are multiple edges exiting the element.
                    # Account for each of them, essentially creating a
                    # new path that will need to be checked for each.
                    new_paths = []
                    for i in range(len(curr_depth[-1].get_destination()) - 1):
                        # Create a copy of the curr_depth array
                        copy_array = curr_depth.copy()
                        # Append the element from the destinations to this copy
                        copy_array.append(self._get_element_by_id(
                            curr_depth[-1].get_destination()[i]))
                        # Store this modified copy in the new_paths
                        new_paths.append(copy_array)

                    # Add the results to all_paths
                    for path in new_paths:
                        all_paths.append(path)

                    # Finally, update the original curr_depth
                    next_element = self._get_element_by_id(
                        curr_depth[-1].get_destination()[-1])
                    curr_depth.append(next_element)
                else:
                    # There is only one edge exiting the element, simply
                    # append it to the end of the path and continue.
                    next_element = self._get_element_by_id(
                        curr_depth[-1].get_destination()[0])
                    curr_depth.append(next_element)

        self._all_paths = all_paths
        self._longest_path = max(all_paths, key=len) if all_paths else []

    def _calculate_cpp(self):
        """
        Calculate the Corruption Propagation Potential (CPP) metric for each path.
        """
        cpp_values = []
        for path in self._all_paths:
            has_sanitizer = any(
                element.get_uml_type() == CorruptionAnalysis.DATA_SANITIZER for
                element in path)
            path_length = len(path)
            cpp_value = path_length if not has_sanitizer else 0  # Adjust the calculation as needed
            cpp_values.append((path, cpp_value))
        return cpp_values

    def perform_analysis(self, web=False):
        """
        Performs three types of analysis on .XMI files. The three
        analysis types aim to either protect datastore, expected entry
        points into the system, or the system as a whole by minimizing
        corruption propagation. Each analysis will run concurrently.

        Once each analysis activity has concluded, the results will be
        displayed to the console so that designers may use them to
        assist in hardening systems against data corruption attacks.

        Analysis will fail if the supplied XMI is malformed. In this
        instance, Dubhe will not provide any analysis results and will
        instead inform users that they need to check their XMI file to
        ensure it is not malformed and that it is also compliant with
        the XMI 2.X standard.
        """
        if self._check_for_datastore():
            # The submitted diagram already includes a data sanitizer.
            # Don't try to supersede the judgement of designers.
            self._display_results(False)
        else:
            # Create the analysis threads.
            t1 = threading.Thread(target=self._analyze_datastore)
            t2 = threading.Thread(target=self._analyze_entry)
            t3 = threading.Thread(target=self._analyze_whole)
            t4 = threading.Thread(target=self._gather_paths)

            # Start the threads.
            t1.start()
            t2.start()
            t3.start()
            t4.start()

            # Wait for each analysis activity to finish before moving on.
            t1.join()
            t2.join()
            t3.join()
            t4.join()

            cpp_values = self._calculate_cpp()
            print(f"CPP Values: {cpp_values}")

            # Display the results.
            self._display_results(web)

    def _check_for_datastore(self):
        """
        Check the list of analyzed elements for an ActivityElement
        with the parent "DataSanitizer".

        :return: True if an element with the parent DataSanitizer
                 is found, False otherwise.
        """
        for element in self._elements:
            if element.get_parent() == CorruptionAnalysis.DATA_SANITIZER:
                return True
        return False

    def _analyze_datastore(self):
        """
        Analyzes paths from the data stores identified in the system.
        """
        for element in self._elements:
            if element.get_uml_type() == CorruptionAnalysis.STORE_NODE_TYPE:
                entry_points = 0
                sanitizer_points = 0
                check_list = [element]
                visited = []
                while len(check_list) > 0:
                    current = check_list.pop(0)
                    visited.append(current)
                    sources = current.get_source()
                    for source in sources:
                        entry = self._get_element_by_id(source)
                        if entry and entry not in visited:
                            check_list.append(entry)
                            if entry.get_parent() == CorruptionAnalysis.DATA_SANITIZER:
                                sanitizer_points += 1
                            entry_points += 1
                self._protect_stores.append(entry_points - sanitizer_points)

    def _analyze_entry(self):
        """
        Analyzes paths from the identified entry points of the system.
        """
        for element in self._elements:
            if element.get_uml_type() == CorruptionAnalysis.INITIAL_NODE_TYPE:
                entry_points = 0
                sanitizer_points = 0
                check_list = [element]
                visited = []
                while len(check_list) > 0:
                    current = check_list.pop(0)
                    visited.append(current)
                    destinations = current.get_destination()
                    for destination in destinations:
                        entry = self._get_element_by_id(destination)
                        if entry and entry not in visited:
                            check_list.append(entry)
                            if entry.get_parent() == CorruptionAnalysis.DATA_SANITIZER:
                                sanitizer_points += 1
                            entry_points += 1
                self._protect_entry.append(entry_points - sanitizer_points)

    def _analyze_whole(self):
        """
        Analyzes the entire system for propagation potential.
        """
        entry_points = 0
        sanitizer_points = 0
        check_list = [element for element in self._elements if
                      element.get_uml_type() == CorruptionAnalysis.INITIAL_NODE_TYPE]
        visited = []
        while len(check_list) > 0:
            current = check_list.pop(0)
            visited.append(current)
            destinations = current.get_destination()
            for destination in destinations:
                entry = self._get_element_by_id(destination)
                if entry and entry not in visited:
                    check_list.append(entry)
                    if entry.get_parent() == CorruptionAnalysis.DATA_SANITIZER:
                        sanitizer_points += 1
                    entry_points += 1
        self._protect_whole.append(entry_points - sanitizer_points)

    def _display_results(self, web):
        """
        Display the results of the analysis to the console.

        :param web: A boolean indicating if the results should be displayed on the web.
        """
        if web:
            # Implement web-based result display if necessary.
            pass
        else:
            print("Analysis Results:")
            print(f"Datastore Protection: {self._protect_stores}")
            print(f"Entry Point Protection: {self._protect_entry}")
            print(f"Whole System Protection: {self._protect_whole}")
            print(f"Longest Path Length: {self._longest_path}")

    def get_longest_path(self):
        return self._longest_path

    def get_all_paths(self):
        return self._all_paths

    def get_protect_entry(self):
        return self._protect_entry

    def get_protect_stores(self):
        return self._protect_stores

    def get_protect_whole(self):
        return self._protect_whole


# Entry point for testing the CorruptionAnalysis class.
if __name__ == "__main__":
    from ActivityParser import ActivityParser

    XMI_FILE_PATH = os.path.join(os.getcwd(), "..", "common", "XMI Files",
                                 "Information Leakage Example Unprotected.xmi")

    parser = ActivityParser(XMI_FILE_PATH)
    result = parser.parse_xmi()

    if result == 0:
        print(
            "[ERROR]: It appears the supplied .xmi file is malformed. "
            "Dubhe currently support XMI versions 2.X+. "
            "Please double-check your .xmi file before trying to rerun Dubhe.")
        exit()

    corruption_analysis = CorruptionAnalysis(parser.get_elements())
    corruption_analysis.perform_analysis()
