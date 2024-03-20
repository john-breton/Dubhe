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

    def _analyze_datastore(self):
        """
        This analysis activity is specifically concerned with sanitizing
        data before it enters datastores. It will also attempt to
        protect the most datastores possible with a single data
        sanitizer object.

        ---How does this work?---
        Using the previously created ActivityElements, Dubhe will first
        determine if there are any datastores. If only one exists, the
        optimal location to protect the datastore is to place a data
        sanitizer between said datastore and the previous
        ActivityElement, limiting internal bad actors from being able
        to corrupt a nearby activity that would still result in damage
        to the datastore.

        If more than one datastore exists, Dubhe will determine the
        latest ActivityElement that appears in the most paths that
        contain a datastore. Once identified, the suggestion will be to
        place a data sanitizer between the identified ActivityElement
        and the element immediately before it in order to maximize the
        protection of the most datastores within the system.
        """
        # Determine if any datastores exist in the submitted XMI.
        curr_count = 0
        indexes = []

        for element in self._elements:
            if element.get_uml_type() == CorruptionAnalysis.STORE_NODE_TYPE:
                indexes.append(curr_count)
            curr_count += 1

        if len(indexes) == 1:
            # Easy case, we just place the data sanitizer between the
            # element directly before it.
            curr_store = self._elements[indexes[0]]
            prev_ele_id = curr_store.get_source()[0]
            for prev_ele in self._elements:
                if prev_ele_id == prev_ele.get_id():
                    # We have a match, populate the analysis results.
                    self._protect_stores.append([prev_ele.get_uml_type(),
                                                 prev_ele.get_name(),
                                                 prev_ele.get_parent()])
                    self._protect_stores.append([curr_store.get_uml_type(),
                                                 curr_store.get_name(),
                                                 curr_store.get_parent()])
                    break
        elif len(indexes) > 1:
            # A more complicated case, we need do walk backs on each
            # identified datastore and see where they first overlap.
            total_walk_paths = []
            for curr_index in indexes:
                curr_element = self._elements[curr_index]
                temp_array = []
                while True:
                    if len(curr_element.get_source()) != 0:
                        temp_ele = self._get_element_by_id(
                            curr_element.get_source()[0])
                        temp_array.append(temp_ele.get_id())
                        curr_element = temp_ele
                    else:
                        break
                total_walk_paths.append(temp_array)

            # Figure out which element appears in the most database paths.
            total_counts = Counter()
            for array in total_walk_paths:
                total_counts += Counter(array)
            # Grab the first element with the highest number of occurrences.
            # Due to Python Counter order preservation, this is the optimal
            # ActivityElement that will protect the most datastores.
            best_element = self._get_element_by_id(
                max(total_counts, key=total_counts.get))
            prev_best = self._get_element_by_id(best_element.get_source()[0])
            self._protect_stores.append([prev_best.get_uml_type(),
                                         prev_best.get_name(),
                                         prev_best.get_parent()])
            self._protect_stores.append([best_element.get_uml_type(),
                                         best_element.get_name(),
                                         best_element.get_parent()])

    # There are only two types of analysis, and they depend on the existence
    # of datastores. If none exist, no results are reported.

    def _analyze_entry(self):
        """
        This analysis activity is specifically concerned with cleaning
        data entering into the system from expected entry points.

        ---How does this work?---
        Using the previously created ActivityElements, Dubhe looks for
        an element of type InitialNode. Once that is found, two tuples
        are created, one for the InitialNode element and its parent,
        and one for the element that comes after the InitialNode.
        """
        initial_data = []
        connected_data = []
        next_element = None

        # Check for the initial node ActivityElement.
        for element in self._elements:
            if element.get_uml_type() == CorruptionAnalysis.INITIAL_NODE_TYPE:
                # We found the initial node.
                initial_data = [element.get_uml_type(), element.get_name(),
                                element.get_parent()]
                next_element = element.get_destination()[0]
                break

        # We need to walk through it twice to find the connecting element.
        for element in self._elements:
            if element.get_id() == next_element:
                # We found the connected element.
                connected_data = [element.get_uml_type(), element.get_name(),
                                  element.get_parent()]
        self._protect_entry.append(initial_data)
        self._protect_entry.append(connected_data)

    def _analyze_whole(self):
        """
        This analysis activity is specifically concerned with minimizing
        the length of any corruptible paths within a system.

        ---How does this work?---
        The tool identify the single longest path of ActivityElements
        for a given UML Activity Diagram. Once this is identified, the
        tool will determine the mid-point of the path. Once determined
        a suggestion to place a data sanitizer between the mid-point
        elements will be generated.
        """
        # Determine the longest path in the system
        # Find each element without a source (path start elements)
        source_elements = []
        for element in self._elements:
            if len(element.get_source()) == 0:
                source_elements.append(element)

        # Determine the paths for each element
        all_paths = []
        for curr_source in source_elements:
            all_paths.append([curr_source])
        for curr_depth in all_paths:
            while curr_depth is not None and \
                    len(curr_depth[-1].get_destination()) > 0:
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

        # Determine the longest path
        longest_path = max(all_paths, key=len)

        # Get the middle ActivityElement
        if len(longest_path) % 2 == 0:
            # Even
            mid_element = longest_path[len(longest_path) // 2 - 1]
        else:
            mid_element = longest_path[len(longest_path) // 2]

        # Get the element immediately before the middle element
        prev_element = self._get_element_by_id(mid_element.get_source()[-1])

        # Prepare the analysis result.
        self._protect_whole.append([prev_element.get_uml_type(),
                                    prev_element.get_name(),
                                    prev_element.get_parent()])
        self._protect_whole.append([mid_element.get_uml_type(),
                                    mid_element.get_name(),
                                    mid_element.get_parent()])

    def _display_results(self, no_datastore=True):
        """
        A method used to report the analysis results back to the user.

        Three results are possible, however only two will display if no
        data sanitizers were present in the submitted XMI.
        :param no_datastore: True if there are analysis results to show,
                             False otherwise (such as the case where a
                             system model already includes a data
                             sanitizer).
        """
        if no_datastore:
            print("----Protecting Expected Entry Points----")
            print(f"It is recommended to place a Data Sanitizer object between"
                  f" the following elements:\n\t- {self._protect_entry[0][0]} "
                  f"(parented by {self._protect_entry[0][2]})\n\t- "
                  f"{self._protect_entry[1][0]}: {self._protect_entry[1][1]} "
                  f"(parented by {self._protect_entry[1][2]})")
            print("This recommendation is useful if the threat of insider "
                  "attacks is sufficiently small compared to\nthe threat of "
                  "external attacks. Examples of such external attacks include"
                  " attempting to harm\nyour system by threatening its "
                  "availability, or attempting a forceful takeover using "
                  "arbitrary \ncode execution via corrupted data.")
            if len(self._protect_stores) > 0:
                print("\n----Protecting Data Stores----")
                print(f"It is recommended to place a Data Sanitizer object"
                      f"between the following elements:\n\t- "
                      f"{self._protect_stores[0][0]}: "
                      f"{self._protect_stores[0][1]} (parented by "
                      f"{self._protect_stores[0][2]})\n\t- "
                      f"{self._protect_stores[1][0]}: "
                      f"{self._protect_stores[1][1]}"
                      f" (parented by {self._protect_stores[1][2]})")
                print("This recommendation is beneficial if you want to "
                      "maximize the protection of your data stores\nagainst "
                      "corrupted data that would be damaging if destroyed or "
                      "leaked to an attacker\n(e.g. data injection attacks).")
            print("\n----Minimizing Corruption Propagation----")
            print(f"It is recommended to place a Data Sanitizer object between"
                  f" the following elements:\n\t- {self._protect_whole[0][0]}:"
                  f" {self._protect_whole[0][1]} (parented by "
                  f"{self._protect_whole[0][2]})\n\t- "
                  f"{self._protect_whole[1][0]}:"
                  f" {self._protect_whole[1][1]} (parented by "
                  f"{self._protect_whole[1][2]})")
            print("This recommendation should be applied if you have the goal "
                  "of minimizing the longest path\nof corruption within your "
                  "system, making system wide data corruption attacks more"
                  " difficult.")
        else:
            print("----Detected Data Sanitizer----")
            print("It appears your submitted XMI already contains a reference "
                  "to a 'DataSanitizer'. It may be\nplaced in an optimal "
                  "location according to your specific security goals. If you "
                  "wish to have\nanalysis performed, please remove any "
                  "references to 'DataSanitizer' elements and resubmit\n"
                  "your modified XMI to Dubhe.")

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

    def perform_analysis(self):
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
        # Parse the XMI into usable ActivityElement objects.
        if self._check_for_datastore():
            # The submitted diagram already includes a data sanitizer.
            # Don't try to supersede the judgement of designers.
            self._display_results(False)
        else:
            # Create the analysis threads.
            t1 = threading.Thread(target=self._analyze_datastore)
            t2 = threading.Thread(target=self._analyze_entry)
            t3 = threading.Thread(target=self._analyze_whole)

            # Start the threads.
            t1.start()
            t2.start()
            t3.start()

            # Wait for each analysis activity to finish before moving on.
            t1.join()
            t2.join()
            t3.join()

            # Display the results.
            self._display_results()
