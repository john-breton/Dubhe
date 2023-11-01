"""
Dubhe is a work-in-progress tool that is geared towards design-time
security hardening activities. In its current iteration, Dubhe is
able to:
    - Analyze UML Activity Diagrams and provide recommendations for
      the locations of data sanitization object.

In the future, Dubhe will support additional functions that will
culminate in the output of a 'behavioural security posture' of
in-development software systems using artifacts generated to
represent the behavioural view of a system-to-be.

Main contact: john.breton@carleton.ca
"""
import os
import sys

from PySide2.QtWidgets import QApplication

from CorruptionAnalysis import CorruptionAnalysis

# You can update the path to a different XMI File here, otherwise
# you can leave this as for the OSM case study.
from frontend.Window import Window

XMI_FILE_PATH = os.path.join(os.getcwd(), "..", "common", "XMI Files",
                             "DualDatabase.xmi")

# Entry point for the application.
if __name__ == "__main__":
    app = QApplication(sys.argv)

    dubhe = CorruptionAnalysis(XMI_FILE_PATH)
    dubhe.perform_analysis()

    window = Window(dubhe)
    window.show()

    sys.exit(app.exec_())
