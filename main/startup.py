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
from flask import Flask, render_template

from CorruptionAnalysis import CorruptionAnalysis
from ActivityParser import ActivityParser
from PatternMatching import PatternMatching

# You can update the path to a different XMI File here, otherwise
# you can leave this as for the OSM case study.
XMI_FILE_PATH = os.path.join(os.getcwd(), "..", "common", "XMI Files",
                             "Information Leakage Example Unprotected.xmi")

app = Flask(__name__)


# Defining the home page of our site
@app.route("/")  # this sets the route to this page
def home():
    return render_template("index.html")


# Entry point for the application.
if __name__ == "__main__":
    # Parse the XMI and create ActivityElements
    parser = ActivityParser(XMI_FILE_PATH)
    result = parser.parse_xmi()
    if parser == 0:
        print(
            "[ERROR]: It appears the supplied .xmi file is malformed. "
            "Dubhe currently support XMI versions 2.X+. "
            "Please double-check your .xmi file before trying to rerun Dubhe.")
        exit()

    # Check for patterns within the parsed ActivityElements
    detector = PatternMatching(parser.get_elements())

    # Perform Analysis Specific to Data Corruption Attacks
    corruption = CorruptionAnalysis(parser.get_elements())
    corruption.perform_analysis()
    app.run()
