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
import numpy as np
from flask import Flask, render_template, request, jsonify
import plotly.graph_objects as go

from CorruptionAnalysis import CorruptionAnalysis
from ActivityParser import ActivityParser
from PatternMatching import PatternMatching

# You can update the path to a different XMI File here, otherwise
# you can leave this as for the OSM case study.
XMI_FILE_PATH = os.path.join(os.getcwd(), "..", "common", "XMI Files",
                             "Spoofing Example Unprotected.xmi")

# Flask related variables, if you want to run the program in the command-line,
# these variables are not needed.
XMI_PATH_WEB = os.path.join(os.getcwd(), "..", "common", "XMI Files",
                            "Analysis.xmi")
app = Flask(__name__)
web_detector = None
web_corruption = None


# Defining the home page of our site
@app.route("/")  # this sets the route to this page
def home():
    return render_template("index.html")


# Defining the start of Dubhe
@app.route("/start")  # this sets the route to this page
def start_page():
    return render_template("start.html")


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file:
        return jsonify({"message": "No file provided", "status": "error"})
    if file and file.filename.endswith('.xmi'):
        # Process the file here
        file.save(os.path.join(XMI_PATH_WEB))
        web_parser = ActivityParser(XMI_PATH_WEB)
        web_result = web_parser.parse_xmi()
        if web_result == 0:
            return jsonify(
                {
                    "message": "The submitted .xmi file is malformed. Please "
                               "ensure your .xmi file conforms to the XMI "
                               "2.5.1 specification.",
                    "status": "error"})
        else:
            global web_detector
            web_detector = PatternMatching(web_parser.get_elements())
            web_detector.perform_pattern_matching(True)
            global web_corruption
            web_corruption = CorruptionAnalysis(web_parser.get_elements())
            web_corruption.perform_analysis(True)
            return jsonify(
                {"message": "File successfully uploaded", "status": "success"})
    return jsonify(
        {"message": "Invalid file format. Dubhe only supports .xmi files.",
         "status": "error"})


# Defining the report page of Dubhe
@app.route("/report")  # this sets the route to this page
def report_page():
    if web_detector is None:
        return render_template("start.html")
    ceri = web_detector.get_ceri()
    mitigated = web_detector.get_mitigated_threats()
    potential = web_detector.get_potential_threats()
    unmitigated = web_detector.get_detected_threats()

    longest_path = web_corruption.get_longest_path()
    all_paths = web_corruption.get_all_paths()

    # Graph data
    unmitigated_values = [1, 1, 1, 1, 1, 1]
    potential_values = [1, 1, 1, 1, 1, 1]
    mitigated_values = [1, 1, 1, 1, 1, 1]

    for entry in unmitigated:
        if entry[0].replace('_', ' ').title() == "Spoofing":
            unmitigated_values[0] = unmitigated_values[0] + 1
        elif entry[0].replace('_', ' ').title() == "Tampering":
            unmitigated_values[1] = unmitigated_values[1] + 1
        elif entry[0].replace('_', ' ').title() == "Repudiation":
            unmitigated_values[2] = unmitigated_values[2] + 1
        elif entry[0].replace('_', ' ').title() == "Information Disclosure":
            unmitigated_values[3] = unmitigated_values[3] + 1
        elif entry[0].replace('_', ' ').title() == "Denial Of Service":
            unmitigated_values[4] = unmitigated_values[4] + 1
        elif entry[0].replace('_', ' ').title() == "Elevation Of Privilege":
            unmitigated_values[5] = unmitigated_values[5] + 1

    for entry in potential:
        if entry[0].replace('_', ' ').title() == "Spoofing":
            potential_values[0] = potential_values[0] + 1
        elif entry[0].replace('_', ' ').title() == "Tampering":
            potential_values[1] = potential_values[1] + 1
        elif entry[0].replace('_', ' ').title() == "Repudiation":
            potential_values[2] = potential_values[2] + 1
        elif entry[0].replace('_', ' ').title() == "Information Disclosure":
            potential_values[3] = potential_values[3] + 1
        elif entry[0].replace('_', ' ').title() == "Denial Of Service":
            potential_values[4] = potential_values[4] + 1
        elif entry[0].replace('_', ' ').title() == "Elevation Of Privilege":
            potential_values[5] = potential_values[5] + 1

    for entry in mitigated:
        if entry[0].replace('_', ' ').title() == "Spoofing":
            mitigated_values[0] = mitigated_values[0] + 1
        elif entry[0].replace('_', ' ').title() == "Tampering":
            mitigated_values[1] = mitigated_values[1] + 1
        elif entry[0].replace('_', ' ').title() == "Repudiation":
            mitigated_values[2] = mitigated_values[2] + 1
        elif entry[0].replace('_', ' ').title() == "Information Disclosure":
            mitigated_values[3] = mitigated_values[3] + 1
        elif entry[0].replace('_', ' ').title() == "Denial Of Service":
            mitigated_values[4] = mitigated_values[4] + 1
        elif entry[0].replace('_', ' ').title() == "Elevation Of Privilege":
            mitigated_values[5] = mitigated_values[5] + 1

    # STRIDE categories
    categories = ['Spoofing', 'Tampering', 'Repudiation',
                  'Information Disclosure', 'Denial of Service',
                  'Elevation of Privilege']

    # Number of variables we're plotting.
    num_vars = len(categories)

    # Compute angle for each axis
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()

    unmitigated_values += unmitigated_values[:1]
    potential_values += potential_values[:1]
    mitigated_values += mitigated_values[:1]
    angles += angles[:1]

    # Create Plotly figure
    fig = go.Figure()

    fig.add_trace(go.Scatterpolar(
        r=unmitigated_values,
        theta=categories,
        fill='toself',
        name='Unmitigated',
        line=dict(color='red')
    ))

    fig.add_trace(go.Scatterpolar(
        r=potential_values,
        theta=categories,
        fill='toself',
        name='Potentially Mitigated',
        line=dict(color='yellow')
    ))

    fig.add_trace(go.Scatterpolar(
        r=mitigated_values,
        theta=categories,
        fill='toself',
        name='Mitigated',
        line=dict(color='green')
    ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, max(max(unmitigated_values), max(potential_values), max(mitigated_values))]
            )),
        showlegend=True
    )

    # Save the graph as an HTML div
    graph_div = fig.to_html(full_html=False)

    ceri_average_worst = 0
    ceri_average_best = 0

    for entry in ceri:
        ceri_average_worst += entry[2]
        ceri_average_best += entry[3]

    if not ceri:
        return "No CERI values calculated, please check the input and try again."

    ceri_average_worst = ceri_average_worst / len(ceri)
    ceri_average_best = ceri_average_best / len(ceri)

    bsp_label = ""
    for entry in ceri:
        if bsp_label == "":
            bsp_label += f"<br>CERI for {entry[0]} - ({entry[1]}): ({entry[2]}, {entry[3]})"
        else:
            bsp_label += f"<br>CERI for {entry[0]} - ({entry[1]}): ({entry[2]}, {entry[3]})"

    mitigated_label = ""
    for entry in mitigated:
        if mitigated_label == "":
            mitigated_label += f"<br><b>{entry[0].replace('_', ' ').title()[0]}</b>: {entry[-1].get_technique().strip()} ({entry[-1].get_technique_num().strip()})"
        else:
            mitigated_label += f"<br><b>{entry[0].replace('_', ' ').title()[0]}</b>: {entry[-1].get_technique().strip()} ({entry[-1].get_technique_num().strip()})"
    potential_label = ""
    for entry in potential:
        if potential_label == "":
            potential_label += f"<br><b>{entry[0].replace('_', ' ').title()[0]}</b>: {entry[-1].get_technique().strip()} ({entry[-1].get_technique_num().strip()})"
        else:
            potential_label += f"<br><b>{entry[0].replace('_', ' ').title()[0]}</b>: {entry[-1].get_technique().strip()} ({entry[-1].get_technique_num().strip()})"
    unmitigated_label = ""
    for entry in unmitigated:
        if unmitigated_label == "":
            unmitigated_label += f"<br><b>{entry[0].replace('_', ' ').title()[0]}</b>: {entry[-1].get_technique().strip()} ({entry[-1].get_technique_num().strip()})"
        else:
            unmitigated_label += f"<br><b>{entry[0].replace('_', ' ').title()[0]}</b>: {entry[-1].get_technique().strip()} ({entry[-1].get_technique_num().strip()})"

    return render_template("report.html",
                           ceri_average_worst=ceri_average_worst,
                           ceri_average_best=ceri_average_best,
                           mitigated=mitigated,
                           potential=potential, unmitigated=unmitigated,
                           bsp_label=bsp_label,
                           mitigated_label=mitigated_label,
                           potential_label=potential_label,
                           unmitigated_label=unmitigated_label,
                           longest_path=longest_path,
                           graph_div=graph_div)

# Defining the suggestions page of Dubhe
@app.route("/suggestions")  # this sets the route to this page
def suggestions_page():
    if web_detector is None:
        return render_template("start.html")

    unmitigated = web_detector.get_detected_threats()
    potential = web_detector.get_potential_threats()

    datastores = [web_corruption.get_protect_entry(),
                  web_corruption.get_protect_stores(),
                  web_corruption.get_protect_whole()]

    # Build the DataSanitizer recommendation string.
    suggestions_label = f"If you want to harden your system against data corruption attacks, we recommend the incorporation of a DataSanitizer object. We outline some possible locations for the DataSanitizer below:<br><br><b>Protecting Expected Entry Points</b><br>It is recommended to place a Data Sanitizer object between the following elements:<br><b>{datastores[0][0][0]}</b> (parented by {datastores[0][0][2]}), <b>{datastores[0][1][0]}-{datastores[0][1][1]}</b> (parented by {datastores[0][1][2]})"
    if len(datastores[1]) > 0:
        suggestions_label += f"<br><br><b>Protecting Data Stores</b><br>It is recommended to place a Data Sanitizer object between the following elements:<br><b>{datastores[1][0][0]}-{datastores[1][0][1]}</b> (parented by {datastores[1][0][2]}), <b>{datastores[1][1][0]}-{datastores[1][1][1]}</b> (parented by {datastores[1][1][2]})"
    suggestions_label += f"<br><br><b>Minimizing Corruption Propagation</b><br>It is recommended to place a Data Sanitizer object between the following elements:<br><b>{datastores[2][0][0]}-{datastores[2][0][1]}</b> (parented by {datastores[2][0][2]}), <b>{datastores[2][1][0]}-{datastores[2][1][1]}</b> (parented by {datastores[2][1][2]})"

    return render_template("suggestions.html",
                           suggestions_label=suggestions_label)


# Defining the learn page of our site
@app.route("/learn")
def learn_page():
    return render_template("learn.html")


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

    # If you don't want the web interface, please comment out the next line
    app.run()
