import os
import re
import numpy as np
from flask import Flask, render_template, request, jsonify
import plotly.graph_objects as go
from markupsafe import Markup

from CorruptionAnalysis import CorruptionAnalysis
from ActivityParser import ActivityParser
from PatternMatching import PatternMatching

XMI_FILE_PATH = os.path.join(os.getcwd(), "..", "common", "XMI Files", "Spoofing Example Unprotected.xmi")
XMI_PATH_WEB = os.path.join(os.getcwd(), "..", "common", "XMI Files", "Analysis.xmi")
app = Flask(__name__)
web_detector = None
web_corruption = None
uploaded_file_name = ""


@app.template_filter('linkify_threat_numbers')
def linkify_threat_numbers(text):
    pattern = re.compile(r'\(T(\d+)\)')
    return Markup(pattern.sub(r'(<a href="https://attack.mitre.org/techniques/T\1/" target="_blank" class="hyperlink">T\1</a>)', text))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/start")
def start_page():
    return render_template("start.html")


@app.route('/upload', methods=['POST'])
def upload_file():
    global uploaded_file_name
    file = request.files.get('file')
    if not file:
        return jsonify({"message": "No file provided", "status": "error"})
    if file and file.filename.endswith('.xmi'):
        uploaded_file_name = file.filename
        file.save(os.path.join(XMI_PATH_WEB))
        web_parser = ActivityParser(XMI_PATH_WEB)
        web_result = web_parser.parse_xmi()
        if web_result == 0:
            return jsonify({
                "message": "The submitted .xmi file is malformed. Please ensure your .xmi file conforms to the XMI 2.5.1 specification.",
                "status": "error"
            })
        else:
            global web_detector
            web_detector = PatternMatching(web_parser.get_elements())
            web_detector.perform_pattern_matching(True)
            global web_corruption
            web_corruption = CorruptionAnalysis(web_parser.get_elements())
            web_corruption.perform_analysis(True)
            return jsonify({"message": "File successfully uploaded", "status": "success"})
    return jsonify({"message": "Invalid file format. Dubhe only supports .xmi files.", "status": "error"})


@app.route("/report")
def report_page():
    if web_detector is None:
        return render_template("start.html")

    ceri = web_detector.get_ceri()
    mitigated = web_detector.get_mitigated_threats()
    potential = web_detector.get_potential_threats()
    unmitigated = web_detector.get_detected_threats()

    all_paths = web_corruption.get_all_paths()
    sum_paths = 0
    total_paths = 0

    for cpp_path in all_paths:
        for elem in cpp_path:
            if elem.get_parent() == 'Data Sanitizer':
                total_paths += 1
                sum_paths -= 1
        sum_paths += len(cpp_path) - 1
        total_paths += 1

    cpp = sum_paths / total_paths

    unmitigated_values = [0, 0, 0, 0, 0, 0]
    potential_values = [0, 0, 0, 0, 0, 0]
    mitigated_values = [0, 0, 0, 0, 0, 0]

    for entry in unmitigated:
        if entry[0].replace('_', ' ').title() == "Spoofing":
            unmitigated_values[0] += 1
        elif entry[0].replace('_', ' ').title() == "Tampering":
            unmitigated_values[1] += 1
        elif entry[0].replace('_', ' ').title() == "Repudiation":
            unmitigated_values[2] += 1
        elif entry[0].replace('_', ' ').title() == "Information Disclosure":
            unmitigated_values[3] += 1
        elif entry[0].replace('_', ' ').title() == "Denial Of Service":
            unmitigated_values[4] += 1
        elif entry[0].replace('_', ' ').title() == "Elevation Of Privilege":
            unmitigated_values[5] += 1

    for entry in potential:
        if entry[0].replace('_', ' ').title() == "Spoofing":
            potential_values[0] += 1
        elif entry[0].replace('_', ' ').title() == "Tampering":
            potential_values[1] += 1
        elif entry[0].replace('_', ' ').title() == "Repudiation":
            potential_values[2] += 1
        elif entry[0].replace('_', ' ').title() == "Information Disclosure":
            potential_values[3] += 1
        elif entry[0].replace('_', ' ').title() == "Denial Of Service":
            potential_values[4] += 1
        elif entry[0].replace('_', ' ').title() == "Elevation Of Privilege":
            potential_values[5] += 1

    for entry in mitigated:
        if entry[0].replace('_', ' ').title() == "Spoofing":
            mitigated_values[0] += 1
        elif entry[0].replace('_', ' ').title() == "Tampering":
            mitigated_values[1] += 1
        elif entry[0].replace('_', ' ').title() == "Repudiation":
            mitigated_values[2] += 1
        elif entry[0].replace('_', ' ').title() == "Information Disclosure":
            mitigated_values[3] += 1
        elif entry[0].replace('_', ' ').title() == "Denial Of Service":
            mitigated_values[4] += 1
        elif entry[0].replace('_', ' ').title() == "Elevation Of Privilege":
            mitigated_values[5] += 1

    categories = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege']
    num_vars = len(categories)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()

    unmitigated_values += unmitigated_values[:1]
    potential_values += potential_values[:1]
    mitigated_values += mitigated_values[:1]
    angles += angles[:1]

    fig = go.Figure()

    fig.add_trace(go.Scatterpolar(
        r=[x + 1 for x in unmitigated_values],  # Shift values by +1
        theta=categories,
        fill='toself',
        name='Unmitigated',
        line=dict(color='red')
    ))

    fig.add_trace(go.Scatterpolar(
        r=[x + 1 for x in potential_values],  # Shift values by +1
        theta=categories,
        fill='toself',
        name='Potentially Mitigated',
        line=dict(color='yellow')
    ))

    fig.add_trace(go.Scatterpolar(
        r=[x + 1 for x in mitigated_values],  # Shift values by +1
        theta=categories,
        fill='toself',
        name='Mitigated',
        line=dict(color='green')
    ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, max(max(unmitigated_values), max(potential_values), max(mitigated_values)) + 1]  # Extend range by +1
            )),
        showlegend=True
    )

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
            bsp_label += f"<br><b>CERI for {entry[0]}: {entry[1]}</b> - ({entry[2]}, {entry[3]})"
        else:
            bsp_label += f"<br><b>CERI for {entry[0]}: {entry[1]}</b> - ({entry[2]}, {entry[3]})"

    # Sort the BSP label alphabetically
    bsp_entries = bsp_label.split("<br>")
    bsp_entries_sorted = sorted([entry for entry in bsp_entries if entry.strip() != ""], key=lambda x: x.split(" ")[2].lower())
    bsp_label_sorted = "<br>".join(bsp_entries_sorted)

    mitigated_label = create_stride_sorted_label(mitigated)
    potential_label = create_stride_sorted_label(potential)
    unmitigated_label = create_stride_sorted_label(unmitigated)

    return render_template(
        "report.html",
        filename=uploaded_file_name,
        ceri_average_worst=ceri_average_worst,
        ceri_average_best=ceri_average_best,
        mitigated=mitigated,
        potential=potential,
        unmitigated=unmitigated,
        bsp_label=bsp_label_sorted,
        mitigated_label=mitigated_label,
        potential_label=potential_label,
        unmitigated_label=unmitigated_label,
        cpp=cpp,
        graph_div=graph_div
    )


def create_stride_sorted_label(threats):
    if not threats:
        return ""

    # Define the STRIDE order
    stride_order = {
        "Spoofing": 0,
        "Tampering": 1,
        "Repudiation": 2,
        "Information Disclosure": 3,
        "Denial Of Service": 4,
        "Elevation Of Privilege": 5
    }

    # Create a list of formatted threat strings
    threat_strings = [
        (stride_order.get(entry[0].replace('_', ' ').title(), 6),  # Use a high default value for unrecognized threats
         f"<b>{entry[0].replace('_', ' ').title()}</b>: {entry[-1].get_technique().strip()} ({entry[-1].get_technique_num().strip()})")
        for entry in threats
    ]

    # Sort the list according to the STRIDE order
    sorted_threats = sorted(threat_strings, key=lambda x: x[0])

    # Join the sorted list into a single string separated by <br> tags
    formatted_threats = "<br>".join([entry[1] for entry in sorted_threats])

    return formatted_threats


@app.route("/suggestions")
def suggestions_page():
    if web_detector is None:
        return render_template("start.html")

    unmitigated = web_detector.get_detected_threats()
    potential = web_detector.get_potential_threats()
    mitigated = web_detector.get_mitigated_threats()

    datastores = [web_corruption.get_protect_entry(), web_corruption.get_protect_stores(), web_corruption.get_protect_whole()]

    suggestions_label = ""

    try:
        entry_points = datastores[0]
        datastore_points = datastores[1]
        whole_system_points = datastores[2]

        if entry_points and len(entry_points) >= 2:
            suggestions_label += (
                "<b>Protecting Expected Entry Points</b><br>"
                "<div class='indented'>It is recommended to place a DataSanitizer object between the following elements:<br>"
                f"&emsp;<b>1. {entry_points[0][0]}: {entry_points[0][1]}</b> (parented by {entry_points[0][2]})<br>"
                f"&emsp;<b>2. {entry_points[1][0]}: {entry_points[1][1]}</b> (parented by {entry_points[1][2]})</div><br>"
            )
        else:
            suggestions_label += (
                "<b>Protecting Expected Entry Points</b><br>"
                "<div class='indented'>No InitialNodes were detected in your file. Are you sure you submitted the right file?</div><br>"
            )

        if datastore_points and len(datastore_points) >= 2:
            suggestions_label += (
                "<b>Protecting Data Stores</b><br>"
                "<div class='indented'>It is recommended to place a DataSanitizer object between the following elements:<br>"
                f"&emsp;<b>1. {datastore_points[0][0]}: {datastore_points[0][1]}</b> (parented by {datastore_points[0][2]})<br> "
                f"&emsp;<b>2. {datastore_points[1][0]}: {datastore_points[1][1]}</b> (parented by {datastore_points[1][2]})</div><br>"
            )
        else:
            suggestions_label += (
                "<b>Protecting Data Stores</b><br>"
                "<div class='indented'>No datastores were detected in your system, so no recommendation was generated.</div><br>"
            )

        if whole_system_points and len(whole_system_points) >= 2:
            suggestions_label += (
                "<b>Minimizing Corruption Propagation</b><br>"
                "<div class='indented'>It is recommended to place a DataSanitizer object between the following elements:<br>"
                f"&emsp;<b>1. {whole_system_points[0][0]}: {whole_system_points[0][1]}</b> (parented by {whole_system_points[0][2]})<br> "
                f"&emsp;<b>2. {whole_system_points[1][0]}: {whole_system_points[1][1]}</b> (parented by {whole_system_points[1][2]})</div>"
            )
        else:
            suggestions_label += (
                "<b>Minimizing Corruption Propagation</b><br>"
                "<div class='indented'>Somehow, no paths were detected in your system... Are you sure you submitted the correct file?</div><br>"
            )

    except (IndexError, TypeError) as e:
        suggestions_label = (
            "An error occurred while generating suggestions. "
            "Please ensure the analysis was performed correctly and the XMI file is properly formatted."
        )
        print(f"Error generating suggestions: {e}")

    # Group threats by STRIDE categories
    stride_categories = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial Of Service', 'Elevation Of Privilege']
    grouped_threats = {category: [] for category in stride_categories}

    for entry in unmitigated + potential:
        category = entry[0].replace('_', ' ').title()
        if category in grouped_threats:
            grouped_threats[category].append((entry[0].replace('_', ' ').title(), entry[-1].get_technique(), entry[-1].get_technique_num().strip(),
                                              entry[-1].get_mitigation(), entry[-1].get_mitigation_num().strip(), "path/to/placeholder-image.jpg"))

    # Collect the threats data
    all_threats = web_detector.get_detected_threats() + web_detector.get_potential_threats() + web_detector.get_mitigated_threats()
    total_threats_checked = len(all_threats)

    # Initialize threat counts
    threat_counts = {category: {'undetected': [], 'unmitigated': [], 'potentially_mitigated': [], 'mitigated': []} for category in stride_categories}

    # Fill in the counts and threat lists
    for threat in web_detector.get_detected_threats():
        category = threat[0].replace('_', ' ').title()
        threat_counts[category]['unmitigated'].append((threat[1].get_technique_num(), threat[1].get_technique()))

    for threat in web_detector.get_potential_threats():
        category = threat[0].replace('_', ' ').title()
        threat_counts[category]['potentially_mitigated'].append((threat[1].get_technique_num(), threat[1].get_technique()))

    for threat in web_detector.get_mitigated_threats():
        category = threat[0].replace('_', ' ').title()
        threat_counts[category]['mitigated'].append((threat[1].get_technique_num(), threat[1].get_technique()))

    # Collect BSP vector string and CERI values
    ceri = web_detector.get_ceri()
    all_paths = web_corruption.get_all_paths()
    sum_paths = 0
    total_paths = 0

    for cpp_path in all_paths:
        for elem in cpp_path:
            if elem.get_parent() == 'Data Sanitizer':
                total_paths += 1
                sum_paths -= 1
        sum_paths += len(cpp_path) - 1
        total_paths += 1

    cpp = sum_paths / total_paths
    bsp_vector = "({:.2f}, {:.2f}), {}".format(ceri[0][2], ceri[0][3], cpp)
    ceri_values = [(ceri_val[0], ceri_val[1], ceri_val[2], ceri_val[3]) for ceri_val in ceri]

    # Data Sanitizer Check
    has_data_sanitizer = any(elem.get_parent() == 'Data Sanitizer' for elem in web_corruption._elements)

    return render_template(
        "suggestions.html",
        suggestions_label=Markup(suggestions_label),
        grouped_threats=grouped_threats,
        total_threats_checked=total_threats_checked,
        threat_counts=threat_counts,
        bsp_vector=bsp_vector,
        ceri_values=ceri_values,
        total_paths=total_paths,
        has_data_sanitizer=has_data_sanitizer,
        uploaded_file_name=uploaded_file_name
    )


@app.route("/learn")
def learn_page():
    return render_template("learn.html")


if __name__ == "__main__":
    parser = ActivityParser(XMI_FILE_PATH)
    result = parser.parse_xmi()
    if parser == 0:
        print(
            "[ERROR]: It appears the supplied .xmi file is malformed. Dubhe currently support XMI versions 2.X+. Please double-check your .xmi file before trying to rerun Dubhe.")
        exit()

    detector = PatternMatching(parser.get_elements())
    corruption = CorruptionAnalysis(parser.get_elements())
    corruption.perform_analysis()

    app.run()
