# Dubhe ✨

Dubhe is an analysis tool that takes in behavioural system design artifacts as input and produces security recommendations to assist designers with the incorporation of security during design time.

Dubhe is currently under active development and will be updated with additional features in the near future.

Created by the CyberSEA Lab at Carleton University. Learn more [here](https://carleton.ca/cybersea/).

### Did You Know?
Dubhe is a star in the Ursa Major constellation. It is commonly referred to as a ""pointer star"" as it is helpful for finding Polaris, also known as the North Star. Dubhe follows the naming conventions of previous released security posture analysis tools. You can learn more about these tools [here](https://compass.carleton.ca/explore).

## Development

### Tools

- Code editor: [PyCharm](https://www.jetbrains.com/pycharm/download/)
- Python: [3.9+](https://www.python.org/downloads/)
- Python package manager: [requirements.txt](https://www.jetbrains.com/help/pycharm/managing-dependencies.html)

### Getting Started

1. Clone the repository
2. **Option 1** - IDE
   1. Open the Project's root directory within a Python supported IDE, such as PyCharm or VSCode
   2. Navigate to `backend/Dubhe.py`
      1. [Optional] Update the XMI_FILE_PATH constant if you wish to target a different .xmi file for analysis.
   3. Run the main method of the application within Dubhe.py. By default, the analysis will be performed on a UML Activity Diagram created to represent the login flow for an Online Seller of Merchandise system. One additional use case is included under the path `common/XMI Files/DualDatabase.xmi` that illustrates how the analysis changes if there are multiple datastores within a UML Activity Diagram.
3. **Option 2** - CLI
   1. Navigate to the root directory of the project via your command line of choice.
   2. Ensure Python 3.9+ is installed on your system. If it is not, install it from the above download link.
      1. On Windows, use the command `py` to check for a Python installation
      2. On OSX and Linux, use the command `python3 --version`
   3. From the root directory of the project, install the required dependencies using the command `pip install -r requirements.txt`
   4. Navigate to the `backend` directory and run the tool using the command `py Dubhe.py`
      1. [Optional] If you wish to save the output of the analysis to a file, you can redirect the output using the command `py Dubhe.py > output.txt`
   5. **Note:** If you wish to use a different file for analysis when running from the command line, you will need to update the file path directly in the `Dubhe.py` file on lines 21 and 22. 

### XMI Files
If you want to try to submit your own XMI files for analysis with Dubhe, great! Just be sure that your UML Modelling tool supports XMI exports following the XMI 2.X [official specification](https://www.omg.org/spec/XMI/2.5.1/PDF/).

Sample XMI files are included under `common/XMI Files` which were generated using [StarUML](https://staruml.io/download/). You can find the model files that were used to generate the XMI under `common/StarUML Files`.

## Analysis

Dubhe currently supports the following types of analysis:
 - Analysis of UML Activity Diagrams to provide recommendations for the locations of data sanitization objects with activity flows. Up to three recommendations can be generated that aim to minimize the potential for data corruption propagation throughout the system as a whole, or to protect datastores or the expected entry points of systems.

More details on how this analysis works can be found within the source code of Dubhe.
## Known issues

Currently, there are no known issues.

> If you notice a bug, please add it to Issues tab. Make sure you include how to recreate the bug!
