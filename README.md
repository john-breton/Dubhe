# Dubhe ✨
Dubhe is an analysis tool that takes in UML activity diagrams to determine a system's behavioural security posture.

We plan to deploy Dubhe to the [Compass](https://compass.carleton.ca/) toolkit in the near future. Stay tuned!

Created by the CyberSEA Lab at Carleton University. Learn more [here](https://carleton.ca/cybersea/).

Lead Maintainer: [John Breton](mailto:johnbreton37@gmail.com)

### Did You Know?
Dubhe is a star in the Ursa Major constellation. It is commonly referred to as a **pointer star** as it is helpful for finding Polaris, also known as the North Star. Dubhe follows the naming conventions of previous released security posture analysis tools. You can learn more about these tools [here](https://compass.carleton.ca/explore).

## Sample Video
![A demonstration of Dubhe](https://gitlab.com/CyberSEA-Public/dubhe/-/raw/main/main/static/assets/Dubhe.gif)

## Development

### Tools
- Code editor: [PyCharm](https://www.jetbrains.com/pycharm/download/)
- Python: [3.9+](https://www.python.org/downloads/)
- Flask [3.0.3](https://flask.palletsprojects.com/en/3.0.x/)
- Python package manager: [requirements.txt](https://www.jetbrains.com/help/pycharm/managing-dependencies.html)

### Getting Started
1. Clone the repository
2. **Option 1** - Flask App
   1. Open the Project's root directory within a Python supported IDE, such as PyCharm or VSCode
   2. Navigate to `main/startup.py`
      1. [Optional] If you want to run Dubhe without the web UI, ensure the XMI_FILE_PATH is updated to reference your desired .xmi file.
   3. Run the main method of the application within startup.py. This will deploy Dubhe on your localhost. 
3. **Option 2** - CLI
   1. Navigate to the root directory of the project via your command line of choice.
   2. Ensure Python 3.9+ is installed on your system. If it is not, install it from the above download link.
      1. On Windows, use the command `py` to check for a Python installation
      2. On OSX and Linux, use the command `python3 --version`
   3. From the root directory of the project, install the required dependencies using the command `pip install -r requirements.txt`
   4. Navigate to the `main` directory and run the tool using the command `py startup.py`
      1. [Optional] If you wish to save the output of the analysis to a file, you can redirect the output using the command `py startup.py > output.txt`
   5. **Note:** If you wish to use a different file for analysis when running from the command line, you will need to update the file path directly in the `startup.py` file on line 12. 

### XMI Files
If you want to try to submit your own XMI files for analysis with Dubhe, great! Just be sure that your UML modelling tool supports XMI exports following the XMI 2.X [official specification](https://www.omg.org/spec/XMI/2.5.1/PDF/).

Sample XMI files are included under `common/XMI Files` which were generated using [StarUML](https://staruml.io/download/). You can find the model files that were used to generate the XMI under `common/StarUML Files`.

## Analysis
Dubhe currently supports the following types of analysis:
 - Determination of a system's behavioural security posture through the calculation of its average Critical Element Risk Index (CERI) and its Corruption Propagation Potential (CPP).
 - Identifying threat patterns within UML activity diagrams, and determining if these threats have been properly mitigated through custom XMI pattern matching methods.
 - Analysis of UML Activity Diagrams to provide recommendations for the locations of data sanitization objects with activity flows. Up to three recommendations can be generated that aim to minimize the potential for data corruption propagation throughout the system as a whole, or to protect datastores or the expected entry points of systems.
 - Suggestion mitigation patterns for detected unmitigated threats, with the ability to save the full analysis report as a PDF for future reference.

More details on how this analysis works can be found within the source code of Dubhe and in the following publication(s):
 - J Breton, J Jaskolka, GOM Yee, Hardening Systems Against Data Corruption Attacks at Design Time - <a href="https://www.fps-2023.com/index.php/detailed-program/">FPS 2023</a> 

## Contributing
If you want to contribute to Dubhe, feel free to open a merge request! Be sure to describe your changes and to ensure all existing test cases pass. If these conditions are not met your merge request will likely be closed.

## Known issues
Currently, there are no known issues.

> If you notice a bug, please add it to Issues tab. Make sure you include how to recreate the bug!
