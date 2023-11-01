from PySide2.QtWidgets import QDesktopWidget, QMainWindow

from frontend.Dubhe import Ui_DubheMain


class Window(QMainWindow):

    def __init__(self, dubhe):
        super().__init__()
        # Setup the UI using ZOIALibrarian.py
        self.ui = Ui_DubheMain()
        self.dubhe = dubhe
        self.ui.setupUi(self)
        # Center the application on launch.
        frame = self.frameGeometry()
        center = QDesktopWidget().availableGeometry().center()
        frame.moveCenter(center)
        self.move(frame.topLeft())
        self.ui.analysis_button.clicked.connect(dubhe.perform_analysis)

