# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'Dubhe.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_DubheMain(object):
    def setupUi(self, DubheMain):
        if not DubheMain.objectName():
            DubheMain.setObjectName(u"DubheMain")
        DubheMain.resize(828, 638)
        self.centralwidget = QWidget(DubheMain)
        self.centralwidget.setObjectName(u"centralwidget")
        self.widget = QWidget(self.centralwidget)
        self.widget.setObjectName(u"widget")
        self.widget.setGeometry(QRect(0, 0, 831, 41))
        self.frame = QFrame(self.centralwidget)
        self.frame.setObjectName(u"frame")
        self.frame.setGeometry(QRect(0, 30, 831, 601))
        self.frame.setFrameShape(QFrame.StyledPanel)
        self.frame.setFrameShadow(QFrame.Raised)
        self.dubhe_label = QLabel(self.frame)
        self.dubhe_label.setObjectName(u"dubhe_label")
        self.dubhe_label.setGeometry(QRect(380, 270, 31, 21))
        self.analysis_button = QPushButton(self.frame)
        self.analysis_button.setObjectName(u"analysis_button")
        self.analysis_button.setGeometry(QRect(360, 300, 75, 23))
        self.results_label = QLabel(self.frame)
        self.results_label.setObjectName(u"results_label")
        self.results_label.setGeometry(QRect(70, 390, 691, 181))
        DubheMain.setCentralWidget(self.centralwidget)

        self.retranslateUi(DubheMain)

        QMetaObject.connectSlotsByName(DubheMain)
    # setupUi

    def retranslateUi(self, DubheMain):
        DubheMain.setWindowTitle(QCoreApplication.translate("DubheMain", u"Dubhe", None))
        self.dubhe_label.setText(QCoreApplication.translate("DubheMain", u"Dubhe", None))
        self.analysis_button.setText(QCoreApplication.translate("DubheMain", u"Do Analysis", None))
        self.results_label.setText(QCoreApplication.translate("DubheMain", u"TextLabel", None))
    # retranslateUi

