# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ui/editor.ui'
#
# Created: Fri Nov  5 00:55:45 2010
#      by: PyQt4 UI code generator 4.7.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

class Ui_EditorDialog(object):
    def setupUi(self, EditorDialog):
        EditorDialog.setObjectName("EditorDialog")
        EditorDialog.setWindowModality(QtCore.Qt.ApplicationModal)
        EditorDialog.resize(640, 600)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(EditorDialog.sizePolicy().hasHeightForWidth())
        EditorDialog.setSizePolicy(sizePolicy)
        self.verticalLayout = QtGui.QVBoxLayout(EditorDialog)
        self.verticalLayout.setMargin(0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.menubar = QtGui.QMenuBar(EditorDialog)
        self.menubar.setObjectName("menubar")
        self.menuFile = QtGui.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.verticalLayout.addWidget(self.menubar)
        self.frame = QtGui.QFrame(EditorDialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame.sizePolicy().hasHeightForWidth())
        self.frame.setSizePolicy(sizePolicy)
        self.frame.setFrameShape(QtGui.QFrame.NoFrame)
        self.frame.setFrameShadow(QtGui.QFrame.Plain)
        self.frame.setLineWidth(0)
        self.frame.setObjectName("frame")
        self.verticalLayout.addWidget(self.frame)
        self.actionSave = QtGui.QAction(EditorDialog)
        self.actionSave.setObjectName("actionSave")
        self.menuFile.addAction(self.actionSave)
        self.menubar.addAction(self.menuFile.menuAction())

        self.retranslateUi(EditorDialog)
        QtCore.QMetaObject.connectSlotsByName(EditorDialog)

    def retranslateUi(self, EditorDialog):
        EditorDialog.setWindowTitle(_("LinkChecker source view"))
        self.menuFile.setTitle(_("File"))
        self.actionSave.setText(_("Save"))
