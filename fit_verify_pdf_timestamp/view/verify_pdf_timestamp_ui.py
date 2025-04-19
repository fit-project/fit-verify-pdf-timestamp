#!/usr/bin/env python3
# -*- coding:utf-8 -*-
######
# -----
# Copyright (c) 2023 FIT-Project
# SPDX-License-Identifier: LGPL-3.0-or-later
# -----
######


from PySide6 import QtCore, QtGui, QtWidgets

from fit_verify_pdf_timestamp.lang import load_translations
from fit_common.core.utils import get_version


class Ui_fit_verify_pdf_timestamp(object):
    def setupUi(self, fit_verify_pdf_timestamp):
        fit_verify_pdf_timestamp.setObjectName("fit_verify_pdf_timestamp")
        fit_verify_pdf_timestamp.resize(800, 600)
        fit_verify_pdf_timestamp.setMinimumSize(QtCore.QSize(800, 600))
        self.styleSheet = QtWidgets.QWidget(parent=fit_verify_pdf_timestamp)
        self.styleSheet.setStyleSheet(
            "\n"
            "\n"
            "QWidget{\n"
            "    color: rgb(221, 221, 221);\n"
            "    font: 13px;\n"
            "}\n"
            "\n"
            "/* Tooltip */\n"
            "QToolTip {\n"
            "    color: #e06133;\n"
            "    background-color: rgba(33, 37, 43, 180);\n"
            "    border: 1px solid rgb(44, 49, 58);\n"
            "    background-image: none;\n"
            "    background-position: left center;\n"
            "    background-repeat: no-repeat;\n"
            "    border: none;\n"
            "    border-left: 2px solid rgb(224, 97, 51);\n"
            "    text-align: left;\n"
            "    padding-left: 8px;\n"
            "    margin: 0px;\n"
            "}\n"
            "\n"
            "/* Bg App*/\n"
            "#bg_app {    \n"
            "    background-color: rgb(40, 44, 52);\n"
            "    border: 1px solid rgb(44, 49, 58);\n"
            "}\n"
            "\n"
            "/* Title Menu */\n"
            "#title_right_info { font: 13px; }\n"
            "#title_right_info { padding-left: 10px; }\n"
            "\n"
            "/* Content App */\n"
            "#content_top_bg{    \n"
            "    background-color: rgb(33, 37, 43);\n"
            "}\n"
            "#content_bottom{\n"
            "    border-top: 3px solid rgb(44, 49, 58);\n"
            "}\n"
            "\n"
            "/* Top Buttons */\n"
            "#right_buttons_container .QPushButton { background-color: rgba(255, 255, 255, 0); border: none;  border-radius: 5px; }\n"
            "#right_buttons_container .QPushButton:hover { background-color: rgb(44, 49, 57); border-style: solid; border-radius: 4px; }\n"
            "#right_buttons_container .QPushButton:pressed { background-color: rgb(23, 26, 30); border-style: solid; border-radius: 4px; }\n"
            "\n"
            "\n"
            "/* Bottom Bar */\n"
            "#bottom_bar { background-color: rgb(44, 49, 58); }\n"
            "#bottom_bar QLabel { font-size: 11px; color: rgb(113, 126, 149); padding-left: 10px; padding-right: 10px; padding-bottom: 2px; }\n"
            "\n"
            "\n"
            "#content .QLabel:disabled {color: rgba(255, 255, 255, 10%) }\n"
            "#content .QDateEdit:disabled {color: rgba(255, 255, 255, 10%) }\n"
            "#content .QLineEdit:disabled {color: rgba(255, 255, 255, 10%) }\n"
            "\n"
            "#content .QPushButton:disabled {background-color: rgb(52, 59, 72); color: rgba(255, 255, 255, 10%) }\n"
            "#content .QPushButton:hover { background-color: rgb(44, 49, 57);}\n"
            "#content .QPushButton:pressed { background-color: rgb(44, 49, 57);}\n"
            "#content .QPushButton {background-color: rgb(52, 59, 72); }\n"
            "\n"
            "#content .QDateEdit {\n"
            "    border-radius: 5px;\n"
            "    border: 2px solid rgb(33, 37, 43);\n"
            "    padding-left: 10px;\n"
            "}\n"
            "\n"
            "#content .QDateEdit:hover {\n"
            "    border: 2px solid rgb(64, 71, 88);\n"
            "}\n"
            "#content .QDateEdit:focus {\n"
            "    border: 2px solid rgb(91, 101, 124);\n"
            "}\n"
            "\n"
            "#content .QDateEdit::up-button, QDateEdit::down-button {\n"
            "    border: none;\n"
            "    padding-right: 5px;\n"
            "}\n"
            "\n"
            "QDateEdit::up-button {\n"
            "    subcontrol-position: top right;\n"
            "}\n"
            "\n"
            "QDateEdit::down-button {\n"
            "    subcontrol-position: bottom right;\n"
            "}\n"
            "\n"
            "/* now, the magic begins */\n"
            "\n"
            "#content .QDateEdit::up-arrow, QDateEdit::down-arrow {\n"
            '    /* a default color for the "border" (aka, the arrow) */\n'
            "    border: 5px solid white;\n"
            "\n"
            "    /* right and left borders will be transparent */\n"
            "    border-left-color: rgba(255, 255, 255, 0);\n"
            "    border-right-color: rgba(255, 255, 255, 0);\n"
            "\n"
            '    /* basic "null" size as above */\n'
            "    width: 0;\n"
            "    height: 0;\n"
            "}\n"
            "\n"
            "/* set up the up arrow states */\n"
            "\n"
            "#content .QDateEdit::up-arrow {\n"
            "    /*\n"
            '        we want to show the "down border" alone, so we make the \n'
            "        opposite one (the top) invisible and **empty**\n"
            "    */\n"
            "    border-top: none;\n"
            "}\n"
            "\n"
            "#content .QDateEdit::up-arrow:hover {\n"
            "    border-bottom-color: rgb(57, 65, 80);\n"
            "}\n"
            "\n"
            "#content .QDateEdit::up-arrow:pressed {\n"
            "    border-bottom-color: white;\n"
            "}\n"
            "\n"
            "#content .QDateEdit::up-arrow:disabled, QDateEdit::up-arrow:off {\n"
            "    /*\n"
            '        use the "mid" color role as a disabled/invalid arrow\n'
            "        state; since this rule is stated *after*, it will take\n"
            "        precedence in case it matches;\n"
            "    */\n"
            "    border-bottom-color: rgb(52, 59, 72);\n"
            "}\n"
            "\n"
            "/*\n"
            "    set up the down arrow states, similarly to the above, but\n"
            "    using the opposite border when relevant.\n"
            "*/\n"
            "\n"
            "#content .QDateEdit::down-arrow {\n"
            "    border-bottom: none;\n"
            "}\n"
            "\n"
            "#content .QDateEdit::down-arrow:hover {\n"
            "    border-bottom-color: rgb(57, 65, 80);\n"
            "}\n"
            "\n"
            "#content .QDateEdit::down-arrow:pressed {\n"
            "    border-top-color: white;\n"
            "}\n"
            "\n"
            "#content .QDateEdit::down-arrow:disabled, QDateEdit::down-arrow:off {\n"
            "    border-top-color: rgb(52, 59, 72);\n"
            "}\n"
            "\n"
            "/* LineEdit */\n"
            "QLineEdit {\n"
            "    background-color: rgb(33, 37, 43);\n"
            "    border-radius: 5px;\n"
            "    border: 2px solid rgb(33, 37, 43);\n"
            "    padding-left: 10px;\n"
            "    selection-color: rgb(255, 255, 255);\n"
            "    selection-background-color: rgb(255, 121, 198);\n"
            "}\n"
            "QLineEdit:hover {\n"
            "    border: 2px solid rgb(64, 71, 88);\n"
            "}\n"
            "QLineEdit:focus {\n"
            "    border: 2px solid rgb(91, 101, 124);\n"
            "}\n"
            "\n"
            "/* QDateEdit */\n"
            "QDateEdit {\n"
            "    background-color: rgb(33, 37, 43);\n"
            "    border-radius: 5px;\n"
            "    border: 2px solid rgb(33, 37, 43);\n"
            "    padding-left: 10px;\n"
            "}\n"
            "\n"
            "/* ScrollBars */\n"
            "QScrollBar:horizontal {\n"
            "    border: none;\n"
            "    background: rgb(52, 59, 72);\n"
            "    height: 8px;\n"
            "    margin: 0px 21px 0 21px;\n"
            "    border-radius: 0px;\n"
            "}\n"
            "QScrollBar::handle:horizontal {\n"
            "    background: rgb(52, 59, 72);\n"
            "    min-width: 25px;\n"
            "    border-radius: 4px\n"
            "}\n"
            "QScrollBar::add-line:horizontal {\n"
            "    border: none;\n"
            "    background: rgb(55, 63, 77);\n"
            "    width: 20px;\n"
            "    border-top-right-radius: 4px;\n"
            "    border-bottom-right-radius: 4px;\n"
            "    subcontrol-position: right;\n"
            "    subcontrol-origin: margin;\n"
            "}\n"
            "QScrollBar::sub-line:horizontal {\n"
            "    border: none;\n"
            "    background: rgb(55, 63, 77);\n"
            "    width: 20px;\n"
            "    border-top-left-radius: 4px;\n"
            "    border-bottom-left-radius: 4px;\n"
            "    subcontrol-position: left;\n"
            "    subcontrol-origin: margin;\n"
            "}\n"
            "QScrollBar::up-arrow:horizontal, QScrollBar::down-arrow:horizontal{\n"
            "     background: none;\n"
            "}\n"
            "QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal{\n"
            "     background: none;\n"
            "}\n"
            " QScrollBar:vertical {\n"
            "    border: none;\n"
            "    background: rgb(52, 59, 72);\n"
            "    width: 8px;\n"
            "    margin: 21px 0 21px 0;\n"
            "    border-radius: 0px;\n"
            " }\n"
            " QScrollBar::handle:vertical {    \n"
            "    background: rgb(52, 59, 72);\n"
            "    min-height: 25px;\n"
            "    border-radius: 4px\n"
            " }\n"
            " QScrollBar::add-line:vertical {\n"
            "     border: none;\n"
            "    background: rgb(55, 63, 77);\n"
            "     height: 20px;\n"
            "    border-bottom-left-radius: 4px;\n"
            "    border-bottom-right-radius: 4px;\n"
            "     subcontrol-position: bottom;\n"
            "     subcontrol-origin: margin;\n"
            " }\n"
            " QScrollBar::sub-line:vertical {\n"
            "    border: none;\n"
            "    background: rgb(55, 63, 77);\n"
            "     height: 20px;\n"
            "    border-top-left-radius: 4px;\n"
            "    border-top-right-radius: 4px;\n"
            "     subcontrol-position: top;\n"
            "     subcontrol-origin: margin;\n"
            " }\n"
            " QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {\n"
            "     background: none;\n"
            " }\n"
            "\n"
            " QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {\n"
            "     background: none;\n"
            " }\n"
            "\n"
            "\n"
            "QTreeView::indicator {\n"
            "    border: 3px solid rgb(52, 59, 72);\n"
            "    width: 15px;\n"
            "    height: 15px;\n"
            "    border-radius: 10px;\n"
            "    background: rgb(44, 49, 60);\n"
            "    margin:5px 3px 5px 3px;\n"
            "}\n"
            "QTreeView::indicator:hover {\n"
            "    border: 3px solid rgb(58, 66, 81);\n"
            "}\n"
            "QTreeView::indicator:checked {\n"
            "    background: 3px solid rgb(52, 59, 72);\n"
            "    border: 3px solid rgb(52, 59, 72);    \n"
            "    background-image: url(:/icons/cil-check-alt.png);\n"
            "}\n"
            "\n"
            "QTreeView::item{\n"
            "    padding-bottom: 2px;\n"
            "}\n"
            "\n"
            "\n"
            "/* CheckBox */\n"
            "QCheckBox::indicator {\n"
            "    border: 3px solid rgb(52, 59, 72);\n"
            "    width: 15px;\n"
            "    height: 15px;\n"
            "    border-radius: 10px;\n"
            "    background: rgb(44, 49, 60);\n"
            "    margin:0px 3px 0px 3px;\n"
            "}\n"
            "QCheckBox::indicator:hover {\n"
            "    border: 3px solid rgb(58, 66, 81);\n"
            "}\n"
            "QCheckBox::indicator:checked {\n"
            "    background: 3px solid rgb(52, 59, 72);\n"
            "    border: 3px solid rgb(52, 59, 72);    \n"
            "    background-image: url(:/icons/cil-check-alt.png);\n"
            "}\n"
            "\n"
            "QCheckBox::disabled {color: rgba(255, 255, 255, 10%) }\n"
            "\n"
            "/* ComboBox */\n"
            "QComboBox{\n"
            "    background-color: rgb(33, 37, 43);\n"
            "    border-radius: 5px;\n"
            "    border: 2px solid rgb(33, 37, 43);\n"
            "    padding-bottom: 5px;\n"
            "    padding-top: 5px;\n"
            "    padding-left: 10px;\n"
            "\n"
            "}\n"
            "QComboBox:hover{\n"
            "    border: 2px solid rgb(64, 71, 88);\n"
            "}\n"
            "QComboBox::drop-down {\n"
            "    subcontrol-origin: padding;\n"
            "    subcontrol-position: top right;\n"
            "    width: 25px; \n"
            "    border-left-width: 3px;\n"
            "    border-left-color: rgba(39, 44, 54, 150);\n"
            "    border-left-style: solid;\n"
            "    border-top-right-radius: 3px;\n"
            "    border-bottom-right-radius: 3px;    \n"
            "    background-image: url(:/icons/cil-arrow-bottom.png);\n"
            "    background-position: center;\n"
            "    background-repeat: no-reperat;\n"
            " }\n"
            "\n"
            "QComboBox:!editable{\n"
            "    selection-background-color: rgb(33, 37, 43);\n"
            "}\n"
            "\n"
            "QComboBox QAbstractItemView {\n"
            "    border: none;\n"
            "    background-color: rgb(0, 0, 0);\n"
            "     padding:10px;\n"
            "    selection-background-color: rgb(33, 37, 43);\n"
            "}\n"
            "\n"
            "/* RadioButton */\n"
            "QRadioButton::indicator {\n"
            "    border: 3px solid rgb(52, 59, 72);\n"
            "    width: 15px;\n"
            "    height: 15px;\n"
            "    border-radius: 10px;\n"
            "    background: rgb(44, 49, 60);\n"
            "}\n"
            "QRadioButton::indicator:hover {\n"
            "    border: 3px solid rgb(58, 66, 81);\n"
            "}\n"
            "QRadioButton::indicator:checked {\n"
            "    background: 3px solid rgb(94, 106, 130);\n"
            "    border: 3px solid rgb(52, 59, 72);    \n"
            "}\n"
            "\n"
            "/* ComboBox */\n"
            "QComboBox{\n"
            "    background-color: rgb(33, 37, 43);\n"
            "    border-radius: 5px;\n"
            "    border: 2px solid rgb(33, 37, 43);\n"
            "    padding-bottom: 5px;\n"
            "    padding-top: 5px;\n"
            "    padding-left: 10px;\n"
            "\n"
            "}\n"
            "QComboBox:hover{\n"
            "    border: 2px solid rgb(64, 71, 88);\n"
            "}\n"
            "QComboBox::drop-down {\n"
            "    subcontrol-origin: padding;\n"
            "    subcontrol-position: top right;\n"
            "    width: 25px; \n"
            "    border-left-width: 3px;\n"
            "    border-left-color: rgba(39, 44, 54, 150);\n"
            "    border-left-style: solid;\n"
            "    border-top-right-radius: 3px;\n"
            "    border-bottom-right-radius: 3px;    \n"
            "    background-image: url(:/icons/cil-arrow-bottom.png);\n"
            "    background-position: center;\n"
            "    background-repeat: no-reperat;\n"
            " }\n"
            "\n"
            "QComboBox:!editable{\n"
            "    selection-background-color: rgb(33, 37, 43);\n"
            "}\n"
            "\n"
            "QComboBox QAbstractItemView {\n"
            "    border: none;\n"
            "    background-color: rgb(0, 0, 0);\n"
            "     padding:10px;\n"
            "    selection-background-color: rgb(33, 37, 43);\n"
            "}\n"
            ""
        )
        self.styleSheet.setObjectName("styleSheet")
        self.appMargins = QtWidgets.QVBoxLayout(self.styleSheet)
        self.appMargins.setContentsMargins(10, 10, 10, 10)
        self.appMargins.setSpacing(0)
        self.appMargins.setObjectName("appMargins")
        self.bg_app = QtWidgets.QFrame(parent=self.styleSheet)
        self.bg_app.setStyleSheet("")
        self.bg_app.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.bg_app.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.bg_app.setObjectName("bg_app")
        self.appLayout = QtWidgets.QHBoxLayout(self.bg_app)
        self.appLayout.setContentsMargins(0, 0, 0, 0)
        self.appLayout.setSpacing(0)
        self.appLayout.setObjectName("appLayout")
        self.content_box = QtWidgets.QFrame(parent=self.bg_app)
        self.content_box.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.content_box.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.content_box.setObjectName("content_box")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.content_box)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.content_top_bg = QtWidgets.QFrame(parent=self.content_box)
        self.content_top_bg.setMinimumSize(QtCore.QSize(0, 50))
        self.content_top_bg.setMaximumSize(QtCore.QSize(16777215, 50))
        self.content_top_bg.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.content_top_bg.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.content_top_bg.setObjectName("content_top_bg")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.content_top_bg)
        self.horizontalLayout.setContentsMargins(0, 0, 10, 0)
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.left_box = QtWidgets.QFrame(parent=self.content_top_bg)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Preferred,
        )
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.left_box.sizePolicy().hasHeightForWidth())
        self.left_box.setSizePolicy(sizePolicy)
        self.left_box.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.left_box.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.left_box.setObjectName("left_box")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.left_box)
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_3.setSpacing(0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.logo_container = QtWidgets.QFrame(parent=self.left_box)
        self.logo_container.setMinimumSize(QtCore.QSize(60, 0))
        self.logo_container.setMaximumSize(QtCore.QSize(60, 16777215))
        self.logo_container.setObjectName("logo_container")
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout(self.logo_container)
        self.horizontalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.top_logo = QtWidgets.QLabel(parent=self.logo_container)
        self.top_logo.setMinimumSize(QtCore.QSize(42, 42))
        self.top_logo.setMaximumSize(QtCore.QSize(42, 42))
        self.top_logo.setText("")
        self.top_logo.setPixmap(QtGui.QPixmap(":/images/images/logo-42x42.png"))
        self.top_logo.setObjectName("top_logo")
        self.horizontalLayout_8.addWidget(self.top_logo)
        self.horizontalLayout_3.addWidget(self.logo_container)
        self.title_right_info = QtWidgets.QLabel(parent=self.left_box)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Policy.Preferred,
            QtWidgets.QSizePolicy.Policy.Expanding,
        )
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.title_right_info.sizePolicy().hasHeightForWidth()
        )
        self.title_right_info.setSizePolicy(sizePolicy)
        self.title_right_info.setMaximumSize(QtCore.QSize(16777215, 45))
        self.title_right_info.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeading
            | QtCore.Qt.AlignmentFlag.AlignLeft
            | QtCore.Qt.AlignmentFlag.AlignVCenter
        )
        self.title_right_info.setObjectName("title_right_info")
        self.horizontalLayout_3.addWidget(self.title_right_info)
        self.horizontalLayout.addWidget(self.left_box)
        self.right_buttons_container = QtWidgets.QFrame(parent=self.content_top_bg)
        self.right_buttons_container.setMinimumSize(QtCore.QSize(0, 28))
        self.right_buttons_container.setStyleSheet("font-size:18px;")
        self.right_buttons_container.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.right_buttons_container.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.right_buttons_container.setObjectName("right_buttons_container")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.right_buttons_container)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setSpacing(5)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.minimize_button = QtWidgets.QPushButton(
            parent=self.right_buttons_container
        )
        self.minimize_button.setMinimumSize(QtCore.QSize(28, 28))
        self.minimize_button.setMaximumSize(QtCore.QSize(28, 28))
        self.minimize_button.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        )
        self.minimize_button.setToolTip("")
        self.minimize_button.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(
            QtGui.QPixmap(":/icons/icons/icon_minimize-disabled.png"),
            QtGui.QIcon.Mode.Normal,
            QtGui.QIcon.State.Off,
        )
        self.minimize_button.setIcon(icon)
        self.minimize_button.setIconSize(QtCore.QSize(20, 20))
        self.minimize_button.setObjectName("minimize_button")
        self.horizontalLayout_2.addWidget(self.minimize_button)
        self.close_button = QtWidgets.QPushButton(parent=self.right_buttons_container)
        self.close_button.setMinimumSize(QtCore.QSize(28, 28))
        self.close_button.setMaximumSize(QtCore.QSize(28, 28))
        self.close_button.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        )
        self.close_button.setToolTip("")
        self.close_button.setText("")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(
            QtGui.QPixmap(":/icons/icons/icon_close-disabled.png"),
            QtGui.QIcon.Mode.Normal,
            QtGui.QIcon.State.Off,
        )
        self.close_button.setIcon(icon1)
        self.close_button.setIconSize(QtCore.QSize(20, 20))
        self.close_button.setObjectName("close_button")
        self.horizontalLayout_2.addWidget(self.close_button)
        self.horizontalLayout.addWidget(
            self.right_buttons_container, 0, QtCore.Qt.AlignmentFlag.AlignRight
        )
        self.verticalLayout_2.addWidget(self.content_top_bg)
        self.content_bottom = QtWidgets.QFrame(parent=self.content_box)
        self.content_bottom.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.content_bottom.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.content_bottom.setObjectName("content_bottom")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.content_bottom)
        self.verticalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_6.setSpacing(0)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.content = QtWidgets.QFrame(parent=self.content_bottom)
        self.content.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.content.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.content.setObjectName("content")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self.content)
        self.horizontalLayout_4.setContentsMargins(10, 10, 10, 10)
        self.horizontalLayout_4.setSpacing(0)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.wrapper = QtWidgets.QFrame(parent=self.content)
        self.wrapper.setEnabled(True)
        self.wrapper.setStyleSheet(
            "QDateEdit::up-arraow{\n" "color:red !important;\n" "}"
        )
        self.wrapper.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.wrapper.setObjectName("wrapper")
        self.topFrameRight = QtWidgets.QVBoxLayout(self.wrapper)
        self.topFrameRight.setContentsMargins(0, 0, 0, 0)
        self.topFrameRight.setSpacing(0)
        self.topFrameRight.setObjectName("topFrameRight")
        self.pdf_file_layout = QtWidgets.QFrame(parent=self.wrapper)
        self.pdf_file_layout.setMinimumSize(QtCore.QSize(0, 0))
        self.pdf_file_layout.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.pdf_file_layout.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.pdf_file_layout.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.pdf_file_layout.setObjectName("pdf_file_layout")
        self.logo_layout = QtWidgets.QHBoxLayout(self.pdf_file_layout)
        self.logo_layout.setSizeConstraint(
            QtWidgets.QLayout.SizeConstraint.SetDefaultConstraint
        )
        self.logo_layout.setContentsMargins(0, 10, 0, 0)
        self.logo_layout.setObjectName("logo_layout")
        self.pdf_file_input = QtWidgets.QLineEdit(parent=self.pdf_file_layout)
        self.pdf_file_input.setMinimumSize(QtCore.QSize(0, 30))
        self.pdf_file_input.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.pdf_file_input.setStyleSheet("background-color: rgb(33, 37, 43);")
        self.pdf_file_input.setText("")
        self.pdf_file_input.setObjectName("pdf_file_input")
        self.logo_layout.addWidget(self.pdf_file_input)
        spacerItem = QtWidgets.QSpacerItem(
            10,
            20,
            QtWidgets.QSizePolicy.Policy.Minimum,
            QtWidgets.QSizePolicy.Policy.Minimum,
        )
        self.logo_layout.addItem(spacerItem)
        self.pdf_file_button = QtWidgets.QPushButton(parent=self.pdf_file_layout)
        self.pdf_file_button.setMinimumSize(QtCore.QSize(80, 30))
        self.pdf_file_button.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.pdf_file_button.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        )
        self.pdf_file_button.setStyleSheet("background-color: rgb(52, 59, 72);")
        self.pdf_file_button.setText("")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(
            QtGui.QPixmap(":/icons/icons/cil-folder-open.png"),
            QtGui.QIcon.Mode.Normal,
            QtGui.QIcon.State.Off,
        )
        self.pdf_file_button.setIcon(icon2)
        self.pdf_file_button.setObjectName("pdf_file_button")
        self.logo_layout.addWidget(self.pdf_file_button)
        self.topFrameRight.addWidget(self.pdf_file_layout)
        self.tsr_file_layout = QtWidgets.QFrame(parent=self.wrapper)
        self.tsr_file_layout.setMinimumSize(QtCore.QSize(0, 0))
        self.tsr_file_layout.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.tsr_file_layout.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.tsr_file_layout.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.tsr_file_layout.setObjectName("tsr_file_layout")
        self.logo_layout_2 = QtWidgets.QHBoxLayout(self.tsr_file_layout)
        self.logo_layout_2.setSizeConstraint(
            QtWidgets.QLayout.SizeConstraint.SetDefaultConstraint
        )
        self.logo_layout_2.setContentsMargins(0, 10, 0, 0)
        self.logo_layout_2.setObjectName("logo_layout_2")
        self.tsr_file_input = QtWidgets.QLineEdit(parent=self.tsr_file_layout)
        self.tsr_file_input.setMinimumSize(QtCore.QSize(0, 30))
        self.tsr_file_input.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.tsr_file_input.setStyleSheet("background-color: rgb(33, 37, 43);")
        self.tsr_file_input.setText("")
        self.tsr_file_input.setObjectName("tsr_file_input")
        self.logo_layout_2.addWidget(self.tsr_file_input)
        spacerItem1 = QtWidgets.QSpacerItem(
            10,
            20,
            QtWidgets.QSizePolicy.Policy.Minimum,
            QtWidgets.QSizePolicy.Policy.Minimum,
        )
        self.logo_layout_2.addItem(spacerItem1)
        self.tsr_file_button = QtWidgets.QPushButton(parent=self.tsr_file_layout)
        self.tsr_file_button.setMinimumSize(QtCore.QSize(80, 30))
        self.tsr_file_button.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.tsr_file_button.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        )
        self.tsr_file_button.setStyleSheet("background-color: rgb(52, 59, 72);")
        self.tsr_file_button.setText("")
        self.tsr_file_button.setIcon(icon2)
        self.tsr_file_button.setObjectName("tsr_file_button")
        self.logo_layout_2.addWidget(self.tsr_file_button)
        self.topFrameRight.addWidget(self.tsr_file_layout)
        self.crt_file_layout = QtWidgets.QFrame(parent=self.wrapper)
        self.crt_file_layout.setMinimumSize(QtCore.QSize(0, 0))
        self.crt_file_layout.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.crt_file_layout.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.crt_file_layout.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.crt_file_layout.setObjectName("crt_file_layout")
        self.logo_layout_3 = QtWidgets.QHBoxLayout(self.crt_file_layout)
        self.logo_layout_3.setSizeConstraint(
            QtWidgets.QLayout.SizeConstraint.SetDefaultConstraint
        )
        self.logo_layout_3.setContentsMargins(0, 10, 0, 0)
        self.logo_layout_3.setObjectName("logo_layout_3")
        self.crt_file_input = QtWidgets.QLineEdit(parent=self.crt_file_layout)
        self.crt_file_input.setMinimumSize(QtCore.QSize(0, 30))
        self.crt_file_input.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.crt_file_input.setStyleSheet("background-color: rgb(33, 37, 43);")
        self.crt_file_input.setText("")
        self.crt_file_input.setObjectName("crt_file_input")
        self.logo_layout_3.addWidget(self.crt_file_input)
        spacerItem2 = QtWidgets.QSpacerItem(
            10,
            20,
            QtWidgets.QSizePolicy.Policy.Minimum,
            QtWidgets.QSizePolicy.Policy.Minimum,
        )
        self.logo_layout_3.addItem(spacerItem2)
        self.crt_file_button = QtWidgets.QPushButton(parent=self.crt_file_layout)
        self.crt_file_button.setMinimumSize(QtCore.QSize(80, 30))
        self.crt_file_button.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.crt_file_button.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        )
        self.crt_file_button.setStyleSheet("background-color: rgb(52, 59, 72);")
        self.crt_file_button.setText("")
        self.crt_file_button.setIcon(icon2)
        self.crt_file_button.setObjectName("crt_file_button")
        self.logo_layout_3.addWidget(self.crt_file_button)
        self.topFrameRight.addWidget(self.crt_file_layout)
        self.verification_status_list_layout = QtWidgets.QVBoxLayout()
        self.verification_status_list_layout.setContentsMargins(12, 12, 12, 12)
        self.verification_status_list_layout.setSpacing(0)
        self.verification_status_list_layout.setObjectName(
            "verification_status_list_layout"
        )
        self.verification_status_list = QtWidgets.QListWidget(parent=self.wrapper)
        self.verification_status_list.setEnabled(True)
        self.verification_status_list.setStyleSheet(
            "QListWidget {\n"
            "background-color: rgb(33, 37, 43);\n"
            'font: italic 13pt "Courier New";\n'
            "}\n"
            "\n"
            "QListWidget::disabled {\n"
            "background-color: rgba(33, 37, 43, 50%);\n"
            "color: rgba(255, 255, 255, 10%);\n"
            "}\n"
            "\n"
            "QScrollBar:horizontal {\n"
            "    border: none;\n"
            "    background: rgb(52, 59, 72);\n"
            "    height: 8px;\n"
            "    margin: 0px 21px 0 21px;\n"
            "    border-radius: 0px;\n"
            "}\n"
            "QScrollBar::handle:horizontal {\n"
            "    background: rgba(255, 255, 255, 30%);\n"
            "    min-width: 25px;\n"
            "    border-radius: 4px\n"
            "}\n"
            "\n"
            "QScrollBar::handle:horizontal:disabled {\n"
            "    background: rgba(255, 255, 255, 5%);\n"
            "    min-width: 25px;\n"
            "    border-radius: 4px\n"
            "}\n"
            "QScrollBar::add-line:horizontal {\n"
            "    border: none;\n"
            "    background: rgb(55, 63, 77);\n"
            "    width: 20px;\n"
            "    border-top-right-radius: 4px;\n"
            "    border-bottom-right-radius: 4px;\n"
            "    subcontrol-position: right;\n"
            "    subcontrol-origin: margin;\n"
            "}\n"
            "QScrollBar::sub-line:horizontal {\n"
            "    border: none;\n"
            "    background: rgb(55, 63, 77);\n"
            "    width: 20px;\n"
            "    border-top-left-radius: 4px;\n"
            "    border-bottom-left-radius: 4px;\n"
            "    subcontrol-position: left;\n"
            "    subcontrol-origin: margin;\n"
            "}\n"
            "QScrollBar::up-arrow:horizontal, QScrollBar::down-arrow:horizontal\n"
            "{\n"
            "     background: none;\n"
            "}\n"
            "QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal\n"
            "{\n"
            "     background: none;\n"
            "}\n"
            " QScrollBar:vertical {\n"
            "    border: none;\n"
            "    background: rgb(52, 59, 72);\n"
            "    width: 8px;\n"
            "    margin: 21px 0 21px 0;\n"
            "    border-radius: 0px;\n"
            " }\n"
            " QScrollBar::handle:vertical {    \n"
            "    background: rgba(255, 255, 255, 30%);\n"
            "    min-height: 25px;\n"
            "    border-radius: 4px\n"
            " }\n"
            " QScrollBar::handle:vertical:disabled  {    \n"
            "    background: rgba(255, 255, 255, 5%);\n"
            "    min-height: 25px;\n"
            "    border-radius: 4px\n"
            " }\n"
            " QScrollBar::add-line:vertical {\n"
            "     border: none;\n"
            "    background: rgb(55, 63, 77);\n"
            "     height: 20px;\n"
            "    border-bottom-left-radius: 4px;\n"
            "    border-bottom-right-radius: 4px;\n"
            "     subcontrol-position: bottom;\n"
            "     subcontrol-origin: margin;\n"
            " }\n"
            " QScrollBar::sub-line:vertical {\n"
            "    border: none;\n"
            "    background: rgb(55, 63, 77);\n"
            "     height: 20px;\n"
            "    border-top-left-radius: 4px;\n"
            "    border-top-right-radius: 4px;\n"
            "     subcontrol-position: top;\n"
            "     subcontrol-origin: margin;\n"
            " }\n"
            " QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {\n"
            "     background: none;\n"
            " }\n"
            "\n"
            " QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {\n"
            "     background: none;\n"
            " }"
        )
        self.verification_status_list.setModelColumn(0)
        self.verification_status_list.setObjectName("verification_status_list")
        self.verification_status_list_layout.addWidget(self.verification_status_list)
        self.topFrameRight.addLayout(self.verification_status_list_layout)
        self.verification_button_layout = QtWidgets.QHBoxLayout()
        self.verification_button_layout.setContentsMargins(12, -1, 18, 0)
        self.verification_button_layout.setSpacing(0)
        self.verification_button_layout.setObjectName("verification_button_layout")
        spacerItem3 = QtWidgets.QSpacerItem(
            40,
            20,
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Minimum,
        )
        self.verification_button_layout.addItem(spacerItem3)
        self.verification_button = QtWidgets.QPushButton(parent=self.wrapper)
        self.verification_button.setEnabled(True)
        self.verification_button.setMinimumSize(QtCore.QSize(150, 30))
        self.verification_button.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.verification_button.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        )
        self.verification_button.setLayoutDirection(
            QtCore.Qt.LayoutDirection.LeftToRight
        )
        self.verification_button.setIconSize(QtCore.QSize(0, 0))
        self.verification_button.setObjectName("verification_button")
        self.verification_button_layout.addWidget(self.verification_button)
        self.topFrameRight.addLayout(self.verification_button_layout)
        self.horizontalLayout_4.addWidget(self.wrapper)
        self.verticalLayout_6.addWidget(self.content)
        self.bottom_bar = QtWidgets.QFrame(parent=self.content_bottom)
        self.bottom_bar.setMinimumSize(QtCore.QSize(0, 22))
        self.bottom_bar.setMaximumSize(QtCore.QSize(16777215, 22))
        self.bottom_bar.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.bottom_bar.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.bottom_bar.setObjectName("bottom_bar")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.bottom_bar)
        self.horizontalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_5.setSpacing(0)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.credits_label = QtWidgets.QLabel(parent=self.bottom_bar)
        self.credits_label.setMaximumSize(QtCore.QSize(120, 16))
        self.credits_label.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeading
            | QtCore.Qt.AlignmentFlag.AlignLeft
            | QtCore.Qt.AlignmentFlag.AlignVCenter
        )
        self.credits_label.setObjectName("credits_label")
        self.horizontalLayout_5.addWidget(self.credits_label)
        spacerItem4 = QtWidgets.QSpacerItem(
            20,
            20,
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Minimum,
        )
        self.horizontalLayout_5.addItem(spacerItem4)
        self.version = QtWidgets.QLabel(parent=self.bottom_bar)
        self.version.setMaximumSize(QtCore.QSize(120, 16777215))
        self.version.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignRight
            | QtCore.Qt.AlignmentFlag.AlignTrailing
            | QtCore.Qt.AlignmentFlag.AlignVCenter
        )
        self.version.setObjectName("version")
        self.horizontalLayout_5.addWidget(self.version)
        self.frame_size_grip = QtWidgets.QFrame(parent=self.bottom_bar)
        self.frame_size_grip.setMinimumSize(QtCore.QSize(20, 0))
        self.frame_size_grip.setMaximumSize(QtCore.QSize(20, 16777215))
        self.frame_size_grip.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.frame_size_grip.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.frame_size_grip.setObjectName("frame_size_grip")
        self.horizontalLayout_5.addWidget(self.frame_size_grip)
        self.verticalLayout_6.addWidget(self.bottom_bar)
        self.verticalLayout_2.addWidget(self.content_bottom)
        self.appLayout.addWidget(self.content_box)
        self.appMargins.addWidget(self.bg_app)
        fit_verify_pdf_timestamp.setCentralWidget(self.styleSheet)

        self.retranslateUi(fit_verify_pdf_timestamp)
        QtCore.QMetaObject.connectSlotsByName(fit_verify_pdf_timestamp)

    def retranslateUi(self, fit_verify_pdf_timestamp):
        fit_verify_pdf_timestamp.setWindowTitle("FIT Verify PDF Timestamp")
        self.translations = load_translations()
        self.title_right_info.setText(self.translations["TITLE_RIGHT_INFO"])
        self.pdf_file_input.setPlaceholderText(self.translations["PDF_FILE_INPUT"])
        self.tsr_file_input.setPlaceholderText(self.translations["TSR_FILE_INPUT"])
        self.crt_file_input.setPlaceholderText(self.translations["CRT_FILE_INPUT"])
        self.verification_button.setText(self.translations["VERIFICATION_BUTTON"])
        self.credits_label.setText("By: fit-project.org")
        self.version.setText(get_version())
