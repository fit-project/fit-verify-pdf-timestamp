#!/usr/bin/env python3
# -*- coding:utf-8 -*-
######
# -----
# Copyright (c) 2023 FIT-Project
# SPDX-License-Identifier: LGPL-3.0-or-later
# -----
######

import hashlib
import os

import rfc3161ng

from PySide6 import QtCore, QtWidgets
from PySide6.QtWidgets import QFileDialog


from fit_cases.view.case_form_dialog import CaseFormDialog
from fit_common.gui.utils import (
    show_finish_verification_dialog,
    get_verification_label_text,
    add_label_in_verification_status_list,
    VerificationTypes,
    Status,
)
from fit_common.core.utils import get_ntp_date_and_time, get_version

from fit_verify_pdf_timestamp.controller.verify_pdf_timestamp import (
    VerifyPDFTimestamp as VerifyPDFTimestampController,
)

from fit_configurations.controller.tabs.general.general import (
    General as GeneralConfigurationController,
)
from fit_configurations.controller.tabs.network.networkcheck import (
    NetworkControllerCheck,
)
from fit_configurations.controller.tabs.timestamp.timestamp import (
    Timestamp as TimestampConfigurationController,
)

from fit_verify_pdf_timestamp.view.verify_pdf_timestamp_ui import (
    Ui_fit_verify_pdf_timestamp,
)

from fit_verify_pdf_timestamp.lang import load_translations


class VerifyPDFTimestamp(QtWidgets.QMainWindow):
    def __init__(self, wizard=None):
        super(VerifyPDFTimestamp, self).__init__(wizard)
        self.acquisition_directory = None
        self.wizard = wizard

        self.translations = load_translations()

        self.__init_ui()

    def __init_ui(self):

        # HIDE STANDARD TITLE BAR
        self.setWindowFlags(QtCore.Qt.WindowType.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground)

        self.ui = Ui_fit_verify_pdf_timestamp()
        self.ui.setupUi(self)

        # CUSTOM TOP BAR
        self.ui.left_box.mouseMoveEvent = self.move_window

        # MINIMIZE BUTTON
        self.ui.minimize_button.clicked.connect(self.showMinimized)

        # CLOSE BUTTON
        self.ui.close_button.clicked.connect(self.close)

        # SET VERSION
        self.ui.version.setText(get_version())

        # PDF FILE BUTTON
        self.ui.pdf_file_button.clicked.connect(
            lambda extension: self.__select_file("pdf")
        )

        # PDF TSR BUTTON
        self.ui.tsr_file_button.clicked.connect(
            lambda extension: self.__select_file("tsr")
        )

        # PDF CRT BUTTON
        self.ui.crt_file_button.clicked.connect(
            lambda extension: self.__select_file("crt")
        )

        # VERIFICATION BUTTON
        self.ui.verification_button.clicked.connect(self.__verify)
        self.ui.verification_button.setEnabled(False)

        # DISABLE VERIFY BUTTON IF FIELDs IS EMPTY
        self.input_fields = self.ui.wrapper.findChildren(QtWidgets.QLineEdit)
        for input_field in self.input_fields:
            input_field.textChanged.connect(self.__enable_verify_button)

    def mousePressEvent(self, event):
        self.dragPos = event.globalPosition().toPoint()

    def move_window(self, event):
        if event.buttons() == QtCore.Qt.MouseButton.LeftButton:
            self.move(self.pos() + event.globalPosition().toPoint() - self.dragPos)
            self.dragPos = event.globalPosition().toPoint()
            event.accept()

    def __enable_verify_button(self):
        all_fields_filled = all(input_field.text() for input_field in self.input_fields)
        self.ui.verification_button.setEnabled(all_fields_filled)

    def __select_file(self, extension):
        # open the correct file picker based on extension
        open_folder = self.__get_cases_dir()

        if extension == "pdf":
            file, check = QFileDialog.getOpenFileName(
                None,
                self.translations["OPEN_PDF_FILE"],
                self.__get_cases_dir(),
                self.translations["PDF_FILE"],
            )
            if check:
                self.ui.pdf_file_input.setText(file)
                if self.acquisition_directory is None:
                    self.acquisition_directory = os.path.dirname(file)
        elif extension == "tsr":
            file, check = QFileDialog.getOpenFileName(
                None,
                self.translations["OPEN_TSR_FILE"],
                self.__get_cases_dir(),
                self.translations["TSR_FILE"],
            )
            if check:
                self.ui.tsr_file_input.setText(file)
                if self.acquisition_directory is None:
                    self.acquisition_directory = os.path.dirname(file)

        elif extension == "crt":
            file, check = QFileDialog.getOpenFileName(
                None,
                self.translations["OPEN_CRT_FILE"],
                self.__get_cases_dir(),
                self.translations["CRT_FILE"],
            )
            if check:
                self.ui.crt_file_input.setText(file)
                if self.acquisition_directory is None:
                    self.acquisition_directory = os.path.dirname(file)

    def __verify(self):
        self.ui.verification_status_list.clear()

        certificate = open(self.ui.crt_file_input.text(), "rb").read()
        pdf_file = self.ui.pdf_file_input.text()
        timestamp = open(self.ui.tsr_file_input.text(), "rb").read()
        server_name = TimestampConfigurationController().options.get("server_name")

        verification_status, remote_timestamper = self.__check_remote_timestamper(
            certificate, server_name
        )
        if verification_status == Status.SUCCESS and remote_timestamper is not None:
            verification_status, verified = self.__verify_timestamp(
                remote_timestamper, timestamp, pdf_file
            )

            if verification_status == Status.SUCCESS:
                verification_status, info_file_path = (
                    self.__generate_file_timestamp_info(
                        pdf_file, server_name, timestamp, verified
                    )
                )
                if verification_status == Status.SUCCESS:
                    if (
                        self.__generate_report(info_file_path, verified)
                        == Status.SUCCESS
                    ):
                        show_finish_verification_dialog(
                            self.acquisition_directory, VerificationTypes.TIMESTAMP
                        )
                else:
                    label = "INFO: {}".format(
                        self.translations["GENERATE_FILE_TIMESTAMP_INFO_FAIL"]
                    )
                    add_label_in_verification_status_list(
                        self.ui.verification_status_list, label
                    )
            else:
                label = "INFO: {}".format(self.translations["VERIFY_TIMESTAMP_FAIL"])
                add_label_in_verification_status_list(
                    self.ui.verification_status_list, label
                )
        else:
            label = "INFO: {}".format(self.translations["CHECK_TIMESTAMP_SERVER_FAIL"])
            add_label_in_verification_status_list(
                self.ui.verification_status_list, label
            )

    def __check_remote_timestamper(self, certificate, server_name):

        remote_timestamper = None
        verification_status = Status.SUCCESS
        verification_name = self.translations["CHECK_TIMESTAMP_SERVER"].format(
            server_name
        )
        verification_message = ""

        try:
            remote_timestamper = rfc3161ng.RemoteTimestamper(
                server_name, certificate=certificate, hashname="sha256"
            )
        except Exception as e:
            verification_status = Status.FAIL
            verification_message = str(e)

        label = get_verification_label_text(
            verification_name, verification_status, verification_message
        )

        add_label_in_verification_status_list(self.ui.verification_status_list, label)

        return verification_status, remote_timestamper

    def __verify_timestamp(self, remote_timestamper, timestamp, pdf_file):
        verified = False
        verification_status = Status.SUCCESS
        verification_name = self.translations["VERIFY_TIMESTAMP"]
        verification_message = ""

        try:
            verified = remote_timestamper.check(
                timestamp, data=open(pdf_file, "rb").read()
            )
        except Exception as e:
            verification_status = Status.FAIL
            verification_message = str(e)

        label = get_verification_label_text(
            verification_name, verification_status, verification_message
        )

        add_label_in_verification_status_list(self.ui.verification_status_list, label)

        return verification_status, verified

    def __generate_file_timestamp_info(self, data, server_name, timestamp, check):

        verification_status = Status.SUCCESS
        verification_name = self.translations["GENERATE_FILE_TIMESTAMP_INFO"]
        verification_message = ""

        try:
            if check:
                verification = self.translations["VALID_TIMESTAMP"]
            else:
                verification = self.translations["INVALID_TIMESTAMP"]

            # calculate hash (as in rfc lib)
            hashobj = hashlib.new("sha256")
            hashobj.update(open(data, "rb").read())
            digest = hashobj.hexdigest()

            # get date from tsr file
            timestamp_datetime = rfc3161ng.get_timestamp(timestamp)

            info_file_path = os.path.join(
                self.acquisition_directory, "timestamp_info.txt"
            )
            with open(info_file_path, "w") as file:
                file.write(
                    "======================================================================\n"
                )
                file.write(f"{self.translations['REPORT_LABEL_RESULT']}\n")
                file.write(f"{verification}\n")
                file.write(
                    "======================================================================\n"
                )
                file.write(f"{self.translations['REPORT_LABEL_FILENAME']}\n")
                file.write(f"{os.path.basename(self.ui.pdf_file_input.text())}\n")
                file.write(
                    "======================================================================\n"
                )
                file.write(f"{self.translations['REPORT_LABEL_SIZE']}\n")
                file.write(f"{os.path.getsize(self.ui.pdf_file_input.text())} bytes\n")
                file.write(
                    "======================================================================\n"
                )
                file.write(f"{self.translations['REPORT_LABEL_HASH_ALGORITHM']}\n")
                file.write(f"{self.translations['REPORT_LABEL_SHA256']}\n")
                file.write(
                    "======================================================================\n"
                )
                file.write(f"{self.translations['REPORT_LABEL_DIGEST']}\n")
                file.write(f"{digest}\n")
                file.write(
                    "======================================================================\n"
                )
                file.write(f"{self.translations['REPORT_LABEL_TIMESTAMP']}\n")
                file.write(f"{str(timestamp_datetime)}\n")
                file.write(
                    "======================================================================\n"
                )
                file.write(f"{self.translations['REPORT_LABEL_SERVER']}\n")
                file.write(f"{server_name}\n")
                file.write(
                    "======================================================================\n"
                )
        except Exception as e:
            verification_status = Status.FAIL
            verification_message = str(e)

        label = get_verification_label_text(
            verification_name, verification_status, verification_message
        )

        add_label_in_verification_status_list(self.ui.verification_status_list, label)

        return verification_status, info_file_path

    def __generate_report(self, info_file_path, result):

        ntp = get_ntp_date_and_time(
            NetworkControllerCheck().configuration["ntp_server"]
        )
        case_info = CaseFormDialog().get_case_info(self.acquisition_directory)

        verification_status = Status.SUCCESS
        verification_name = self.translations["GENARATE_REPORT"]
        verification_message = ""

        try:
            report = VerifyPDFTimestampController(
                self.acquisition_directory, case_info, ntp
            )
            report.generate_pdf(result, info_file_path)
        except Exception as e:
            verification_status = Status.FAIL
            verification_message = str(e)

        label = get_verification_label_text(
            verification_name, verification_status, verification_message
        )

        add_label_in_verification_status_list(self.ui.verification_status_list, label)

        return verification_status

    def __get_cases_dir(self):
        if self.acquisition_directory is None:
            return os.path.expanduser(
                GeneralConfigurationController().configuration.get("cases_folder_path")
            )
        else:
            return self.acquisition_directory

    def __back_to_wizard(self):
        self.deleteLater()
        self.wizard.reload_case_info()
        self.wizard.show()

    def closeEvent(self, event):
        if self.wizard is not None:
            event.ignore()
            self.__back_to_wizard()
