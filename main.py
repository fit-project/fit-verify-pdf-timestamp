#!/usr/bin/env python3
# -*- coding:utf-8 -*-
######
# -----
# Copyright (c) 2023 FIT-Project
# SPDX-License-Identifier: LGPL-3.0-or-later
# -----
######

from PySide6.QtWidgets import QApplication
import sys

from fit_verify_pdf_timestamp.view.verify_pdf_timestamp import VerifyPDFTimestamp


def main():
    app = QApplication(sys.argv)
    window = VerifyPDFTimestamp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
