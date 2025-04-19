#!/usr/bin/env python3
# -*- coding:utf-8 -*-
######
# -----
# Copyright (c) 2023 FIT-Project
# SPDX-License-Identifier: LGPL-3.0-or-later
# -----
######

import base64
import os

from jinja2 import Template
from importlib.resources import files

from xhtml2pdf import pisa
from PyPDF2 import PdfMerger


from fit_configurations.controller.tabs.general.typesproceedings import (
    TypesProceedings as TypesProceedingsController,
)

from fit_common.core.utils import get_version
from fit_configurations.utils import get_language
from fit_verify_pdf_timestamp.lang import load_translations


class VerifyPDFTimestamp:
    def __init__(self, cases_folder_path, case_info, ntp):
        self.cases_folder_path = cases_folder_path
        self.output_front = os.path.join(self.cases_folder_path, "front_report.pdf")
        self.output_content = os.path.join(self.cases_folder_path, "content_report.pdf")
        self.output_front_result = open(self.output_front, "w+b")
        self.output_content_result = open(self.output_content, "w+b")
        self.case_info = case_info
        self.ntp = ntp

        language = get_language()

        if language == "Italian":
            self.translations = load_translations(lang="it")
        else:
            self.translations = load_translations()

    def generate_pdf(self, result, info_file_path):
        # PREPARING DATA TO FILL THE PDF
        with open(info_file_path, "r") as f:
            info_file = f.read()

        # FILLING FRONT PAGE WITH DATA
        template = Template(
            (files("fit_assets.templates") / "front.html").read_text(encoding="utf-8")
        )

        logo_path = files("fit_assets.images") / "logo-640x640.png"
        logo_bytes = logo_path.read_bytes()
        logo_base64 = base64.b64encode(logo_bytes).decode("utf-8")

        front_index = template.render(
            img=f"data:image/png;base64,{logo_base64}",
            t1=self.translations["T1"],
            title=self.translations["TITLE"],
            report=self.translations["REPORT"],
            version=get_version(),
        )

        proceeding_type = TypesProceedingsController().get_proceeding_name_by_id(
            self.case_info.get("proceeding_type", 0)
        )

        logo = self.case_info.get("logo_bin", "")
        if logo is not None:
            logo = (
                '<div style="padding-bottom: 10px;"><img src="data:image/png;base64,'
                + base64.b64encode(logo).decode("utf-8")
                + '" height="'
                + self.case_info.get("logo_height", "")
                + '" width="'
                + self.case_info.get("logo_width", "")
                + '"></div>'
            )
        else:
            logo = "<div></div>"

        t3descr = (
            self.translations["VERIFI_OK"] if result else self.translations["VERIFI_KO"]
        )

        template = Template(
            (files("fit_assets.templates") / "template_verification.html").read_text(
                encoding="utf-8"
            )
        )
        content_index = template.render(
            title=self.translations["TITLE"],
            index=self.translations["INDEX"],
            description=self.translations["DESCRIPTION"],
            t1=self.translations["T1"],
            t2=self.translations["T2"],
            case=self.translations["CASEINFO"],
            casedata=self.translations["CASEDATA"],
            case0=self.translations["CASE"],
            case1=self.translations["LAWYER"],
            case2=self.translations["OPERATOR"],
            case3=self.translations["PROCEEDING"],
            case4=self.translations["COURT"],
            case5=self.translations["NUMBER"],
            case6=self.translations["ACQUISITION_TYPE"],
            case7=self.translations["ACQUISITION_DATE"],
            case8=self.translations["NOTES"],
            t3=self.translations["VERIFICATION"],
            t3descr=t3descr,
            info_file=info_file,
            data0=str(self.case_info["name"] or "N/A"),
            data1=str(self.case_info["lawyer_name"] or "N/A"),
            data2=str(self.case_info["operator"] or "N/A"),
            data3=proceeding_type,
            data4=str(self.case_info["courthouse"] or "N/A"),
            data5=str(self.case_info["proceeding_number"] or "N/A"),
            data6=self.translations["VERIFICATION"],
            data7=self.ntp,
            data8=str(self.case_info["notes"] or "N/A").replace("\n", "<br>"),
            page=self.translations["PAGE"],
            of=self.translations["OF"],
            logo=logo,
        )

        # Create PDF front and content, merge them and remove merged files
        pisa.CreatePDF(front_index, dest=self.output_front_result)
        pisa.CreatePDF(content_index, dest=self.output_content_result)
        merger = PdfMerger()
        merger.append(self.output_front_result)
        merger.append(self.output_content_result)

        report_html = os.path.join(
            self.cases_folder_path, "report_timestamp_verification.pdf"
        )
        merger.write(report_html)
        merger.close()

        self.output_content_result.close()
        self.output_front_result.close()
        if os.path.exists(self.output_front):
            os.remove(self.output_front)
        if os.path.exists(self.output_content):
            os.remove(self.output_content)
        if os.path.exists(info_file_path):
            os.remove(info_file_path)
