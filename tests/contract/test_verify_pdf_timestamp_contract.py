from __future__ import annotations

import importlib
import inspect
import json
from pathlib import Path

import pytest


@pytest.mark.contract
def test_verify_pdf_timestamp_exposes_expected_api(stub_external_modules) -> None:
    module = importlib.reload(
        importlib.import_module("fit_verify_pdf_timestamp.view.verify_pdf_timestamp")
    )
    cls = module.VerifyPDFTimestamp

    assert callable(getattr(cls, "closeEvent", None))
    assert callable(getattr(cls, "move_window", None))
    assert callable(getattr(cls, "mousePressEvent", None))
    assert callable(getattr(cls, "_VerifyPDFTimestamp__verify", None))
    assert callable(getattr(cls, "_VerifyPDFTimestamp__generate_report", None))


@pytest.mark.contract
def test_verify_pdf_timestamp_constructor_accepts_optional_wizard(
    stub_external_modules,
) -> None:
    module = importlib.reload(
        importlib.import_module("fit_verify_pdf_timestamp.view.verify_pdf_timestamp")
    )
    signature = inspect.signature(module.VerifyPDFTimestamp.__init__)

    assert "wizard" in signature.parameters
    assert signature.parameters["wizard"].default is None


@pytest.mark.contract
def test_language_files_define_keys_used_by_verifier() -> None:
    lang_dir = Path(__file__).resolve().parents[2] / "fit_verify_pdf_timestamp" / "lang"
    en = json.loads((lang_dir / "en.json").read_text(encoding="utf-8"))
    it = json.loads((lang_dir / "it.json").read_text(encoding="utf-8"))

    required_keys = {
        "CHECK_TIMESTAMP_SERVER",
        "CHECK_TIMESTAMP_SERVER_FAIL",
        "CRT_FILE",
        "GENARATE_REPORT",
        "GENERATE_FILE_TIMESTAMP_INFO",
        "GENERATE_FILE_TIMESTAMP_INFO_FAIL",
        "INVALID_TIMESTAMP",
        "OPEN_CRT_FILE",
        "OPEN_PDF_FILE",
        "OPEN_TSR_FILE",
        "PDF_FILE",
        "REPORT_LABEL_DIGEST",
        "REPORT_LABEL_FILENAME",
        "REPORT_LABEL_HASH_ALGORITHM",
        "REPORT_LABEL_RESULT",
        "REPORT_LABEL_SERVER",
        "REPORT_LABEL_SHA256",
        "REPORT_LABEL_SIZE",
        "REPORT_LABEL_TIMESTAMP",
        "TSR_FILE",
        "VALID_TIMESTAMP",
        "VERIFY_TIMESTAMP",
        "VERIFY_TIMESTAMP_FAIL",
    }

    assert required_keys.issubset(en.keys())
    assert required_keys.issubset(it.keys())
