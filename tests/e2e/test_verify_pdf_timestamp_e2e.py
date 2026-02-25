from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6 import QtWidgets


@pytest.mark.e2e
def test_verify_pdf_timestamp_happy_path_e2e(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    stub_external_modules,
    tmp_path: Path,
) -> None:
    module = importlib.reload(
        importlib.import_module("fit_verify_pdf_timestamp.view.verify_pdf_timestamp")
    )

    def fake_init_ui(self):
        self.ui = SimpleNamespace(
            pdf_file_input=QtWidgets.QLineEdit(),
            tsr_file_input=QtWidgets.QLineEdit(),
            crt_file_input=QtWidgets.QLineEdit(),
            verification_button=QtWidgets.QPushButton(),
            verification_status_list=QtWidgets.QListWidget(),
        )
        self.input_fields = [
            self.ui.pdf_file_input,
            self.ui.tsr_file_input,
            self.ui.crt_file_input,
        ]
        self.ui.verification_button.setEnabled(False)

    monkeypatch.setattr(module.VerifyPDFTimestamp, "_VerifyPDFTimestamp__init_ui", fake_init_ui)

    window = module.VerifyPDFTimestamp()
    window.acquisition_directory = str(tmp_path)

    pdf_path = tmp_path / "e2e.pdf"
    tsr_path = tmp_path / "e2e.tsr"
    crt_path = tmp_path / "e2e.crt"
    pdf_path.write_bytes(b"pdf")
    tsr_path.write_bytes(b"tsr")
    crt_path.write_bytes(b"crt")

    selected = [
        (str(pdf_path), True),
        (str(tsr_path), True),
        (str(crt_path), True),
    ]

    monkeypatch.setattr(
        module.QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: selected.pop(0),
    )

    window._VerifyPDFTimestamp__select_file("pdf")
    window._VerifyPDFTimestamp__select_file("tsr")
    window._VerifyPDFTimestamp__select_file("crt")
    window._VerifyPDFTimestamp__enable_verify_button()

    assert window.ui.verification_button.isEnabled() is True

    window._VerifyPDFTimestamp__verify()

    assert window.ui.verification_status_list.count() == 4
    assert (tmp_path / "timestamp_info.txt").exists()
    assert len(stub_external_modules["finish_calls"]) == 1
