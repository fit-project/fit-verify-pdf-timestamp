from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6 import QtWidgets


@pytest.mark.integration
def test_verification_flow_smoke(
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

    monkeypatch.setattr(module.VerifyPDFTimestamp, "_VerifyPDFTimestamp__init_ui", fake_init_ui)

    window = module.VerifyPDFTimestamp()
    window.acquisition_directory = str(tmp_path)

    pdf_path = tmp_path / "doc.pdf"
    tsr_path = tmp_path / "doc.tsr"
    crt_path = tmp_path / "doc.crt"
    pdf_path.write_bytes(b"pdf body")
    tsr_path.write_bytes(b"timestamp")
    crt_path.write_bytes(b"certificate")

    window.ui.pdf_file_input.setText(str(pdf_path))
    window.ui.tsr_file_input.setText(str(tsr_path))
    window.ui.crt_file_input.setText(str(crt_path))

    window._VerifyPDFTimestamp__verify()

    assert window.ui.verification_status_list.count() == 4
    assert (tmp_path / "timestamp_info.txt").is_file()
    assert len(stub_external_modules["finish_calls"]) == 1
