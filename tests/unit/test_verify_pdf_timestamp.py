from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6 import QtWidgets


@pytest.fixture
def verify_module(stub_external_modules):
    return importlib.reload(
        importlib.import_module("fit_verify_pdf_timestamp.view.verify_pdf_timestamp")
    )


@pytest.fixture
def window_stub(
    qapp, verify_module, monkeypatch: pytest.MonkeyPatch
):
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

    monkeypatch.setattr(verify_module.VerifyPDFTimestamp, "_VerifyPDFTimestamp__init_ui", fake_init_ui)
    monkeypatch.setattr(
        verify_module,
        "load_translations",
        lambda *args, **kwargs: {
            "OPEN_PDF_FILE": "Open PDF",
            "PDF_FILE": "PDF (*.pdf)",
            "OPEN_TSR_FILE": "Open TSR",
            "TSR_FILE": "TSR (*.tsr)",
            "OPEN_CRT_FILE": "Open CRT",
            "CRT_FILE": "CRT (*.crt)",
            "CHECK_TIMESTAMP_SERVER": "Check {}",
            "VERIFY_TIMESTAMP": "Verify timestamp",
            "GENERATE_FILE_TIMESTAMP_INFO": "Generate timestamp info",
            "GENARATE_REPORT": "Generate report",
            "VALID_TIMESTAMP": "Valid",
            "INVALID_TIMESTAMP": "Invalid",
            "CHECK_TIMESTAMP_SERVER_FAIL": "timestamp server failed",
            "VERIFY_TIMESTAMP_FAIL": "verify failed",
            "GENERATE_FILE_TIMESTAMP_INFO_FAIL": "info failed",
            "REPORT_LABEL_RESULT": "Result",
            "REPORT_LABEL_FILENAME": "Filename",
            "REPORT_LABEL_SIZE": "Size",
            "REPORT_LABEL_HASH_ALGORITHM": "Hash",
            "REPORT_LABEL_SHA256": "SHA256",
            "REPORT_LABEL_DIGEST": "Digest",
            "REPORT_LABEL_TIMESTAMP": "Timestamp",
            "REPORT_LABEL_SERVER": "Server",
        },
    )

    return verify_module.VerifyPDFTimestamp()


@pytest.mark.unit
def test_enable_verify_button_depends_on_all_fields(
    window_stub,
) -> None:
    window = window_stub

    window.ui.pdf_file_input.setText("/tmp/file.pdf")
    window.ui.tsr_file_input.setText("/tmp/file.tsr")
    window._VerifyPDFTimestamp__enable_verify_button()
    assert window.ui.verification_button.isEnabled() is False

    window.ui.crt_file_input.setText("/tmp/file.crt")
    window._VerifyPDFTimestamp__enable_verify_button()
    assert window.ui.verification_button.isEnabled() is True


@pytest.mark.unit
def test_get_cases_dir_uses_configuration_when_acquisition_is_missing(
    window_stub, verify_module
) -> None:
    window = window_stub
    window.acquisition_directory = None

    cases_dir = window._VerifyPDFTimestamp__get_cases_dir()

    assert cases_dir == str(Path("~/cases").expanduser())

    window.acquisition_directory = "/tmp/acquisition"
    assert window._VerifyPDFTimestamp__get_cases_dir() == "/tmp/acquisition"


@pytest.mark.unit
def test_select_file_populates_pdf_field_and_acquisition_directory(
    window_stub, verify_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = window_stub
    monkeypatch.setattr(
        verify_module.QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: ("/tmp/demo.pdf", True),
    )

    window._VerifyPDFTimestamp__select_file("pdf")

    assert window.ui.pdf_file_input.text() == "/tmp/demo.pdf"
    assert window.acquisition_directory == "/tmp"


@pytest.mark.unit
def test_check_remote_timestamper_success(
    window_stub,
) -> None:
    window = window_stub

    status, timestamper = window._VerifyPDFTimestamp__check_remote_timestamper(
        b"cert", "https://tsa.example"
    )

    assert status == "SUCCESS"
    assert timestamper is not None
    assert window.ui.verification_status_list.count() == 1


@pytest.mark.unit
def test_verify_timestamp_failure_adds_label(
    window_stub, verify_module
) -> None:
    window = window_stub

    class _RemoteFail:
        def check(self, _timestamp, data):
            raise RuntimeError(f"invalid data: {len(data)}")

    pdf_path = Path("/tmp/fake.pdf")
    pdf_path.write_bytes(b"pdf")

    status, verified = window._VerifyPDFTimestamp__verify_timestamp(
        _RemoteFail(), b"tsr", str(pdf_path)
    )

    assert status == verify_module.Status.FAILURE
    assert verified is False
    assert window.ui.verification_status_list.count() == 1


@pytest.mark.unit
def test_generate_file_timestamp_info_creates_output_file(
    window_stub, verify_module, tmp_path: Path
) -> None:
    window = window_stub
    window.acquisition_directory = str(tmp_path)
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(b"pdf-data")
    window.ui.pdf_file_input.setText(str(pdf_path))

    status, info_path = window._VerifyPDFTimestamp__generate_file_timestamp_info(
        str(pdf_path),
        "https://tsa.example",
        b"tsr-data",
        True,
    )

    assert status == verify_module.Status.SUCCESS
    assert Path(info_path).is_file()
    text = Path(info_path).read_text(encoding="utf-8")
    assert "Valid" in text
    assert "sample.pdf" in text


@pytest.mark.unit
def test_generate_report_uses_pdf_builder(
    window_stub, verify_module, stub_external_modules, tmp_path: Path
) -> None:
    window = window_stub
    window.acquisition_directory = str(tmp_path)
    info_path = tmp_path / "timestamp_info.txt"
    info_path.write_text("ok", encoding="utf-8")

    status = window._VerifyPDFTimestamp__generate_report(str(info_path), True)

    assert status == verify_module.Status.SUCCESS
    builder = stub_external_modules["PdfReportBuilder"].instances[-1]
    assert builder.generated is True
    assert builder.verify_info_file_path == str(info_path)
    assert builder.verify_result is True
