from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest
from PySide6 import QtWidgets


def _add_local_venv_site_packages() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    py_version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_packages = repo_root / ".venv" / "lib" / py_version / "site-packages"
    if site_packages.exists():
        sys.path.append(str(site_packages))


_add_local_venv_site_packages()


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool:
    markexpr = (config.option.markexpr or "").strip()
    if markexpr != "unit":
        return False

    normalized = collection_path.as_posix().rstrip("/")
    if normalized.endswith("tests") or normalized.endswith("tests/unit"):
        return False
    return "tests/unit/" not in normalized


@pytest.fixture(scope="session")
def qapp() -> QtWidgets.QApplication:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QtWidgets.QApplication.instance()
    if app is None:
        app = QtWidgets.QApplication([])
    return app


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    known = {"unit", "contract", "integration", "e2e"}
    for item in items:
        if any(item.get_closest_marker(name) for name in known):
            continue
        item.add_marker(pytest.mark.integration)


def _ensure_package(monkeypatch: pytest.MonkeyPatch, name: str) -> types.ModuleType:
    current = sys.modules.get(name)
    if current is not None:
        return current

    package = types.ModuleType(name)
    package.__path__ = []
    monkeypatch.setitem(sys.modules, name, package)

    parent_name, _, child = name.rpartition(".")
    if parent_name:
        parent = _ensure_package(monkeypatch, parent_name)
        setattr(parent, child, package)

    return package


def _register_module(
    monkeypatch: pytest.MonkeyPatch, name: str, module: types.ModuleType
) -> None:
    parent_name, _, child = name.rpartition(".")
    if parent_name:
        parent = _ensure_package(monkeypatch, parent_name)
        setattr(parent, child, module)
    monkeypatch.setitem(sys.modules, name, module)


@pytest.fixture
def stub_external_modules(monkeypatch: pytest.MonkeyPatch):
    class Status:
        SUCCESS = "SUCCESS"
        FAIL = "FAIL"
        FAILURE = "FAILURE"

    class VerificationTypes:
        TIMESTAMP = "timestamp"

    def add_label_in_verification_status_list(widget, label: str) -> None:
        widget.addItem(label)

    def get_verification_label_text(name: str, status: str, message: str) -> str:
        suffix = f" ({message})" if message else ""
        return f"{name}: {status}{suffix}"

    finish_calls: list[tuple[str | None, str]] = []

    def show_finish_verification_dialog(path: str | None, verification_type: str) -> None:
        finish_calls.append((path, verification_type))

    core_module = types.ModuleType("fit_common.core")
    core_module.DEFAULT_LANG = "en"
    core_module.get_system_lang = lambda: "en"
    core_module.get_version = lambda: "9.9.9"
    _register_module(monkeypatch, "fit_common.core", core_module)

    report_module = types.ModuleType("fit_common.core.pdf_report_builder")

    class ReportType:
        VERIFY = "verify"

    class PdfReportBuilder:
        instances: list["PdfReportBuilder"] = []

        def __init__(self, report_type, translations, path, filename, case_info):
            self.report_type = report_type
            self.translations = translations
            self.path = path
            self.filename = filename
            self.case_info = case_info
            self.ntp = None
            self.verify_info_file_path = None
            self.verify_result = None
            self.generated = False
            PdfReportBuilder.instances.append(self)

        def generate_pdf(self) -> None:
            self.generated = True

    report_module.PdfReportBuilder = PdfReportBuilder
    report_module.ReportType = ReportType
    _register_module(monkeypatch, "fit_common.core.pdf_report_builder", report_module)

    utils_core_module = types.ModuleType("fit_common.core.utils")
    utils_core_module.get_ntp_date_and_time = lambda _server: "2026-01-01T00:00:00"
    _register_module(monkeypatch, "fit_common.core.utils", utils_core_module)

    ui_translation_module = types.ModuleType("fit_common.gui.ui_translation")
    ui_translation_module.translate_ui = lambda _translations, _widget: None
    _register_module(monkeypatch, "fit_common.gui.ui_translation", ui_translation_module)

    gui_utils_module = types.ModuleType("fit_common.gui.utils")
    gui_utils_module.Status = Status
    gui_utils_module.VerificationTypes = VerificationTypes
    gui_utils_module.add_label_in_verification_status_list = (
        add_label_in_verification_status_list
    )
    gui_utils_module.get_verification_label_text = get_verification_label_text
    gui_utils_module.show_finish_verification_dialog = show_finish_verification_dialog
    _register_module(monkeypatch, "fit_common.gui.utils", gui_utils_module)

    case_form_module = types.ModuleType("fit_cases.view.case_form_dialog")

    class CaseFormDialog:
        def get_case_info(self, _acquisition_directory):
            return {"proceeding_type": 1, "name": "Case A"}

    case_form_module.CaseFormDialog = CaseFormDialog
    _register_module(monkeypatch, "fit_cases.view.case_form_dialog", case_form_module)

    general_module = types.ModuleType(
        "fit_configurations.controller.tabs.general.general"
    )

    class GeneralController:
        def __init__(self):
            self.configuration = {"cases_folder_path": "~/cases"}

    general_module.GeneralController = GeneralController
    _register_module(
        monkeypatch,
        "fit_configurations.controller.tabs.general.general",
        general_module,
    )

    legal_module = types.ModuleType(
        "fit_configurations.controller.tabs.general.legal_proceeding_type"
    )

    class LegalProceedingTypeController:
        def get_proceeding_name_by_id(self, _proceeding_id):
            return "Civil"

    legal_module.LegalProceedingTypeController = LegalProceedingTypeController
    _register_module(
        monkeypatch,
        "fit_configurations.controller.tabs.general.legal_proceeding_type",
        legal_module,
    )

    network_module = types.ModuleType(
        "fit_configurations.controller.tabs.network.network_check"
    )

    class NetworkCheckController:
        def __init__(self):
            self.configuration = {"ntp_server": "pool.ntp.org"}

    network_module.NetworkCheckController = NetworkCheckController
    _register_module(
        monkeypatch,
        "fit_configurations.controller.tabs.network.network_check",
        network_module,
    )

    timestamp_module = types.ModuleType(
        "fit_configurations.controller.tabs.timestamp.timestamp"
    )

    class TimestampController:
        def __init__(self):
            self.configuration = {"server_name": "https://tsa.example"}

    timestamp_module.TimestampController = TimestampController
    _register_module(
        monkeypatch,
        "fit_configurations.controller.tabs.timestamp.timestamp",
        timestamp_module,
    )

    config_utils_module = types.ModuleType("fit_configurations.utils")
    config_utils_module.get_language = lambda: "English"
    _register_module(monkeypatch, "fit_configurations.utils", config_utils_module)

    rfc_module = types.ModuleType("rfc3161ng")

    class RemoteTimestamper:
        def __init__(self, server_name, certificate, hashname="sha256"):
            self.server_name = server_name
            self.certificate = certificate
            self.hashname = hashname

        def check(self, _timestamp, data):
            return bool(data)

    rfc_module.RemoteTimestamper = RemoteTimestamper
    rfc_module.get_timestamp = lambda _timestamp: "2026-01-01 00:00:00"
    _register_module(monkeypatch, "rfc3161ng", rfc_module)

    return {
        "Status": Status,
        "VerificationTypes": VerificationTypes,
        "PdfReportBuilder": PdfReportBuilder,
        "finish_calls": finish_calls,
    }
