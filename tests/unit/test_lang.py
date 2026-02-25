from __future__ import annotations

import importlib

import pytest


@pytest.mark.unit
def test_load_translations_uses_selected_language(
    stub_external_modules,
) -> None:
    lang_module = importlib.reload(importlib.import_module("fit_verify_pdf_timestamp.lang"))

    translations = lang_module.load_translations("it")
    assert translations["OPEN_PDF_FILE"] == "Apri PDF"


@pytest.mark.unit
def test_load_translations_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch, stub_external_modules
) -> None:
    lang_module = importlib.reload(importlib.import_module("fit_verify_pdf_timestamp.lang"))

    monkeypatch.setattr(lang_module, "DEFAULT_LANG", "en")
    translations = lang_module.load_translations("zz")

    assert translations["OPEN_PDF_FILE"] == "Open PDF"


@pytest.mark.unit
def test_load_translations_uses_system_language_when_missing(
    monkeypatch: pytest.MonkeyPatch, stub_external_modules
) -> None:
    lang_module = importlib.reload(importlib.import_module("fit_verify_pdf_timestamp.lang"))

    monkeypatch.setattr(lang_module, "get_system_lang", lambda: "it")
    translations = lang_module.load_translations()

    assert translations["VALID_TIMESTAMP"] == "Il PDF contiene un timestamp valido."
