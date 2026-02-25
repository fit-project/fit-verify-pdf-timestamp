from __future__ import annotations

import importlib

import pytest


@pytest.mark.unit
def test_main_shows_window_and_exits_with_app_code(
    monkeypatch: pytest.MonkeyPatch, stub_external_modules
) -> None:
    import main as main_module

    importlib.reload(main_module)

    class _AppFake:
        def exec(self) -> int:
            return 7

    class _WindowFake:
        def __init__(self) -> None:
            self.show_calls = 0

        def show(self) -> None:
            self.show_calls += 1

    window = _WindowFake()
    monkeypatch.setattr(main_module, "QApplication", lambda _argv: _AppFake())
    monkeypatch.setattr(main_module, "VerifyPDFTimestamp", lambda: window)

    captured = {"code": None}

    def fake_exit(code: int) -> None:
        captured["code"] = code
        raise SystemExit(code)

    monkeypatch.setattr(main_module.sys, "exit", fake_exit)

    with pytest.raises(SystemExit):
        main_module.main()

    assert window.show_calls == 1
    assert captured["code"] == 7
