"""
test_gui_notifications.py
---------------------------
Covers _notify_desktop's on_click parameter threading - whether it's
passed through to the platform-specific notifier, and that platforms
without a click-callback mechanism (macOS, Linux) simply ignore it
rather than erroring. The Windows path's actual click detection lives
inside pywin32 APIs that don't exist on this (Linux) test environment,
so that logic is verified separately via manual smoke testing on a real
Windows machine - see gui.py's _notify_windows docstring for why macOS/
Linux can't support this at all without a new dependency.

Run with:  python3 -m pytest test_gui_notifications.py -v
"""

import gui


def test_notify_desktop_passes_on_click_through_on_windows(monkeypatch):
    monkeypatch.setattr(gui.platform, "system", lambda: "Windows")
    calls = []
    monkeypatch.setattr(
        gui, "_notify_windows", lambda title, message, on_click=None: calls.append(on_click)
    )

    sentinel = lambda: None  # noqa: E731
    gui._notify_desktop("title", "message", on_click=sentinel)

    assert calls == [sentinel]


def test_notify_desktop_ignores_on_click_on_macos(monkeypatch):
    monkeypatch.setattr(gui.platform, "system", lambda: "Darwin")
    calls = []
    monkeypatch.setattr(
        gui.subprocess, "run", lambda *a, **k: calls.append((a, k))
    )

    clicked = []
    gui._notify_desktop("title", "message", on_click=lambda: clicked.append(True))

    assert len(calls) == 1  # osascript was still invoked normally
    assert clicked == [], "macOS has no click-callback mechanism - on_click must never fire"


def test_notify_desktop_ignores_on_click_on_linux(monkeypatch):
    monkeypatch.setattr(gui.platform, "system", lambda: "Linux")
    monkeypatch.setattr(gui.shutil, "which", lambda name: "/usr/bin/notify-send")
    calls = []
    monkeypatch.setattr(
        gui.subprocess, "run", lambda *a, **k: calls.append((a, k))
    )

    clicked = []
    gui._notify_desktop("title", "message", on_click=lambda: clicked.append(True))

    assert len(calls) == 1  # notify-send was still invoked normally
    assert clicked == [], "notify-send is fire-and-forget - on_click must never fire"


def test_notify_desktop_swallows_errors_even_with_on_click(monkeypatch):
    """A crash in the platform-specific notifier must never propagate -
    this is a nice-to-have, not allowed to take the chat session down."""
    monkeypatch.setattr(gui.platform, "system", lambda: "Darwin")

    def _boom(*a, **k):
        raise OSError("no display")

    monkeypatch.setattr(gui.subprocess, "run", _boom)

    gui._notify_desktop("title", "message", on_click=lambda: None)  # must not raise
