"""
test_gui_notifications.py
---------------------------
Covers _notify_desktop's on_click parameter threading - whether it's
passed through to the platform-specific notifier, and that platforms
without a click-callback mechanism (macOS, Linux) simply ignore it
rather than erroring - plus _win_notify_wndproc's dispatch logic, which
IS pure Python and testable without pywin32 (only the surrounding
RegisterClass/CreateWindow/Shell_NotifyIcon calls in _notify_windows
itself need real pywin32 APIs that don't exist on this Linux test
environment - that part is reviewed by hand and via manual smoke
testing on a real Windows machine instead).

Run with:  python3 -m pytest test_gui_notifications.py -v
"""

import sys

import gui


class _FakeWin32Con:
    """Just enough of win32con's surface for _win_notify_wndproc: the two
    constants it reads. Installed into sys.modules so the function's own
    `import win32con` picks this up instead of failing outright."""

    WM_LBUTTONUP = 0x0202
    WM_USER = 0x0400


def _install_fake_win32con(monkeypatch):
    monkeypatch.setitem(sys.modules, "win32con", _FakeWin32Con())


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


# -- _win_notify_wndproc: per-hwnd dispatch (Win32's RegisterClass is -----
# -- process-global, so this must not be closure/call-bound state) -------


def test_win_notify_wndproc_updates_only_the_matching_hwnds_state(monkeypatch):
    """Regression test: a Win32 window class's procedure is registered
    once for the whole process - RegisterClass() on an already-
    registered class name fails, and the class's ORIGINAL procedure
    keeps handling every window later created with that class, including
    from unrelated notifications. Without hwnd-based dispatch, a second
    (or later) concurrent notification's click would silently update the
    FIRST notification's already-returned state instead of its own,
    and the second notification's on_click would never fire."""
    _install_fake_win32con(monkeypatch)
    monkeypatch.setattr(gui, "_win_notify_state", {})

    state_a = {"clicked": False, "done": False}
    state_b = {"clicked": False, "done": False}
    gui._win_notify_state[111] = state_a
    gui._win_notify_state[222] = state_b

    # NIN_BALLOONUSERCLICK = WM_USER + 5, computed the same way the real
    # function does rather than hardcoded, so this test tracks the
    # constant if it's ever changed.
    click_lparam = _FakeWin32Con.WM_USER + gui._NIN_BALLOONUSERCLICK_OFFSET

    gui._win_notify_wndproc(hwnd=222, msg=0, wparam=0, lparam=click_lparam)

    assert state_b == {"clicked": True, "done": True}
    assert state_a == {"clicked": False, "done": False}, (
        "hwnd 111's state must be untouched by a message sent to hwnd 222"
    )


def test_win_notify_wndproc_balloon_timeout_sets_done_without_clicked(monkeypatch):
    """NIN_BALLOONTIMEOUT means Windows itself dismissed the balloon
    (nothing left to click) - the wait loop must stop polling, but
    on_click must not fire."""
    _install_fake_win32con(monkeypatch)
    monkeypatch.setattr(gui, "_win_notify_state", {})

    state = {"clicked": False, "done": False}
    gui._win_notify_state[333] = state

    timeout_lparam = _FakeWin32Con.WM_USER + gui._NIN_BALLOONTIMEOUT_OFFSET
    gui._win_notify_wndproc(hwnd=333, msg=0, wparam=0, lparam=timeout_lparam)

    assert state == {"clicked": False, "done": True}


def test_win_notify_wndproc_ignores_message_for_unregistered_hwnd(monkeypatch):
    """A message can arrive for an hwnd whose state was already popped
    (the notification's own thread already finished tearing down) -
    must not raise."""
    _install_fake_win32con(monkeypatch)
    monkeypatch.setattr(gui, "_win_notify_state", {})

    click_lparam = _FakeWin32Con.WM_USER + gui._NIN_BALLOONUSERCLICK_OFFSET
    result = gui._win_notify_wndproc(hwnd=999, msg=0, wparam=0, lparam=click_lparam)

    assert result == 0
    assert gui._win_notify_state == {}


def test_win_notify_wndproc_tray_icon_click_also_counts(monkeypatch):
    """WM_LBUTTONUP (a direct click on the still-visible tray icon, not
    just the balloon popup itself) should count as a click too."""
    _install_fake_win32con(monkeypatch)
    monkeypatch.setattr(gui, "_win_notify_state", {})

    state = {"clicked": False, "done": False}
    gui._win_notify_state[444] = state

    gui._win_notify_wndproc(hwnd=444, msg=0, wparam=0, lparam=_FakeWin32Con.WM_LBUTTONUP)

    assert state == {"clicked": True, "done": True}
