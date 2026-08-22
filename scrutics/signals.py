"""
Rule reload trigger management.

Call setup() once at startup to register the OS-level handler.
The TUI button, optional SIGHUP, and config file watcher use the same
code path via trigger().

Usage:
    signals.setup()                       # register SIGHUP handler where available
    signals.set_reload_callback(fn)       # fn() called on SIGHUP/watch/trigger()
    signals.start_file_watch()            # poll custom_rules.yaml for changes
    signals.trigger()                     # call from TUI button
"""

import os
import signal as _signal
import threading

from scrutics.config.loader import get_user_config_paths

_lock     = threading.Lock()
_callback = None
_watch_thread = None
_watch_stop = threading.Event()


def set_reload_callback(fn):
    """Register the function to call on reload. Thread-safe."""
    global _callback
    with _lock:
        _callback = fn


def trigger():
    """Programmatically invoke the reload callback (e.g. from a TUI button)."""
    with _lock:
        fn = _callback
    if fn is not None:
        return fn()
    return None


def _handle(sig, frame):
    trigger()


def setup():
    """Register the OS-level SIGHUP handler. No-op on platforms without SIGHUP."""
    if hasattr(_signal, "SIGHUP"):
        _signal.signal(_signal.SIGHUP, _handle)


def _first_existing_config_path() -> str | None:
    # Check advanced override paths first, then fall back to package custom_rules.yaml
    from scrutics.config.loader import get_user_config_paths, _CUSTOM_TEMPLATE
    for path in get_user_config_paths():
        if os.path.exists(path):
            return path
    return _CUSTOM_TEMPLATE  # always watch custom_rules.yaml as fallback


def start_file_watch(interval: float = 2.5):
    """
    Watch the active user config file for mtime changes.

    Polling is intentional: it works in Windows, WSL, containers, and small
    Linux appliances without platform-specific inotify dependencies.
    """
    global _watch_thread
    if _watch_thread and _watch_thread.is_alive():
        return

    _watch_stop.clear()

    def run():
        watched_path = None
        last_mtime = None
        while not _watch_stop.is_set():
            path = _first_existing_config_path()
            try:
                mtime = os.path.getmtime(path) if path else None
            except OSError:
                mtime = None
            if path != watched_path:
                watched_path = path
                last_mtime = mtime
            elif path and mtime is not None and last_mtime is not None and mtime > last_mtime:
                last_mtime = mtime
                try:
                    trigger()
                except Exception:
                    pass
            elif path and last_mtime is None:
                last_mtime = mtime
            _watch_stop.wait(interval)

    _watch_thread = threading.Thread(target=run, daemon=True)
    _watch_thread.start()


def stop_file_watch():
    """Stop the config file watcher if it is running."""
    _watch_stop.set()
