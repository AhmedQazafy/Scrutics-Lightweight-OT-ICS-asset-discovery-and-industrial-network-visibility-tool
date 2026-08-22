"""
Scrutics Terminal UI

Keyboard navigation:
  Left / Right     : move between the asset, event, and anomaly panels
  Up / Down        : move rows or scroll the active panel
  1                : open Start Analysis menu
  2                : open File Options menu
  3                : open Toggle Panels menu
  P                : pause / resume live capture
  Q                : quit
"""

import os
import csv
import threading
import datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Header, DataTable, Label, Log,
    Button, Input, Static
)
from textual import on
from rich.text import Text

from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine
from scrutics.parsers.detector import SUPPORTED_EXTENSIONS

from scrutics.diagnostics import VERSION
TAGLINE = "Passive OT/ICS Network Asset Discovery"

BANNER_ART = """\
███████╗ ██████╗██████╗ ██╗   ██╗████████╗██╗ ██████╗███████╗
██╔════╝██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║██╔════╝██╔════╝
███████╗██║     ██████╔╝██║   ██║   ██║   ██║██║     ███████╗
╚════██║██║     ██╔══██╗██║   ██║   ██║   ██║██║     ╚════██║
███████║╚██████╗██║  ██║╚██████╔╝   ██║   ██║╚██████╗███████║
╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝ ╚═════╝╚══════╝"""

CSS = """
Screen {
    background: $surface;
}

#banner {
    height: 8;
    content-align: center middle;
    color: $accent;
    text-style: bold;
    border-bottom: solid $accent-darken-2;
}

/* ── Toolbar ─────────────────────────────── */
#toolbar {
    height: 2;
    background: $surface-darken-1;
    border-bottom: solid $accent-darken-2;
    padding: 0 1;
    align: left top;
}

#toolbar Button {
    margin: 0 1;
    min-width: 19;
    height: 1;
    background: $accent-darken-2;
    color: $text;
    border: none;
}

#toolbar Button:focus {
    background: $accent;
    text-style: bold;
}

#toolbar Button:hover {
    background: $accent-darken-1;
}

#btn-pause {
    background: $warning-darken-2 !important;
    margin-right: 2;
}

#btn-pause:focus {
    background: $warning !important;
}

#btn-quit {
    background: $error-darken-2 !important;
    dock: right;
    margin-left: 2;
    margin-right: 1;
}

#btn-quit:focus {
    background: $error !important;
}

/* ── Main split ──────────────────────────── */
#main-layout {
    height: 1fr;
}

#table-panel {
    width: 3fr;
    border: solid $accent-darken-2;
}

#event-panel {
    width: 2fr;
    border: solid $accent-darken-3;
}

#anomaly-panel {
    height: 8;
    border: solid $accent-darken-3;
}

#anomaly-panel.expanded-panel {
    height: 1fr;
}

#anomaly-panel.has-anomalies {
    border: solid $error;
}

#table-panel.active-panel,
#event-panel.active-panel,
#anomaly-panel.active-panel {
    border: solid $accent;
}

#status-bar {
    height: 1;
    background: $accent-darken-3;
    color: $text-muted;
    padding: 0 1;
}

.panel-title {
    background: $accent-darken-3;
    color: $text;
    text-style: bold;
    padding: 0 1;
    height: 1;
}

#asset-table { height: 1fr; }
#event-log   { height: 1fr; }
#anomaly-log { height: 1fr; }

DataTable,
Log {
    scrollbar-size: 1 1;
    scrollbar-visibility: visible;
}

Input,
#dropdown-container,
#setup-dialog {
    scrollbar-size: 0 0;
    scrollbar-visibility: hidden;
}

/* ── Dropdown modal ──────────────────────── */
DropdownModal {
    background: transparent;
    align: left top;
}

ChoiceListModal {
    background: transparent;
    align: center middle;
}

#dropdown-container {
    width: 40;
    height: auto;
    background: $surface;
    border: solid $accent;
    margin-top: 11;
    margin-left: 1;
}

ChoiceListModal #dropdown-container {
    width: 62;
    margin-top: 0;
    margin-left: 0;
}

#dropdown-container Button {
    width: 100%;
    height: 2;
    background: $surface;
    color: $text;
    border: none;
    content-align: left middle;
    padding: 0 2;
}

#dropdown-container Button:focus {
    background: $accent-darken-2;
    text-style: bold;
}

#dropdown-container Button:hover {
    background: $accent-darken-2;
}

.menu-sep {
    height: 1;
    background: $accent-darken-3;
}

/* ── Setup modals ────────────────────────── */
LiveCaptureModal, FileAnalysisModal {
    align: center middle;
}

#setup-dialog {
    width: 62;
    height: auto;
    background: $surface;
    border: solid $accent;
    padding: 1 2;
}

#setup-title {
    text-style: bold;
    color: $accent;
    margin-bottom: 1;
}

.field-label {
    color: $text-muted;
    margin-top: 1;
}

.hint {
    color: $text-muted;
    text-style: italic;
}

.dialog-actions {
    height: 3;
    margin-top: 1;
    align: right middle;
}

.dialog-actions Button {
    margin: 0 1;
    height: 1;
    min-width: 14;
    border: none;
    padding: 0 2;
}

.choice-field {
    margin: 0;
    height: 1;
    background: $surface-darken-1;
    color: $text;
    padding: 0 1;
}

.choice-field:focus {
    background: $accent-darken-3;
    text-style: bold;
}

Input {
    margin: 0;
    height: 1;
    min-height: 1;
    background: $surface-darken-1;
    color: $text;
    border: none;
    padding: 0 1;
}

Input:focus {
    background: $accent-darken-3;
}
"""

# ── Helpers ────────────────────────────────────────────────────────────────────

def _sanitize_mac(mac: str) -> str:
    """
    Remove non-printable and non-ASCII characters from MAC address strings.
    Textual's DataTable can render garbage if a MAC contains unexpected bytes.
    """
    if not mac:
        return "Unknown"
    return "".join(c for c in mac if c.isprintable() and ord(c) < 128)


def _type_label(is_ot) -> str:
    if is_ot is True:  return "OT"
    if is_ot is False: return "IT"
    return "?"

def _baseline_display(status: str) -> str:
    if status == "active":            return "active"
    if status.startswith("building"): return status
    return "no data"

def _fmt_elapsed(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h: return f"{h}h {m:02d}m {s:02d}s"
    return f"{m:02d}m {s:02d}s"


class PanelDataTable(DataTable):
    BINDINGS = [
        Binding("enter", "toggle_content_mode", show=False, priority=True),
        Binding("left", "previous_panel", show=False, priority=True),
        Binding("right", "next_panel", show=False, priority=True),
        Binding("up", "panel_up", show=False, priority=True),
        Binding("down", "panel_down", show=False, priority=True),
        Binding("tab", "ignore_focus_key", show=False, priority=True),
        Binding("shift+tab", "ignore_focus_key", show=False, priority=True),
    ]

    def action_toggle_content_mode(self):
        self.app.action_toggle_content_mode()

    def action_previous_panel(self):
        self.app.action_previous_panel()

    def action_next_panel(self):
        self.app.action_next_panel()

    def action_panel_up(self):
        self.app.action_panel_up()

    def action_panel_down(self):
        self.app.action_panel_down()

    def action_ignore_focus_key(self):
        self.app.action_ignore_focus_key()


class PanelLog(Log):
    BINDINGS = [
        Binding("enter", "toggle_content_mode", show=False, priority=True),
        Binding("left", "previous_panel", show=False, priority=True),
        Binding("right", "next_panel", show=False, priority=True),
        Binding("up", "panel_up", show=False, priority=True),
        Binding("down", "panel_down", show=False, priority=True),
        Binding("tab", "ignore_focus_key", show=False, priority=True),
        Binding("shift+tab", "ignore_focus_key", show=False, priority=True),
    ]

    def action_toggle_content_mode(self):
        self.app.action_toggle_content_mode()

    def action_previous_panel(self):
        self.app.action_previous_panel()

    def action_next_panel(self):
        self.app.action_next_panel()

    def action_panel_up(self):
        self.app.action_panel_up()

    def action_panel_down(self):
        self.app.action_panel_down()

    def action_ignore_focus_key(self):
        self.app.action_ignore_focus_key()


class FormInput(Input):
    BINDINGS = [
        Binding("enter", "confirm_field", show=False, priority=True),
        Binding("up", "previous_field", show=False, priority=True),
        Binding("down", "next_field", show=False, priority=True),
        Binding("tab", "ignore_focus_key", show=False, priority=True),
        Binding("shift+tab", "ignore_focus_key", show=False, priority=True),
    ]

    def action_confirm_field(self):
        self.app.screen.action_confirm_field()

    def action_previous_field(self):
        self.app.screen.action_previous_field()

    def action_next_field(self):
        self.app.screen.action_next_field()

    def action_ignore_focus_key(self):
        pass


class FormButton(Button):
    BINDINGS = [
        Binding("left", "previous_button", show=False, priority=True),
        Binding("right", "next_button", show=False, priority=True),
        Binding("up", "previous_field", show=False, priority=True),
        Binding("down", "next_field", show=False, priority=True),
        Binding("tab", "ignore_focus_key", show=False, priority=True),
        Binding("shift+tab", "ignore_focus_key", show=False, priority=True),
    ]

    def action_previous_button(self):
        self.app.screen.action_previous_button()

    def action_next_button(self):
        self.app.screen.action_next_button()

    def action_previous_field(self):
        self.app.screen.action_previous_field()

    def action_next_field(self):
        self.app.screen.action_next_field()

    def action_ignore_focus_key(self):
        pass


class ChoiceField(Static, can_focus=True):
    BINDINGS = [
        Binding("enter", "confirm_field", show=False, priority=True),
        Binding("up", "previous_field", show=False, priority=True),
        Binding("down", "next_field", show=False, priority=True),
        Binding("left", "ignore_focus_key", show=False, priority=True),
        Binding("right", "ignore_focus_key", show=False, priority=True),
        Binding("tab", "ignore_focus_key", show=False, priority=True),
        Binding("shift+tab", "ignore_focus_key", show=False, priority=True),
    ]

    def __init__(self, options: list[str], value: str, **kwargs):
        self.options = options
        self.value = value
        super().__init__(value, classes="choice-field", **kwargs)

    def set_value(self, value: str):
        self.value = value
        self.update(value)

    def action_confirm_field(self):
        self.app.screen.action_confirm_field()

    def action_previous_field(self):
        self.app.screen.action_previous_field()

    def action_next_field(self):
        self.app.screen.action_next_field()

    def action_ignore_focus_key(self):
        pass


class SetupModalMixin:
    FIELD_IDS: list[str] = []
    BUTTON_IDS: list[str] = []

    def on_mount(self):
        if self.FIELD_IDS:
            self.query_one(self.FIELD_IDS[0]).focus()

    def _focus_index(self) -> int:
        focused = self.app.focused
        for index, selector in enumerate(self.FIELD_IDS):
            try:
                if self.query_one(selector) is focused:
                    return index
            except Exception:
                pass
        for selector in self.BUTTON_IDS:
            try:
                if self.query_one(selector) is focused:
                    return len(self.FIELD_IDS) - 1
            except Exception:
                pass
        return 0

    def _focus_field(self, index: int):
        if not self.FIELD_IDS:
            return
        index = max(0, min(len(self.FIELD_IDS) - 1, index))
        self.query_one(self.FIELD_IDS[index]).focus()

    def action_previous_field(self):
        self._focus_field(self._focus_index() - 1)

    def action_next_field(self):
        self._focus_field(self._focus_index() + 1)

    def action_previous_button(self):
        self._focus_button(-1)

    def action_next_button(self):
        self._focus_button(1)

    def _focus_button(self, direction: int):
        if not self.BUTTON_IDS:
            return
        focused = self.app.focused
        index = 0
        for i, selector in enumerate(self.BUTTON_IDS):
            try:
                if self.query_one(selector) is focused:
                    index = i
                    break
            except Exception:
                pass
        self.query_one(self.BUTTON_IDS[(index + direction) % len(self.BUTTON_IDS)]).focus()

    def action_confirm_field(self):
        self.action_next_field()

    def action_ignore_focus_key(self):
        pass


# ── Dropdown Modal ─────────────────────────────────────────────────────────────

class DropdownModal(ModalScreen):
    """
    Floating dropdown menu.
    Appears top-left over the toolbar area.
    Navigate with arrow keys, activate with Enter/Space.
    """
    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("up",     "menu_up",   show=False, priority=True),
        Binding("down",   "menu_down", show=False, priority=True),
        Binding("1", "shortcut_start",         show=False),
        Binding("2", "shortcut_file_options",  show=False),
        Binding("3", "shortcut_toggle_panels", show=False),
        Binding("r", "shortcut_reload",        show=False),
        Binding("p", "shortcut_pause",         show=False),
        Binding("q", "shortcut_quit",          show=False),
        Binding("tab",       "ignore_focus_key", show=False, priority=True),
        Binding("shift+tab", "ignore_focus_key", show=False, priority=True),
    ]

    def __init__(self, items: list):
        super().__init__()
        self._items = items

    def compose(self) -> ComposeResult:
        with Container(id="dropdown-container"):
            for item in self._items:
                if item is None:
                    yield Static("", classes="menu-sep")
                else:
                    label, action_id = item
                    yield Button(label, id=action_id)

    def on_mount(self):
        # Auto-focus first button for immediate keyboard use
        buttons = self.query("Button")
        if buttons:
            buttons.first().focus()

    @on(Button.Pressed)
    def select(self, event: Button.Pressed):
        self.dismiss(event.button.id)

    def action_dismiss(self):
        self.dismiss(None)

    def action_ignore_focus_key(self):
        pass

    def action_menu_up(self):
        self._focus_menu_item(-1)

    def action_menu_down(self):
        self._focus_menu_item(1)

    def _focus_menu_item(self, direction: int):
        buttons = list(self.query("Button"))
        if not buttons:
            return
        focused = self.app.focused
        try:
            index = buttons.index(focused)
        except ValueError:
            index = 0
        buttons[(index + direction) % len(buttons)].focus()

    def action_shortcut_start(self):
        self.dismiss("__shortcut_start")

    def action_shortcut_file_options(self):
        self.dismiss("__shortcut_file_options")

    def action_shortcut_toggle_panels(self):
        self.dismiss("__shortcut_toggle_panels")

    def action_shortcut_reload(self):
        self.dismiss("__shortcut_reload")

    def action_shortcut_pause(self):
        self.dismiss("__shortcut_pause")

    def action_shortcut_quit(self):
        self.dismiss("__shortcut_quit")


class ChoiceListModal(ModalScreen):
    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("up", "menu_up", show=False, priority=True),
        Binding("down", "menu_down", show=False, priority=True),
        Binding("tab", "ignore_focus_key", show=False, priority=True),
        Binding("shift+tab", "ignore_focus_key", show=False, priority=True),
    ]

    def __init__(self, title: str, options: list[str]):
        super().__init__()
        self._title = title
        self._options = options

    def compose(self) -> ComposeResult:
        with Container(id="dropdown-container"):
            yield Static(f"  {self._title}", classes="menu-sep")
            for index, option in enumerate(self._options):
                yield Button(f"  {option}", id=f"choice-{index}")

    def on_mount(self):
        buttons = self.query("Button")
        if buttons:
            buttons.first().focus()

    @on(Button.Pressed)
    def select(self, event: Button.Pressed):
        index = int(event.button.id.split("-", 1)[1])
        self.dismiss(self._options[index])

    def action_dismiss(self):
        self.dismiss(None)

    def action_ignore_focus_key(self):
        pass

    def action_menu_up(self):
        self._focus_menu_item(-1)

    def action_menu_down(self):
        self._focus_menu_item(1)

    def _focus_menu_item(self, direction: int):
        buttons = list(self.query("Button"))
        if not buttons:
            return
        focused = self.app.focused
        try:
            index = buttons.index(focused)
        except ValueError:
            index = 0
        buttons[(index + direction) % len(buttons)].focus()


# ── Live Capture Setup Modal ───────────────────────────────────────────────────

class LiveCaptureModal(SetupModalMixin, ModalScreen):
    FIELD_IDS = ["#iface-choice", "#duration-input", "#baseline-input", "#start-btn"]
    BUTTON_IDS = ["#cancel-btn", "#start-btn"]
    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("up", "previous_field", show=False),
        Binding("down", "next_field", show=False),
        Binding("left", "previous_field", show=False),
        Binding("right", "next_field", show=False),
        Binding("tab", "ignore_focus_key", show=False),
        Binding("shift+tab", "ignore_focus_key", show=False),
    ]

    def __init__(self, prefill: dict = None):
        super().__init__()
        self._prefill = prefill or {}
        try:
            from scapy.all import get_if_list
            self._interfaces = get_if_list()
        except Exception:
            self._interfaces = ["eth0"]

    def compose(self) -> ComposeResult:
        default = self._prefill.get("iface", self._interfaces[0] if self._interfaces else "eth0")
        with Container(id="setup-dialog"):
            yield Label("Live Traffic Capture", id="setup-title")
            yield Label("Network Interface", classes="field-label")
            yield ChoiceField(self._interfaces, default, id="iface-choice")
            yield Label("Duration in seconds  (0 = run until stopped)", classes="field-label")
            yield FormInput(value=str(self._prefill.get("duration", "120")), id="duration-input")
            yield Label("Baseline observation window in seconds", classes="field-label")
            yield FormInput(value=str(self._prefill.get("baseline", "60")), id="baseline-input")
            with Horizontal(classes="dialog-actions"):
                yield FormButton("Cancel",        id="cancel-btn")
                yield FormButton("Start Capture", id="start-btn", variant="primary")

    @on(Button.Pressed, "#cancel-btn")
    def cancel(self): self.dismiss(None)

    @on(Button.Pressed, "#start-btn")
    def start(self):
        iface    = self.query_one("#iface-choice", ChoiceField).value
        duration = int(self.query_one("#duration-input", FormInput).value or "120")
        baseline = int(self.query_one("#baseline-input", FormInput).value or "60")
        self.dismiss({"mode": "live", "iface": iface,
                      "duration": duration, "baseline": baseline})

    def action_confirm_field(self):
        focused = self.app.focused
        if focused is self.query_one("#iface-choice"):
            def handle(value):
                if value:
                    self.query_one("#iface-choice", ChoiceField).set_value(value)
                    self._focus_field(1)
                else:
                    self.query_one("#iface-choice").focus()
            self.app.push_screen(
                ChoiceListModal("Network Interface", self._interfaces),
                handle,
            )
        elif focused is self.query_one("#baseline-input"):
            self.query_one("#start-btn").focus()
        else:
            super().action_confirm_field()


# ── File Analysis Setup Modal ──────────────────────────────────────────────────

class FileAnalysisModal(SetupModalMixin, ModalScreen):
    FIELD_IDS = ["#filepath-input", "#start-btn"]
    BUTTON_IDS = ["#cancel-btn", "#start-btn"]
    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("up", "previous_field", show=False),
        Binding("down", "next_field", show=False),
        Binding("left", "previous_field", show=False),
        Binding("right", "next_field", show=False),
        Binding("tab", "ignore_focus_key", show=False),
        Binding("shift+tab", "ignore_focus_key", show=False),
    ]

    def __init__(self, prefill: dict = None):
        super().__init__()
        self._prefill = prefill or {}

    def compose(self) -> ComposeResult:
        ext_str = "  ".join(sorted(SUPPORTED_EXTENSIONS))
        with Container(id="setup-dialog"):
            yield Label("Log File Analysis", id="setup-title")
            yield Label(f"Supported formats:  {ext_str}", classes="field-label")
            yield Label(".log = Zeek protocol logs    .json = Suricata EVE", classes="hint")
            yield Label("File path", classes="field-label")
            yield FormInput(
                value=self._prefill.get("file", ""),
                id="filepath-input",
                placeholder="/path/to/capture.pcap",
            )
            with Horizontal(classes="dialog-actions"):
                yield FormButton("Cancel",  id="cancel-btn")
                yield FormButton("Analyze", id="start-btn", variant="primary")

    @on(Button.Pressed, "#cancel-btn")
    def cancel(self): self.dismiss(None)

    @on(Button.Pressed, "#start-btn")
    def start(self):
        filepath = self.query_one("#filepath-input", FormInput).value.strip()
        if filepath:
            self.dismiss({"mode": "file", "filepath": filepath})


# ── Main Application ───────────────────────────────────────────────────────────

class ScruticsApp(App):
    CSS = CSS
    TITLE = f"Scrutics {VERSION}"
    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("1",          "start_analysis",  "1:Start Analysis", show=False),
        Binding("2",          "file_options",    "2:File Options",   show=False),
        Binding("3",          "toggle_panels",   "3:Panels",         show=False),
        Binding("r",          "reload_rules",    "R:Reload Rules",   show=False),
        Binding("p",          "pause_resume",    "P:Pause/Resume",   show=False),
        Binding("q",          "quit",            "Q:Quit",           show=False),
        Binding("left",       "previous_panel",  show=False),
        Binding("right",      "next_panel",      show=False),
        Binding("up",         "panel_up",        show=False),
        Binding("down",       "panel_down",      show=False),
        Binding("enter",      "toggle_content_mode", show=False),
        Binding("tab",        "ignore_focus_key", show=False),
        Binding("shift+tab",  "ignore_focus_key", show=False),
    ]

    status_text = reactive("Passive OT/ICS asset discovery ready.")

    def __init__(self):
        super().__init__()
        self.inventory: AssetInventory | None = None
        self.engine: CaptureEngine | None = None
        self._capture_running = threading.Event()
        self._paused = False
        self._session_dir: str | None = None
        self._capture_start: float | None = None
        self._last_anomaly_count = 0
        self._active_panel = "assets"
        self._content_mode = False
        self._status_style = "dim white"

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"{BANNER_ART}\n{VERSION}  .  {TAGLINE}", id="banner")

        with Horizontal(id="toolbar"):
            yield Button("Start Analysis =1", id="btn-start")
            yield Button("File Options =2",   id="btn-file-opts")
            yield Button("Toggle Panels =3",  id="btn-panels")
            yield Button("Reload Rules =R",   id="btn-reload")
            yield Button("Pause =P",          id="btn-pause")
            yield Button("Quit =Q",           id="btn-quit")

        with Horizontal(id="main-layout"):
            with Vertical(id="table-panel"):
                yield Label(" Asset Inventory", id="asset-title", classes="panel-title")
                yield PanelDataTable(
                    id="asset-table",
                    zebra_stripes=True,
                    cursor_type="row",
                )

            with Vertical(id="event-panel"):
                yield Label(" Event Log", id="event-title", classes="panel-title")
                yield PanelLog(id="event-log", auto_scroll=True, max_lines=500)

        with Container(id="anomaly-panel"):
            yield Label(" Anomaly Feed", id="anomaly-title", classes="panel-title")
            yield PanelLog(id="anomaly-log", auto_scroll=True, max_lines=200)

        yield Static("", id="status-bar")

    def on_mount(self):
        table = self.query_one("#asset-table", DataTable)
        table.add_columns(
            "IP Address", "MAC", "Vendor", "Protocol",
            "Role", "Conf%", "Baseline", "Anomalies", "Type"
        )
        self.set_interval(0.5, self._refresh_display)
        self._sync_panel_layout()
        self._focus_active_panel()

        import scrutics.signals as signals
        signals.set_reload_callback(lambda: self.call_from_thread(self.action_reload_rules))
        signals.start_file_watch()

        # Auto-start from CLI env vars
        auto_live = os.environ.get("SCRUTICS_AUTO_LIVE")
        auto_file = os.environ.get("SCRUTICS_AUTO_FILE")
        if auto_live:
            self.set_timer(0.4, lambda: self.push_screen(
                LiveCaptureModal(prefill={
                    "iface":    auto_live,
                    "duration": int(os.environ.get("SCRUTICS_AUTO_DURATION", "120")),
                    "baseline": int(os.environ.get("SCRUTICS_AUTO_BASELINE", "60")),
                }),
                self._on_capture_config
            ))
        elif auto_file:
            self.set_timer(0.4, lambda: self.push_screen(
                FileAnalysisModal(prefill={"file": auto_file}),
                self._on_capture_config
            ))

    # ── Toolbar button handlers ───────────────────────────────────────────────

    @on(Button.Pressed, "#btn-start")
    def btn_start(self):     self.action_start_analysis()

    @on(Button.Pressed, "#btn-file-opts")
    def btn_file_opts(self): self.action_file_options()

    @on(Button.Pressed, "#btn-panels")
    def btn_panels(self):    self.action_toggle_panels()

    @on(Button.Pressed, "#btn-reload")
    def btn_reload(self):    self.action_reload_rules()

    @on(Button.Pressed, "#btn-pause")
    def btn_pause(self):     self.action_pause_resume()

    @on(Button.Pressed, "#btn-quit")
    def btn_quit(self):      self.action_quit()

    # ── Dropdown menus ────────────────────────────────────────────────────────

    def action_start_analysis(self):
        if self._capture_running.is_set():
            self.notify("Capture already running. Stop it first.", severity="warning")
            self._focus_active_panel()
            return
        items = [
            ("  Live Traffic Capture",  "opt-live"),
            ("  Log File Analysis",     "opt-file"),
        ]
        def handle(result):
            if self._handle_dropdown_shortcut(result, current="start"):
                return
            if result == "opt-live":
                self.push_screen(LiveCaptureModal(), self._on_capture_config)
            elif result == "opt-file":
                self.push_screen(FileAnalysisModal(), self._on_capture_config)
            else:
                self._focus_active_panel()
        self.push_screen(DropdownModal(items), handle)

    def action_file_options(self):
        items = [
            ("  Save Current Session",  "opt-save"),
            ("  Load Last Session",     "opt-load"),
        ]
        def handle(result):
            if self._handle_dropdown_shortcut(result, current="file"):
                return
            if result == "opt-save":
                self._save_session()
            elif result == "opt-load":
                self._load_last_results()
            self._focus_active_panel()
        self.push_screen(DropdownModal(items), handle)

    def action_toggle_panels(self):
        table_vis   = self.query_one("#table-panel").display
        event_vis   = self.query_one("#event-panel").display
        anomaly_vis = self.query_one("#anomaly-panel").display
        items = [
            (f"  {'[x]' if table_vis   else '[ ]'} Asset Inventory", "opt-table"),
            (f"  {'[x]' if event_vis   else '[ ]'} Event Log",        "opt-events"),
            (f"  {'[x]' if anomaly_vis else '[ ]'} Anomaly Feed",     "opt-anomaly"),
        ]
        def handle(result):
            if self._handle_dropdown_shortcut(result, current="panels"):
                return
            if result == "opt-table":
                self.query_one("#table-panel").display   = not table_vis
            elif result == "opt-events":
                self.query_one("#event-panel").display   = not event_vis
            elif result == "opt-anomaly":
                self.query_one("#anomaly-panel").display = not anomaly_vis
            self._sync_panel_layout()
        self.push_screen(DropdownModal(items), handle)

    def action_pause_resume(self):
        if not self._capture_running.is_set():
            self._focus_active_panel()
            return
        btn = self.query_one("#btn-pause", Button)
        self._paused = not self._paused
        btn.label = "Resume =P" if self._paused else "Pause =P"
        self._set_status("Capture paused" if self._paused else "Capture resumed")
        self._focus_active_panel()

    def action_reload_rules(self):
        from scrutics.classifier.protocol import reload_rules
        from scrutics.config.loader import load_sinks_config
        from scrutics.integrations.sinks import SinkManager
        try:
            reload_rules()
            new_sinks = load_sinks_config(strict=True)
            if self.engine:
                if self.engine.sink_manager:
                    errors = self.engine.sink_manager.reload(new_sinks)
                elif new_sinks:
                    self.engine.sink_manager = SinkManager(new_sinks)
                    errors = []
                else:
                    errors = []
                if errors:
                    raise ValueError("; ".join(errors))
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self._set_status(f"✓ Rules reloaded at {ts}", "green")
        except Exception as e:
            self._set_status(f"Reload failed: {e}", "bold red")
        self._focus_active_panel()

    # ── Reactive ──────────────────────────────────────────────────────────────

    def action_ignore_focus_key(self):
        self._focus_active_panel()

    def action_toggle_content_mode(self):
        if not self._visible_panels():
            return
        self._content_mode = not self._content_mode
        self._focus_active_panel()

    def action_previous_panel(self):
        if self._content_mode:
            self._move_active_panel_horizontal(-1)
        else:
            self._cycle_panel(-1)

    def action_next_panel(self):
        if self._content_mode:
            self._move_active_panel_horizontal(1)
        else:
            self._cycle_panel(1)

    def action_panel_up(self):
        if self._content_mode:
            self._move_active_panel(-1)
        else:
            self._cycle_panel(-1)

    def action_panel_down(self):
        if self._content_mode:
            self._move_active_panel(1)
        else:
            self._cycle_panel(1)

    def _visible_panels(self):
        panels = [
            ("assets", "#table-panel", "#asset-table"),
            ("events", "#event-panel", "#event-log"),
            ("anomalies", "#anomaly-panel", "#anomaly-log"),
        ]
        visible = []
        for name, panel_id, widget_id in panels:
            try:
                if self.query_one(panel_id).display:
                    visible.append((name, panel_id, widget_id))
            except Exception:
                pass
        return visible

    def _sync_panel_layout(self):
        table_visible = self.query_one("#table-panel").display
        event_visible = self.query_one("#event-panel").display
        anomaly_visible = self.query_one("#anomaly-panel").display
        top_visible = table_visible or event_visible
        self.query_one("#main-layout").display = top_visible
        self.query_one("#anomaly-panel").set_class(
            anomaly_visible and not top_visible,
            "expanded-panel",
        )
        if self._active_panel not in [name for name, _, _ in self._visible_panels()]:
            self._content_mode = False
        self._focus_active_panel()

    def _focus_active_panel(self):
        visible = self._visible_panels()
        if not visible:
            return
        names = [name for name, _, _ in visible]
        if self._active_panel not in names:
            self._active_panel = names[0]
        for name, panel_id, widget_id in visible:
            panel = self.query_one(panel_id)
            panel.set_class(name == self._active_panel, "active-panel")
            if name == self._active_panel:
                self.query_one(widget_id).focus()
        self._refresh_panel_titles()

    def _refresh_panel_titles(self):
        titles = {
            "assets": ("#asset-title", " Asset Inventory"),
            "events": ("#event-title", " Event Log"),
            "anomalies": ("#anomaly-title", " Anomaly Feed"),
        }
        for name, (selector, label) in titles.items():
            marker = " *" if self._content_mode and name == self._active_panel else ""
            try:
                self.query_one(selector, Label).update(f"{label}{marker}")
            except Exception:
                pass

    def _cycle_panel(self, direction: int):
        visible = self._visible_panels()
        if not visible:
            return
        names = [name for name, _, _ in visible]
        index = names.index(self._active_panel) if self._active_panel in names else 0
        self._active_panel = names[(index + direction) % len(names)]
        self._content_mode = False
        self._focus_active_panel()

    def _move_active_panel(self, direction: int):
        self._focus_active_panel()
        if self._active_panel == "assets":
            table = self.query_one("#asset-table", DataTable)
            if table.row_count == 0:
                return
            row = getattr(table.cursor_coordinate, "row", 0)
            table.move_cursor(
                row=max(0, min(table.row_count - 1, row + direction)),
                animate=False,
            )
            return
        widget_id = "#event-log" if self._active_panel == "events" else "#anomaly-log"
        widget = self.query_one(widget_id, Log)
        try:
            widget.scroll_relative(y=direction, animate=False)
        except Exception:
            if direction < 0 and hasattr(widget, "action_scroll_up"):
                widget.action_scroll_up()
            elif direction > 0 and hasattr(widget, "action_scroll_down"):
                widget.action_scroll_down()

    def _move_active_panel_horizontal(self, direction: int):
        self._focus_active_panel()
        widget_id = {
            "assets": "#asset-table",
            "events": "#event-log",
            "anomalies": "#anomaly-log",
        }.get(self._active_panel)
        if not widget_id:
            return
        widget = self.query_one(widget_id)
        try:
            widget.scroll_relative(x=direction * 8, animate=False)
        except Exception:
            if direction < 0 and hasattr(widget, "action_scroll_left"):
                widget.action_scroll_left()
            elif direction > 0 and hasattr(widget, "action_scroll_right"):
                widget.action_scroll_right()

    def _handle_dropdown_shortcut(self, result, current: str) -> bool:
        shortcut_actions = {
            "__shortcut_start":         ("start",  self.action_start_analysis),
            "__shortcut_file_options":  ("file",   self.action_file_options),
            "__shortcut_toggle_panels": ("panels", self.action_toggle_panels),
            "__shortcut_reload":        ("reload", self.action_reload_rules),
            "__shortcut_pause":         ("pause",  self.action_pause_resume),
            "__shortcut_quit":          ("quit",   self.action_quit),
        }
        if result not in shortcut_actions:
            return False
        target, action = shortcut_actions[result]
        if target == current:
            self._focus_active_panel()
        elif target in {"pause", "quit", "reload"}:
            action()
        else:
            self.set_timer(0.01, action)
        return True

    def _set_status(self, value: str, style: str = "dim white"):
        self._status_style = style
        self.status_text = value
        # Errors stay visible longer so users can read them
        timeout = 12.0 if style == "bold red" else 4.0
        self.set_timer(timeout, self._clear_status)

    def _clear_status(self):
        self._status_style = "dim white"
        self.status_text = "Passive OT/ICS asset discovery ready."

    def watch_status_text(self, value: str):
        try:
            self.query_one("#status-bar", Static).update(
                Text(value, style=self._status_style)
            )
        except Exception:
            pass

    # ── Capture config callback ───────────────────────────────────────────────

    def _on_capture_config(self, config):
        if config is None:
            return
        mode = config.get("mode")

        if mode == "live":
            self._start_session(baseline_window=config["baseline"])
            dur = config["duration"]
            dur_str = "infinite (stop with Q)" if dur == 0 else f"{dur}s"
            self._set_status(
                f"Capturing on {config['iface']}  |  "
                f"duration: {dur_str}  |  baseline: {config['baseline']}s"
            )
            import time
            self._capture_start = time.time()

            def run():
                try:
                    self.engine.start_live(
                        interface=config["iface"],
                        timeout=config["duration"],
                    )
                except Exception as e:
                    self.call_from_thread(self.notify, str(e), severity="error")
                finally:
                    self._capture_running.clear()
                    self.call_from_thread(self._on_capture_done)

            threading.Thread(target=run, daemon=True).start()
            self._capture_running.set()

        elif mode == "file":
            filepath = config["filepath"]
            if not os.path.exists(filepath):
                self.notify(f"File not found: {filepath}", severity="error")
                return
            self._start_session()
            self._set_status(f"Analyzing: {os.path.basename(filepath)}")

            def run():
                try:
                    self.engine.start_file(filepath)
                except Exception as e:
                    self.call_from_thread(self.notify, str(e), severity="error")
                finally:
                    self._capture_running.clear()
                    self.call_from_thread(self._on_capture_done)

            threading.Thread(target=run, daemon=True).start()
            self._capture_running.set()

    def _on_capture_done(self):
        self._export_session()
        anomaly_count = len(self.engine.baseline.get_anomalies()) if self.engine else 0
        self._set_status(
            f"Complete  |  {self.inventory.count()} assets  |  "
            f"{anomaly_count} anomalies  |  session: {self._session_dir}"
        )
        self.query_one("#btn-pause", Button).label = "Pause =P"
        self._paused = False

    # ── Session ───────────────────────────────────────────────────────────────

    def _start_session(self, baseline_window: int = 60):
        base = os.environ.get("SCRUTICS_AUTO_OUTPUT", "output")
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self._session_dir = os.path.join(base, f"scrutics_{ts}")
        os.makedirs(self._session_dir, exist_ok=True)

        self.inventory = AssetInventory()
        self.engine = CaptureEngine(inventory=self.inventory, baseline_window=baseline_window)

        from scrutics.db.writer import RollingWriter
        self.engine.writer = RollingWriter(self._session_dir)

        from scrutics.integrations.sinks import SinkManager
        from scrutics.config.loader import load_sinks_config
        try:
            sinks_cfg = load_sinks_config(strict=True)
            if sinks_cfg:
                self.engine.sink_manager = SinkManager(sinks_cfg)
        except Exception as e:
            self._set_status(f"Sink config error: {e}", "bold red")

        self._last_anomaly_count = 0
        self._capture_start = None
        self._paused = False

        self.query_one("#asset-table",  DataTable).clear()
        self.query_one("#event-log",    Log).clear()
        self.query_one("#anomaly-log",  Log).clear()
        self.query_one("#anomaly-panel").remove_class("has-anomalies")
        self.query_one("#btn-pause", Button).label = "Pause =P"
        self._active_panel = "assets"
        self._content_mode = False
        self._sync_panel_layout()

    def _save_session(self):
        if self.inventory and self.inventory.count() > 0 and self._session_dir:
            self._export_session()
            self.notify(f"Session saved to {self._session_dir}", severity="information")
        else:
            self.notify("No data to save", severity="warning")

    def _export_session(self):
        if not self._session_dir or not self.inventory:
            return
        self.inventory.export_csv(os.path.join(self._session_dir, "assets.csv"))

    # ── Display refresh ───────────────────────────────────────────────────────

    def _refresh_display(self):
        if self.inventory is None or self.engine is None:
            return
        if self._paused:
            return
        self._refresh_table()
        self._drain_event_log()
        self._drain_anomaly_log()
        if self._capture_running.is_set():
            import time
            elapsed = _fmt_elapsed(time.time() - self._capture_start) if self._capture_start else "0s"
            self._set_status(
                f"Capturing  |  packets: {self.engine._packet_count}  |  "
                f"assets: {self.inventory.count()}  |  "
                f"anomalies: {len(self.engine.baseline.get_anomalies())}  |  "
                f"elapsed: {elapsed}"
            )

    def _refresh_table(self):
        table = self.query_one("#asset-table", DataTable)
        assets = sorted(self.inventory.get_all(), key=lambda x: x.ip)
        anomaly_counts = {}
        for a in self.engine.baseline.get_anomalies():
            ip = a.get("ip", "")
            anomaly_counts[ip] = anomaly_counts.get(ip, 0) + 1

        if len(assets) == table.row_count:
            for i, asset in enumerate(assets):
                try:
                    table.update_cell_at((i, 2), asset.vendor[:20])
                    table.update_cell_at((i, 3), ", ".join(asset.protocols)[:18] if asset.protocols else "Unknown")
                    table.update_cell_at((i, 4), asset.role[:26])
                    table.update_cell_at((i, 5), f"{asset.confidence_pct}%")
                    table.update_cell_at((i, 6), _baseline_display(asset.baseline_status))
                    table.update_cell_at((i, 7), str(anomaly_counts.get(asset.ip, 0)))
                    table.update_cell_at((i, 8), _type_label(asset.is_ot))
                except Exception:
                    pass
        else:
            table.clear()
            for asset in assets:
                mac = _sanitize_mac(asset.mac)
                table.add_row(
                    asset.ip, mac, asset.vendor[:20],
                    ", ".join(asset.protocols)[:18] if asset.protocols else "Unknown",
                    asset.role[:26], f"{asset.confidence_pct}%",
                    _baseline_display(asset.baseline_status),
                    str(anomaly_counts.get(asset.ip, 0)),
                    _type_label(asset.is_ot),
                    key=asset.ip,
                )

    def _drain_event_log(self):
        log_widget = self.query_one("#event-log", Log)
        while self.engine.event_log:
            try:
                ts, msg, _ = self.engine.event_log.popleft()
                log_widget.write_line(f"{ts}  {msg}")
            except (IndexError, StopIteration):
                break

    def _drain_anomaly_log(self):
        anomalies = self.engine.baseline.get_anomalies()
        new_count = len(anomalies)
        if new_count > self._last_anomaly_count:
            alog = self.query_one("#anomaly-log", Log)
            self.query_one("#anomaly-panel").add_class("has-anomalies")
            for anomaly in anomalies[self._last_anomaly_count:]:
                ts     = datetime.datetime.fromtimestamp(anomaly.get("timestamp", 0)).strftime("%H:%M:%S")
                sev    = anomaly.get("severity", "?")
                ip     = anomaly.get("ip", "?")
                atype  = anomaly.get("type", "?")
                detail = anomaly.get("detail", "")
                alog.write_line(f"{ts}  [{sev}]  {ip}  {atype} — {detail}")
            self._last_anomaly_count = new_count

    # ── Load last session ─────────────────────────────────────────────────────

    def _load_last_results(self):
        base = os.environ.get("SCRUTICS_AUTO_OUTPUT", "output")
        sessions = sorted(
            [os.path.join(base, d) for d in os.listdir(base)
             if os.path.isdir(os.path.join(base, d)) and d.startswith("scrutics_")]
            if os.path.exists(base) else [],
            reverse=True
        )
        if not sessions:
            self.notify("No saved sessions found in output/", severity="warning")
            return

        session = sessions[0]
        table = self.query_one("#asset-table", DataTable)
        table.clear()

        assets_csv = os.path.join(session, "assets.csv")
        if os.path.exists(assets_csv):
            with open(assets_csv, newline="") as f:
                for row in csv.DictReader(f):
                    table.add_row(
                        row.get("ip",""), row.get("mac",""),
                        row.get("vendor","")[:20], row.get("protocol","")[:18],
                        row.get("role","")[:26], f"{row.get('confidence_pct','?')}%",
                        row.get("baseline_status",""), "--", row.get("type",""),
                    )

        elog = self.query_one("#event-log", Log)
        elog.clear()
        events_csv = os.path.join(session, "events.csv")
        if os.path.exists(events_csv):
            with open(events_csv, newline="") as f:
                for row in csv.DictReader(f):
                    elog.write_line(f"{row.get('timestamp','')}  {row.get('message','')}")

        alog = self.query_one("#anomaly-log", Log)
        alog.clear()
        anomalies_csv = os.path.join(session, "anomalies.csv")
        if os.path.exists(anomalies_csv):
            self.query_one("#anomaly-panel").add_class("has-anomalies")
            with open(anomalies_csv, newline="") as f:
                for row in csv.DictReader(f):
                    alog.write_line(
                        f"{row.get('timestamp','')}  [{row.get('severity','?')}]  "
                        f"{row.get('ip','')}  {row.get('type','')} -- {row.get('detail','')}"
                    )

        self._set_status(
            f"Loaded: {os.path.basename(session)}  |  "
            f"full data in CSV files inside session folder"
        )
        self.notify(f"Loaded: {os.path.basename(session)}", severity="information")


# ── Entry point ────────────────────────────────────────────────────────────────

def run():
    ScruticsApp().run()
