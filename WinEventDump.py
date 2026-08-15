
#!/usr/bin/env python3


import os
import re
import sys
import csv
import json
import webbrowser
import xml.etree.ElementTree as ET
from xml.dom import minidom

# ---------------------------------------------------------------------------
# Set environment variables BEFORE importing Qt to avoid rendering issues
# ---------------------------------------------------------------------------
os.environ.setdefault("QT_OPENGL", "software")
os.environ.setdefault("QT_QUICK_BACKEND", "software")
os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")
os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
# Force Qt's native file dialog instead of GTK
os.environ.setdefault("QT_QPA_PLATFORMTHEME", "qt5ct")
os.environ.setdefault("XDG_CURRENT_DESKTOP", "KDE")
os.environ.setdefault("DESKTOP_SESSION", "plasma")

# Suppress GTK warnings
import warnings
warnings.filterwarnings("ignore", category=Warning)

# ---------------------------------------------------------------------------
try:
    from PyQt6 import QtCore, QtGui, QtWidgets
    from PyQt6.QtCore import Qt, QThread
    from PyQt6.QtCore import pyqtSignal as Signal
    QT_API = "PyQt6"
except ImportError:
    from PySide6 import QtCore, QtGui, QtWidgets
    from PySide6.QtCore import Qt, QThread, Signal
    QT_API = "PySide6"

# ---------------------------------------------------------------------------
# Optional EVTX backend
# ---------------------------------------------------------------------------
try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

LEVEL_MAP = {
    "0": "LogAlways",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}

# ---------------------------------------------------------------------------
# Tool Information
# ---------------------------------------------------------------------------
TOOL_NAME = "WinEventDump"
TOOL_VERSION = "1.0"
DEVELOPER_NAME = "Me"
GITHUB_URL = "https://github.com/00xjoe"
WEBSITE_URL = "https://00xjoe.github.io/Abdulmohsen_Alwaleed/"

# ---------------------------------------------------------------------------
# Color palette - Purple/Indigo Dark Theme
# ---------------------------------------------------------------------------
COLORS = {
    "bg_main": "#0D0D1A",
    "bg_panel": "#1A1A2E",
    "bg_panel_alt": "#16213E",
    "border": "#2D2D44",
    "text": "#E0E0FF",
    "subtext": "#8B8BA7",
    "accent": "#6C63FF",
    "accent_hover": "#8B82FF",
    "success": "#00D4AA",
    "success_hover": "#33EBC5",
    "danger": "#FF4757",
    "danger_bg": "#2D0A0E",
    "warning": "#FFA502",
    "warning_bg": "#2D1F00",
    "info": "#00D4AA",
    "info_bg": "#0A2D2A",
    "purple_light": "#B8B5FF",
    "purple_dark": "#4A3FBF",
}

SEVERITY_STYLE = {
    "CRITICAL": (COLORS["danger"], COLORS["danger_bg"]),
    "MEDIUM": (COLORS["warning"], COLORS["warning_bg"]),
    "LOW": (COLORS["info"], COLORS["info_bg"]),
}

# ---------------------------------------------------------------------------
# Forensic cheat-sheet sidebar contents
# ---------------------------------------------------------------------------
CHEAT_SHEET = [
    ("Registry Hives", ["NTUSER.DAT", "SYSTEM", "SAM"]),
    ("Core & Suspicious Processes", ["lsass.exe", "svchost.exe", "cmd.exe", "powershell.exe"]),
    ("Event Logs", ["security.evtx", "system.evtx"]),
    ("File System Artifacts", ["$MFT", "$LogFile", "$UsnJrnl"]),
    ("Execution Artifacts", ["shimcache", "amcache.hve", "prefetch"]),
]

# ---------------------------------------------------------------------------
# Table columns (key in record dict -> header label)
# ---------------------------------------------------------------------------
COLUMNS = [
    ("record_id", "Record ID"),
    ("event_id", "Event ID"),
    ("level", "Level"),
    ("severity", "Severity"),
    ("time_created", "Time Created"),
    ("provider", "Provider"),
    ("channel", "Channel"),
    ("computer", "Computer"),
    ("source_file", "Source File"),
    ("summary", "Summary"),
]

WIDTHS = {
    "record_id": 90, "event_id": 80, "level": 90, "severity": 95,
    "time_created": 170, "provider": 150, "channel": 110,
    "computer": 110, "source_file": 130, "summary": 320,
}

SEARCH_FIELDS = [
    "record_id", "event_id", "level", "severity", "time_created",
    "provider", "channel", "computer", "source_file", "summary", "raw_xml",
]

# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------
CRITICAL_EVENT_IDS = {
    "1102", "4698", "4699", "4720", "4725", "4728", "4732", "4756",
    "4648", "4672", "4719", "4794", "4670", "4724",
}
MEDIUM_EVENT_IDS = {
    "4625", "4103", "4104", "7045", "7034", "4738", "5140", "5145",
    "4663", "4657", "400", "4689",
}

CRITICAL_KEYWORDS = [
    "malfind", "psxview", "hashdump", "unlinked process", "hidden process",
    "unauthorized lsass access", "sam hive", "code injection",
    "audit log was cleared", "log cleared",
]
MEDIUM_KEYWORDS = [
    "netscan", "cmdline", "dlllist", "unbacked dll", "suspicious argument",
    "unusual pid parentage", "-encodedcommand", "-enc ", "svchost.exe -k",
]
LOW_KEYWORDS = ["imageinfo", "pslist", "modules", "clean scan"]


def classify_severity(level, event_id, raw_text):
    """Classify a record into CRITICAL / MEDIUM / LOW using both the
    structured Windows event level and a keyword scan of the raw content
    (useful for generic dumps like Volatility plugin output)."""
    text = (raw_text or "").lower()

    if level in ("Critical", "Error"):
        return "CRITICAL"
    if event_id in CRITICAL_EVENT_IDS:
        return "CRITICAL"
    if any(kw in text for kw in CRITICAL_KEYWORDS):
        return "CRITICAL"

    if level == "Warning":
        return "MEDIUM"
    if event_id in MEDIUM_EVENT_IDS:
        return "MEDIUM"
    if any(kw in text for kw in MEDIUM_KEYWORDS):
        return "MEDIUM"

    return "LOW"


# ---------------------------------------------------------------------------
# EVTX parsing backend (adapted from the original Tkinter tool)
# ---------------------------------------------------------------------------
def parse_record_xml(xml_str, source_file=""):
    """Parse a single .evtx record's XML string into a flat dict, or None."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find("e:System", NS)
    if system is None:
        return None

    def gt(tag, attr=None):
        el = system.find(f"e:{tag}", NS)
        if el is None:
            return ""
        if attr:
            return el.get(attr, "")
        return el.text or ""

    event_id = gt("EventID")
    level_raw = gt("Level")
    level = LEVEL_MAP.get(level_raw, level_raw or "Information")

    event_data = {}
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for i, data in enumerate(ed.findall("e:Data", NS)):
            name = data.get("Name") or f"Data{i}"
            event_data[name] = data.text or ""
    if not event_data:
        ud = root.find("e:UserData", NS)
        if ud is not None:
            for el in ud.iter():
                tag = el.tag.split("}")[-1]
                if el.text and el.text.strip():
                    event_data[tag] = el.text.strip()

    summary = "; ".join(f"{k}={v}" for k, v in list(event_data.items())[:6])

    return {
        "source_file": source_file,
        "record_id": gt("EventRecordID"),
        "event_id": event_id,
        "level": level,
        "time_created": gt("TimeCreated", "SystemTime"),
        "provider": gt("Provider", "Name"),
        "channel": gt("Channel"),
        "computer": gt("Computer"),
        "task": gt("Task"),
        "summary": summary,
        "event_data": event_data,
        "raw_xml": xml_str,
    }


def load_evtx_file(path):
    """Return a list of parsed record dicts from a single .evtx file."""
    if evtx is None:
        raise RuntimeError("python-evtx is not installed. Run: pip install python-evtx")
    fname = os.path.basename(path)
    out = []
    with evtx.Evtx(path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
            except Exception:
                continue
            parsed = parse_record_xml(xml_str, source_file=fname)
            if parsed:
                out.append(parsed)
    return out


# ---------------------------------------------------------------------------
# Generic loader — CSV / JSON / TXT / LOG (e.g. Volatility output, raw dumps)
# ---------------------------------------------------------------------------
_PID_RE = re.compile(r"\bpid[:=]?\s*(\d+)", re.IGNORECASE)


def _make_generic_record(source_file, idx, raw_text):
    m = _PID_RE.search(raw_text)
    return {
        "source_file": source_file,
        "record_id": str(idx),
        "event_id": m.group(1) if m else "",
        "level": "",
        "time_created": "",
        "provider": "",
        "channel": "",
        "computer": "",
        "task": "",
        "summary": raw_text[:220],
        "event_data": {},
        "raw_xml": raw_text,
    }


def load_generic_file(path):
    """Best-effort loader for non-.evtx forensic dumps: JSON, CSV, or plain
    line-based text (Volatility plugin output, raw log dumps, etc.)."""
    fname = os.path.basename(path)
    ext = os.path.splitext(path)[1].lower()
    records = []

    if ext == ".json":
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            if isinstance(data, list):
                for i, item in enumerate(data):
                    records.append(_make_generic_record(fname, i, json.dumps(item, ensure_ascii=False)))
            elif isinstance(data, dict):
                for i, (k, v) in enumerate(data.items()):
                    records.append(_make_generic_record(fname, i, f"{k}: {json.dumps(v, ensure_ascii=False)}"))
            return records
        except Exception:
            pass  # fall through to line-based parsing below

    if ext == ".csv":
        with open(path, "r", newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                records.append(_make_generic_record(fname, i, ", ".join(row)))
        return records

    # Fallback: generic line-based text (also used for .txt/.log/unknown/
    # malformed .json)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            records.append(_make_generic_record(fname, i, line))
    return records


def load_any_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".evtx":
        return load_evtx_file(path)
    return load_generic_file(path)


def format_detail(rec):
    """Build the human-readable detail-pane text for a record."""
    lines = [
        f"Source File   : {rec.get('source_file', '')}",
        f"Record ID     : {rec.get('record_id', '')}",
        f"Event ID      : {rec.get('event_id', '') or '(n/a)'}",
        f"Level         : {rec.get('level', '') or '(n/a)'}",
        f"Severity      : {rec.get('severity', '')}",
        f"Time Created  : {rec.get('time_created', '') or '(n/a)'}",
        f"Provider      : {rec.get('provider', '') or '(n/a)'}",
        f"Channel       : {rec.get('channel', '') or '(n/a)'}",
        f"Computer      : {rec.get('computer', '') or '(n/a)'}",
        "",
        "EventData",
        "---------",
    ]
    if rec.get("event_data"):
        for k, v in rec["event_data"].items():
            lines.append(f"  {k} = {v}")
    else:
        lines.append("  (none)")

    lines += ["", "Raw Content", "-----------"]
    raw = rec.get("raw_xml", "")
    if raw.strip().startswith("<"):
        try:
            pretty = minidom.parseString(raw).toprettyxml(indent="  ")
            raw = "\n".join(l for l in pretty.splitlines() if l.strip())
        except Exception:
            pass
    lines.append(raw)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Background loader thread
# ---------------------------------------------------------------------------
class LoaderThread(QThread):
    progress = Signal(str)
    finished_loading = Signal(list, list)  # (records, error_messages)

    def __init__(self, paths):
        super().__init__()
        self.paths = paths

    def run(self):
        records = []
        errors = []
        for path in self.paths:
            fname = os.path.basename(path)
            self.progress.emit(f"Parsing {fname} ...")
            try:
                recs = load_any_file(path)
                for r in recs:
                    haystack = f"{r.get('raw_xml', '')} {r.get('summary', '')}"
                    r["severity"] = classify_severity(r.get("level", ""), r.get("event_id", ""), haystack)
                records.extend(recs)
            except Exception as ex:
                errors.append(f"{fname}: {ex}")
        self.finished_loading.emit(records, errors)


# ---------------------------------------------------------------------------
# Small reusable widgets
# ---------------------------------------------------------------------------
CHEAT_BTN_STYLE = """
QPushButton {
    text-align: left;
    background-color: #0D0D1A;
    color: #B8B5FF;
    border: 1px solid #2D2D44;
    border-radius: 5px;
    padding: 5px 10px;
    font-size: 11px;
}
QPushButton:hover {
    background-color: #2D2D44;
    color: #E0E0FF;
    border: 1px solid #6C63FF;
}
"""

LINK_BTN_STYLE = """
QPushButton {
    background-color: transparent;
    color: #B8B5FF;
    border: 1px solid #2D2D44;
    border-radius: 15px;
    padding: 5px 15px;
    font-size: 11px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #2D2D44;
    color: #E0E0FF;
    border: 1px solid #6C63FF;
}
"""


class MetricCard(QtWidgets.QFrame):
    def __init__(self, title, accent="#6C63FF", parent=None):
        super().__init__(parent)
        self.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #1A1A2E;
                border: 1px solid #2D2D44;
                border-left: 4px solid {accent};
                border-radius: 8px;
            }}
        """)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(2)

        self.value_label = QtWidgets.QLabel("0")
        self.value_label.setStyleSheet(
            "color:#E0E0FF; font-size:26px; font-weight:800; border:none; background:transparent;"
        )
        self.title_label = QtWidgets.QLabel(title.upper())
        self.title_label.setStyleSheet(
            "color:#8B8BA7; font-size:10px; font-weight:700; letter-spacing:1px; "
            "border:none; background:transparent;"
        )
        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, value):
        self.value_label.setText(str(value))


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{TOOL_NAME} v{TOOL_VERSION} — Windows Event Log Analysis & Dumping")
        self.resize(1500, 900)
        self.setMinimumSize(1100, 650)

        self.all_records = []
        self.filtered_records = []
        self.loader_thread = None

        self._build_ui()
        self.update_metrics()

    # ---------- UI construction ----------

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root = QtWidgets.QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_topbar())
        root.addWidget(self._build_toolbar())

        body = QtWidgets.QWidget()
        body_layout = QtWidgets.QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        body_layout.addWidget(self._build_sidebar())
        body_layout.addWidget(self._build_main_panel(), 1)
        root.addWidget(body, 1)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage(f"Ready — load Windows event logs to begin analysis. | Developed by {DEVELOPER_NAME}")
        
        # Add developer info to status bar
        engine_tag = QtWidgets.QLabel(f"  Engine: {QT_API}  ")
        engine_tag.setStyleSheet("color:#6C63FF; font-size:10px; font-weight:700;")
        self.status_bar.addPermanentWidget(engine_tag)

    def _build_topbar(self):
        bar = QtWidgets.QWidget()
        bar.setObjectName("TopBar")
        layout = QtWidgets.QHBoxLayout(bar)
        layout.setContentsMargins(20, 14, 20, 14)

        title_box = QtWidgets.QVBoxLayout()
        title_box.setSpacing(2)
        title = QtWidgets.QLabel(f"  {TOOL_NAME}")
        title.setStyleSheet("color:#E0E0FF; font-size:20px; font-weight:800;")
        subtitle = QtWidgets.QLabel(f"Windows Event Log Analysis & Dumping Tool | By {DEVELOPER_NAME}")
        subtitle.setStyleSheet("color:#8B8BA7; font-size:11px;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)
        layout.addStretch(1)

        # Website button
        self.website_btn = QtWidgets.QPushButton("  Website")
        self.website_btn.setObjectName("websiteBtn")
        self.website_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.website_btn.setStyleSheet(LINK_BTN_STYLE)
        self.website_btn.setToolTip(f"Visit {DEVELOPER_NAME}'s website: {WEBSITE_URL}")
        self.website_btn.clicked.connect(self.open_website)
        layout.addWidget(self.website_btn, 0, Qt.AlignmentFlag.AlignVCenter)

        # GitHub button
        self.github_btn = QtWidgets.QPushButton("  GitHub")
        self.github_btn.setObjectName("githubBtn")
        self.github_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.github_btn.setStyleSheet(LINK_BTN_STYLE)
        self.github_btn.setToolTip(f"Visit {DEVELOPER_NAME}'s GitHub: {GITHUB_URL}")
        self.github_btn.clicked.connect(self.open_github)
        layout.addWidget(self.github_btn, 0, Qt.AlignmentFlag.AlignVCenter)

        # Add some spacing between buttons and EVTX status
        spacer = QtWidgets.QSpacerItem(10, 10, QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Minimum)
        layout.addSpacerItem(spacer)

        evtx_status = "python-evtx: available" if evtx is not None else "python-evtx: not installed"
        evtx_tag = QtWidgets.QLabel(evtx_status)
        tag_color = "#00D4AA" if evtx is not None else "#FFA502"
        evtx_tag.setStyleSheet(
            f"color:{tag_color}; font-size:10px; font-weight:700; border:1px solid #2D2D44; "
            f"border-radius:10px; padding:4px 12px;"
        )
        layout.addWidget(evtx_tag, 0, Qt.AlignmentFlag.AlignVCenter)
        return bar

    def _build_toolbar(self):
        bar = QtWidgets.QWidget()
        bar.setObjectName("Toolbar")
        layout = QtWidgets.QHBoxLayout(bar)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(8)

        self.btn_open = QtWidgets.QPushButton("  Open File(s)")
        self.btn_open.setObjectName("btnOpen")
        self.btn_open.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_open.clicked.connect(self.open_files)
        layout.addWidget(self.btn_open)

        self.search_bar = QtWidgets.QLineEdit()
        self.search_bar.setPlaceholderText(
            "🔍  Live search — event ID, keyword, IP, username, process, artifact..."
        )
        self.search_bar.textChanged.connect(self.filter_table)
        layout.addWidget(self.search_bar, 1)

        self.btn_run = QtWidgets.QPushButton("  Run Analysis")
        self.btn_run.setObjectName("btnRun")
        self.btn_run.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_run.clicked.connect(self.run_analysis)
        layout.addWidget(self.btn_run)

        btn_csv = QtWidgets.QPushButton("⬇  Export CSV")
        btn_csv.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_csv.clicked.connect(self.export_csv)
        layout.addWidget(btn_csv)

        btn_json = QtWidgets.QPushButton("⬇  Export JSON")
        btn_json.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_json.clicked.connect(self.export_json)
        layout.addWidget(btn_json)

        btn_clear = QtWidgets.QPushButton("  Clear Grid")
        btn_clear.setObjectName("btnClear")
        btn_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_clear.clicked.connect(self.clear_grid)
        layout.addWidget(btn_clear)

        return bar

    def _build_sidebar(self):
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFixedWidth(250)
        scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QtWidgets.QLabel("  Forensic Cheat Sheet")
        header.setStyleSheet("color:#E0E0FF; font-size:13px; font-weight:800;")
        layout.addWidget(header)

        hint = QtWidgets.QLabel("Click any artifact below to filter the results grid.")
        hint.setStyleSheet("color:#6B6B8A; font-size:10px; font-style:italic;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        for category, items in CHEAT_SHEET:
            box = QtWidgets.QGroupBox(category)
            box_layout = QtWidgets.QVBoxLayout(box)
            box_layout.setSpacing(4)
            for item in items:
                btn = QtWidgets.QPushButton(item)
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.setStyleSheet(CHEAT_BTN_STYLE)
                btn.clicked.connect(lambda checked=False, term=item: self.quick_search(term))
                box_layout.addWidget(btn)
            layout.addWidget(box)

        layout.addStretch(1)
        
        # Add developer credit at bottom of sidebar
        credit = QtWidgets.QLabel(f"Developed by\n{DEVELOPER_NAME}\n{TOOL_NAME} v{TOOL_VERSION}")
        credit.setStyleSheet("color:#6B6B8A; font-size:10px; padding: 10px 0;")
        credit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(credit)
        
        scroll.setWidget(container)
        return scroll

    def _build_main_panel(self):
        panel = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        metrics_row = QtWidgets.QHBoxLayout()
        metrics_row.setSpacing(12)
        self.card_total = MetricCard("Total Events", accent=COLORS["accent"])
        self.card_critical = MetricCard("Critical Alerts", accent=COLORS["danger"])
        self.card_warning = MetricCard("Warnings", accent=COLORS["warning"])
        self.card_clean = MetricCard("Clean Items", accent=COLORS["info"])
        for card in (self.card_total, self.card_critical, self.card_warning, self.card_clean):
            metrics_row.addWidget(card)
        layout.addLayout(metrics_row)

        splitter = QtWidgets.QSplitter(Qt.Orientation.Vertical)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(len(COLUMNS))
        self.table.setHorizontalHeaderLabels([label for _, label in COLUMNS])
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(26)
        for i, (key, _label) in enumerate(COLUMNS):
            self.table.setColumnWidth(i, WIDTHS.get(key, 100))
        self.table.horizontalHeader().setSectionResizeMode(
            len(COLUMNS) - 1, QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self.table.itemSelectionChanged.connect(self.on_row_selected)

        self.detail_text = QtWidgets.QPlainTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setPlaceholderText("Select a row to view full parsed details and raw content...")

        splitter.addWidget(self.table)
        splitter.addWidget(self.detail_text)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter, 1)
        return panel

    # ---------- External Links ----------
    
    def open_github(self):
        """Open the developer's GitHub profile in the default browser."""
        webbrowser.open(GITHUB_URL)

    def open_website(self):
        """Open the developer's personal website in the default browser."""
        webbrowser.open(WEBSITE_URL)

    # ---------- File loading ----------

    def open_files(self):
        paths, _ = QtWidgets.QFileDialog.getOpenFileNames(
            self,
            "Select Windows event log file(s)",
            "",
            "Windows Event Log (*.evtx);;"
            "Forensic Artifacts (*.evtx *.csv *.json *.txt *.log);;All Files (*)",
        )
        if paths:
            self._start_loading(paths)

    def _start_loading(self, paths):
        self.btn_open.setEnabled(False)
        self.status_bar.showMessage(f"Loading {len(paths)} file(s)...")
        self.loader_thread = LoaderThread(paths)
        self.loader_thread.progress.connect(self.status_bar.showMessage)
        self.loader_thread.finished_loading.connect(self.on_load_finished)
        self.loader_thread.start()

    def on_load_finished(self, records, errors):
        self.btn_open.setEnabled(True)
        self.all_records.extend(records)
        self.filtered_records = list(self.all_records)
        self.refresh_table()
        self.update_metrics()

        n_files = len({r["source_file"] for r in self.all_records}) if self.all_records else 0
        msg = f"Loaded {len(self.all_records)} record(s) from {n_files} file(s)."
        if errors:
            msg += f"  {len(errors)} file error(s)."
        self.status_bar.showMessage(msg)
        if errors:
            QtWidgets.QMessageBox.warning(self, "Some files had errors", "\n".join(errors))

    # ---------- Filtering / search ----------

    def filter_table(self, text):
        text = text.strip().lower()
        if not text:
            self.filtered_records = list(self.all_records)
        else:
            def matches(rec):
                for field in SEARCH_FIELDS:
                    v = rec.get(field, "")
                    if v and text in str(v).lower():
                        return True
                return False
            self.filtered_records = [r for r in self.all_records if matches(r)]

        self.refresh_table()
        self.update_metrics()
        self.status_bar.showMessage(
            f"Showing {len(self.filtered_records)} of {len(self.all_records)} record(s)."
        )

    def quick_search(self, term):
        self.search_bar.setText(term)

    # ---------- Analysis ----------

    def run_analysis(self):
        if not self.filtered_records:
            QtWidgets.QMessageBox.information(
                self, "Nothing to analyze", "Load one or more Windows event log files first."
            )
            return
        crit = sum(1 for r in self.filtered_records if r.get("severity") == "CRITICAL")
        med = sum(1 for r in self.filtered_records if r.get("severity") == "MEDIUM")
        low = len(self.filtered_records) - crit - med
        self.refresh_table()
        self.update_metrics()
        self.status_bar.showMessage(
            f"Analysis complete — {crit} critical, {med} warning, {low} clean, "
            f"of {len(self.filtered_records)} record(s) in view."
        )
        QtWidgets.QMessageBox.information(
            self,
            "Analysis complete",
            f"Critical Alerts : {crit}\nWarnings        : {med}\nClean Items     : {low}\n\n"
            f"Total in current view: {len(self.filtered_records)}",
        )

    # ---------- Table population ----------

    def refresh_table(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.filtered_records))
        for row, rec in enumerate(self.filtered_records):
            sev = rec.get("severity", "LOW")
            fg, bg = SEVERITY_STYLE.get(sev, SEVERITY_STYLE["LOW"])
            for col, (key, _label) in enumerate(COLUMNS):
                item = QtWidgets.QTableWidgetItem(str(rec.get(key, "")))
                item.setForeground(QtGui.QColor(fg))
                item.setBackground(QtGui.QColor(bg))
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, rec)
                self.table.setItem(row, col, item)
        self.table.setSortingEnabled(True)

    def on_row_selected(self):
        items = self.table.selectedItems()
        if not items:
            return
        row = items[0].row()
        first_item = self.table.item(row, 0)
        if not first_item:
            return
        rec = first_item.data(Qt.ItemDataRole.UserRole)
        if rec:
            self.detail_text.setPlainText(format_detail(rec))

    # ---------- Metrics ----------

    def update_metrics(self):
        total = len(self.filtered_records)
        crit = sum(1 for r in self.filtered_records if r.get("severity") == "CRITICAL")
        med = sum(1 for r in self.filtered_records if r.get("severity") == "MEDIUM")
        low = total - crit - med
        self.card_total.set_value(total)
        self.card_critical.set_value(crit)
        self.card_warning.set_value(med)
        self.card_clean.set_value(low)

    # ---------- Clear ----------

    def clear_grid(self):
        self.all_records = []
        self.filtered_records = []
        self.table.setRowCount(0)
        self.detail_text.clear()
        self.search_bar.clear()
        self.update_metrics()
        self.status_bar.showMessage("Grid cleared. Load Windows event logs to begin.")

    # ---------- Export ----------

    def export_csv(self):
        if not self.filtered_records:
            QtWidgets.QMessageBox.information(
                self, "Nothing to export", "No records in the current filtered view."
            )
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export to CSV", "", "CSV Files (*.csv)")
        if not path:
            return
        if not path.lower().endswith(".csv"):
            path += ".csv"
        fields = [key for key, _ in COLUMNS]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for rec in self.filtered_records:
                    writer.writerow(rec)
            QtWidgets.QMessageBox.information(
                self, "Export complete", f"Exported {len(self.filtered_records)} record(s) to:\n{path}"
            )
        except Exception as ex:
            QtWidgets.QMessageBox.critical(self, "Export failed", str(ex))

    def export_json(self):
        if not self.filtered_records:
            QtWidgets.QMessageBox.information(
                self, "Nothing to export", "No records in the current filtered view."
            )
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export to JSON", "", "JSON Files (*.json)")
        if not path:
            return
        if not path.lower().endswith(".json"):
            path += ".json"
        data = [{k: v for k, v in rec.items() if k != "raw_xml"} for rec in self.filtered_records]
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            QtWidgets.QMessageBox.information(
                self, "Export complete", f"Exported {len(self.filtered_records)} record(s) to:\n{path}"
            )
        except Exception as ex:
            QtWidgets.QMessageBox.critical(self, "Export failed", str(ex))


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
STYLE_SHEET = """
QMainWindow, QWidget { background-color: #0D0D1A; }

QWidget#TopBar { background-color: #1A1A2E; border-bottom: 1px solid #2D2D44; }
QWidget#Toolbar { background-color: #0D0D1A; border-bottom: 1px solid #2D2D44; }

QLabel { color: #E0E0FF; }

QPushButton {
    background-color: #1A1A2E;
    color: #E0E0FF;
    border: 1px solid #2D2D44;
    border-radius: 6px;
    padding: 7px 14px;
    font-weight: 600;
    font-size: 12px;
}
QPushButton:hover { background-color: #2D2D44; border: 1px solid #6C63FF; }
QPushButton:pressed { background-color: #0D0D1A; }
QPushButton:disabled { color: #6B6B8A; background-color: #1A1A2E; border: 1px solid #1A1A2E; }

QPushButton#btnOpen { background-color: #6C63FF; color: #0D0D1A; border: 1px solid #6C63FF; }
QPushButton#btnOpen:hover { background-color: #8B82FF; }

QPushButton#btnRun { background-color: #00D4AA; color: #0D0D1A; border: 1px solid #00D4AA; }
QPushButton#btnRun:hover { background-color: #33EBC5; }

QPushButton#btnClear { background-color: transparent; color: #FF4757; border: 1px solid #FF4757; }
QPushButton#btnClear:hover { background-color: #2D0A0E; }

QPushButton#githubBtn, QPushButton#websiteBtn { 
    background-color: transparent; 
    color: #B8B5FF; 
    border: 1px solid #2D2D44; 
    border-radius: 15px;
    padding: 5px 15px;
}
QPushButton#githubBtn:hover, QPushButton#websiteBtn:hover { 
    background-color: #2D2D44; 
    color: #E0E0FF; 
    border: 1px solid #6C63FF; 
}

QLineEdit {
    background-color: #1A1A2E;
    color: #E0E0FF;
    border: 1px solid #2D2D44;
    border-radius: 6px;
    padding: 7px 12px;
    font-size: 12px;
}
QLineEdit:focus { border: 1px solid #6C63FF; }

QTableWidget {
    background-color: #1A1A2E;
    alternate-background-color: #16213E;
    color: #E0E0FF;
    gridline-color: #2D2D44;
    border: 1px solid #2D2D44;
    border-radius: 8px;
    selection-background-color: #2D2D44;
    selection-color: #E0E0FF;
    font-size: 12px;
}
QHeaderView::section {
    background-color: #0D0D1A;
    color: #B8B5FF;
    padding: 7px;
    border: none;
    border-bottom: 2px solid #2D2D44;
    font-weight: 700;
    font-size: 11px;
}

QPlainTextEdit {
    background-color: #0D0D1A;
    color: #C0C0E0;
    border: 1px solid #2D2D44;
    border-radius: 8px;
    padding: 8px;
    font-family: Consolas, "Cascadia Code", monospace;
    font-size: 11px;
}

QScrollArea { border: none; background-color: transparent; }
QGroupBox {
    color: #B8B5FF;
    border: 1px solid #2D2D44;
    border-radius: 8px;
    margin-top: 12px;
    font-weight: 700;
    font-size: 11px;
    padding-top: 14px;
    background-color: #13132B;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
}

QStatusBar { background-color: #0D0D1A; color: #8B8BA7; border-top: 1px solid #2D2D44; font-size: 11px; }
QSplitter::handle { background-color: #2D2D44; }

QScrollBar:vertical { background: #0D0D1A; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #2D2D44; border-radius: 5px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: #6C63FF; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal { background: #0D0D1A; height: 10px; margin: 0; }
QScrollBar::handle:horizontal { background: #2D2D44; border-radius: 5px; min-width: 24px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

QMessageBox { background-color: #1A1A2E; }
"""


def main():
    # Suppress GTK warnings
    import logging
    logging.getLogger('GTK').setLevel(logging.CRITICAL)
    
    # Set software rendering before creating QApplication
    if hasattr(QtCore.Qt, "AA_UseSoftwareOpenGL"):
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.ApplicationAttribute.AA_UseSoftwareOpenGL, True)
    
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE_SHEET)

    if evtx is None:
        print("NOTE: python-evtx not found. .evtx files will fail to parse. "
              "Install it with: pip install python-evtx")

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
