#!/usr/bin/env python3
"""CyberShield premium interface using the existing Python backend."""

import os
import sys
import types

from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QFont, QFontDatabase, QColor, QBrush
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
    QGraphicsOpacityEffect,
)

# Load the existing backend without starting its original QApplication.
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_DIR)
MAIN_PATH = os.path.join(APP_DIR, "main.py")
os.chdir(PROJECT_ROOT)

if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

with open(MAIN_PATH, "r", encoding="utf-8") as fh:
    source = fh.read()

MARKER = "# =========================================================\n# START APPLICATION"
if MARKER not in source:
    raise RuntimeError("Could not find START APPLICATION marker in app/main.py")

backend_source = source.split(MARKER, 1)[0]
backend = types.ModuleType("cybershield_backend")
backend.__file__ = MAIN_PATH
exec(compile(backend_source, MAIN_PATH, "exec"), backend.__dict__)
BaseMainWindow = backend.MainWindow


def best_family():
    families = set(QFontDatabase.families())
    for name in ("Inter", "Noto Sans", "DejaVu Sans", "Liberation Sans"):
        if name in families:
            return name
    return QApplication.font().family()


def font_for(size=10, weight=QFont.Weight.Normal, spacing=0.0, family=None):
    f = QFont(family or best_family())
    f.setPointSizeF(float(size))
    f.setWeight(weight)
    if spacing:
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, float(spacing))
    return f


def set_font(widget, size=10, weight=QFont.Weight.Normal, spacing=0.0, family=None):
    widget.setFont(font_for(size, weight, spacing, family))
    return widget


def label(text, role=None, wrap=False):
    w = QLabel(text)
    if role:
        w.setObjectName(role)
    w.setWordWrap(wrap)
    return w


def card(name="card"):
    w = QFrame()
    w.setObjectName(name)
    return w


def add_shadowless_card_layout(widget, margins=(22, 20, 22, 20), spacing=12):
    lay = QVBoxLayout(widget)
    lay.setContentsMargins(*margins)
    lay.setSpacing(spacing)
    return lay


class MetricCard(QFrame):
    def __init__(self, eyebrow, value, helper, accent="teal"):
        super().__init__()
        self.setObjectName("metricCard")
        self.setProperty("accent", accent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(5)

        self.eyebrow = label(eyebrow.upper(), "metricEyebrow")
        self.value = label(value, "metricValue")
        self.helper = label(helper, "metricHelp", True)
        set_font(self.eyebrow, 8.8, QFont.Weight.DemiBold, 0.9)
        set_font(self.value, 17.5, QFont.Weight.DemiBold, 0.25)
        set_font(self.helper, 9.3, QFont.Weight.Normal, 0.05)

        lay.addWidget(self.eyebrow)
        lay.addWidget(self.value)
        lay.addWidget(self.helper)
        lay.addStretch()


class PremiumMainWindow(BaseMainWindow):
    PAGE_META = [
        ("Dashboard", "Live overview of the authorised assessment", "OVERVIEW"),
        ("Target + Scope", "Define the private lab target and confirm permission", "STEP 1"),
        ("Reconnaissance", "Discover exposed services and version information", "STEP 2"),
        ("Vulnerabilities + AI", "Match NVD findings, then explain them with local AI", "STEP 3"),
        ("Controlled Testing", "Run only the predefined verification after explicit approval", "STEP 4"),
        ("Evidence", "Review the audit trail created by controlled testing", "STEP 5"),
        ("Report", "Turn the current assessment into a readable security report", "STEP 6"),
        ("Validation", "Benchmark the prototype against its success criteria", "STEP 7"),
    ]

    NAV = [
        ("Overview", "Dashboard"),
        ("01", "Target + Scope"),
        ("02", "Reconnaissance"),
        ("03", "Vulnerabilities + AI"),
        ("04", "Controlled Testing"),
        ("05", "Evidence"),
        ("06", "Report"),
        ("07", "Validation"),
    ]

    def __init__(self):
        super().__init__()

        self.setWindowTitle("CyberShield — AI-Assisted Penetration Testing")
        self.resize(1540, 940)
        self.setMinimumSize(1180, 760)

        # Keep the backend widgets but replace the original layouts/pages.
        old_stack = self.takeCentralWidget()

        self.stack = QStackedWidget()
        self.stack.setObjectName("workspaceStack")

        self.home_page = self.build_dashboard()
        self.target_page = self.build_target_page()
        self.scan_page = self.build_scan_page()
        self.vulnerability_page = self.build_vulnerability_page()
        self.testing_page = self.build_testing_page()
        self.evidence_page = self.build_evidence_page()
        self.report_page = self.build_report_page()
        self.validation_page = self.build_validation_page()

        for page in (
            self.home_page,
            self.target_page,
            self.scan_page,
            self.vulnerability_page,
            self.testing_page,
            self.evidence_page,
            self.report_page,
            self.validation_page,
        ):
            self.stack.addWidget(page)

        self.build_shell()
        self.configure_backend_widgets()
        self.apply_theme()

        self.stack.currentChanged.connect(self.on_page_changed)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_live_state)
        self.refresh_timer.start(650)

        self._last_vuln_rows = -1
        self._last_validation_rows = -1
        self._last_evidence_rows = -1

        self.stack.setCurrentWidget(self.home_page)
        self.on_page_changed(0)
        self.refresh_live_state()

        # Old pages are no longer needed. The functional widgets were reparented.
        old_stack.hide()
        QTimer.singleShot(1000, old_stack.deleteLater)

    def build_shell(self):
        root = QWidget()
        root.setObjectName("root")
        root_lay = QHBoxLayout(root)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(252)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(20, 24, 20, 20)
        side.setSpacing(9)

        brand_row = QHBoxLayout()
        brand_row.setSpacing(12)
        logo = QLabel("CS")
        logo.setObjectName("logoBadge")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setFixedSize(48, 48)
        set_font(logo, 13, QFont.Weight.Bold, 0.5)

        brand_text = QVBoxLayout()
        brand_text.setSpacing(1)
        brand = label("CyberShield", "brand")
        brand_sub = label("SECURITY WORKSPACE", "brandSub")
        set_font(brand, 15.5, QFont.Weight.DemiBold, 0.35)
        set_font(brand_sub, 7.8, QFont.Weight.DemiBold, 1.15)
        brand_text.addWidget(brand)
        brand_text.addWidget(brand_sub)
        brand_row.addWidget(logo)
        brand_row.addLayout(brand_text, 1)
        side.addLayout(brand_row)
        side.addSpacing(18)

        menu_label = label("ASSESSMENT FLOW", "sideLabel")
        set_font(menu_label, 8.2, QFont.Weight.DemiBold, 1.05)
        side.addWidget(menu_label)

        self.nav_buttons = []
        actions = [
            self.open_home_page,
            self.open_target_page,
            self.open_scan_page,
            self.open_vulnerability_page,
            self.open_testing_page,
            self.open_evidence_page,
            self.open_report_page,
            self.open_validation_page,
        ]

        for (step, text), action in zip(self.NAV, actions):
            b = QPushButton()
            b.setObjectName("navButton")
            b.setProperty("active", False)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumHeight(48)
            b.setText(f"{step}    {text}")
            set_font(b, 10.2, QFont.Weight.Medium, 0.18)
            b.clicked.connect(action)
            self.nav_buttons.append(b)
            side.addWidget(b)

        side.addStretch()

        lab_card = card("labCard")
        lab_lay = add_shadowless_card_layout(lab_card, (15, 14, 15, 14), 7)
        lab_title = label("●  AUTHORISED LAB", "labTitle")
        set_font(lab_title, 8.7, QFont.Weight.DemiBold, 0.65)
        lab_desc = label(
            "Private targets only.\nLocal AI explains. Python controls.\nYou approve the final verification.",
            "labText",
            True,
        )
        set_font(lab_desc, 8.9, QFont.Weight.Normal, 0.04)
        lab_lay.addWidget(lab_title)
        lab_lay.addWidget(lab_desc)
        side.addWidget(lab_card)

        main = QWidget()
        main.setObjectName("mainArea")
        main_lay = QVBoxLayout(main)
        main_lay.setContentsMargins(0, 0, 0, 0)
        main_lay.setSpacing(0)

        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar_lay = QHBoxLayout(topbar)
        topbar_lay.setContentsMargins(30, 17, 30, 17)
        topbar_lay.setSpacing(12)

        top_text = QVBoxLayout()
        top_text.setSpacing(2)
        self.top_kicker = label("OVERVIEW", "topKicker")
        self.top_title = label("Dashboard", "topTitle")
        self.top_subtitle = label("Live overview of the authorised assessment", "topSubtitle")
        set_font(self.top_kicker, 7.7, QFont.Weight.DemiBold, 1.2)
        set_font(self.top_title, 17.5, QFont.Weight.DemiBold, 0.45)
        set_font(self.top_subtitle, 9.3, QFont.Weight.Normal, 0.05)
        top_text.addWidget(self.top_kicker)
        top_text.addWidget(self.top_title)
        top_text.addWidget(self.top_subtitle)

        self.target_pill = label("NO TARGET", "targetPill")
        self.target_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        set_font(self.target_pill, 8.5, QFont.Weight.DemiBold, 0.55)

        self.ai_pill = label("LOCAL AI", "aiPill")
        self.ai_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        set_font(self.ai_pill, 8.5, QFont.Weight.DemiBold, 0.55)

        topbar_lay.addLayout(top_text)
        topbar_lay.addStretch()
        topbar_lay.addWidget(self.target_pill)
        topbar_lay.addWidget(self.ai_pill)

        content = QWidget()
        content.setObjectName("content")
        content_lay = QVBoxLayout(content)
        content_lay.setContentsMargins(24, 20, 24, 24)
        content_lay.addWidget(self.stack)

        main_lay.addWidget(topbar)
        main_lay.addWidget(content, 1)

        root_lay.addWidget(sidebar)
        root_lay.addWidget(main, 1)
        self.setCentralWidget(root)

    def page_header(self, eyebrow, title_text, body_text):
        box = QVBoxLayout()
        box.setSpacing(5)
        eyebrow_w = label(eyebrow.upper(), "pageEyebrow")
        title_w = label(title_text, "pageTitle")
        body_w = label(body_text, "pageDescription", True)
        set_font(eyebrow_w, 8.1, QFont.Weight.DemiBold, 1.2)
        set_font(title_w, 21.5, QFont.Weight.DemiBold, 0.45)
        set_font(body_w, 10.1, QFont.Weight.Normal, 0.06)
        box.addWidget(eyebrow_w)
        box.addWidget(title_w)
        box.addWidget(body_w)
        return box

    def section_title(self, title_text, subtitle=None):
        wrap = QVBoxLayout()
        wrap.setSpacing(3)
        title_w = label(title_text, "sectionTitle")
        set_font(title_w, 12.8, QFont.Weight.DemiBold, 0.35)
        wrap.addWidget(title_w)
        if subtitle:
            sub = label(subtitle, "sectionSub", True)
            set_font(sub, 9.2, QFont.Weight.Normal, 0.05)
            wrap.addWidget(sub)
        return wrap

    def make_button(self, text, role, slot=None):
        button = QPushButton(text)
        button.setProperty("role", role)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setMinimumHeight(44 if role == "primary" else 42)
        if role == "primary":
            set_font(button, 10.0, QFont.Weight.DemiBold, 0.25)
        else:
            set_font(button, 9.8, QFont.Weight.Medium, 0.18)
        if slot:
            button.clicked.connect(slot)
        return button

    def make_primary(self, text, slot=None):
        return self.make_button(text, "primary", slot)

    def make_secondary(self, text, slot=None):
        return self.make_button(text, "secondary", slot)

    def make_soft_badge(self, text, kind="neutral"):
        w = label(text, "softBadge")
        w.setProperty("kind", kind)
        w.setAlignment(Qt.AlignmentFlag.AlignCenter)
        set_font(w, 8.1, QFont.Weight.DemiBold, 0.55)
        return w

    def form_label(self, text):
        w = label(text, "formLabel")
        set_font(w, 9.2, QFont.Weight.DemiBold, 0.18)
        return w

    def wrap_scroll(self, body):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(body)
        return scroll

    def build_dashboard(self):
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(16)

        hero = card("hero")
        hero_lay = QHBoxLayout(hero)
        hero_lay.setContentsMargins(28, 26, 28, 26)
        hero_lay.setSpacing(28)

        left = QVBoxLayout()
        left.setSpacing(9)
        hero_kicker = label("AI-ASSISTED • HUMAN-CONTROLLED", "heroKicker")
        hero_title = label("Security testing that feels guided, calm and clear.", "heroTitle", True)
        hero_body = label(
            "One workspace for authorised targeting, Nmap reconnaissance, NVD analysis, local AI explanation, controlled verification, evidence and reporting.",
            "heroBody",
            True,
        )
        set_font(hero_kicker, 8.0, QFont.Weight.DemiBold, 1.1)
        set_font(hero_title, 25.5, QFont.Weight.DemiBold, 0.55)
        set_font(hero_body, 10.4, QFont.Weight.Normal, 0.08)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        actions.addWidget(self.make_primary("Authorise a target", self.open_target_page))
        actions.addWidget(self.make_secondary("View findings", self.open_vulnerability_page))
        actions.addStretch()

        left.addWidget(hero_kicker)
        left.addWidget(hero_title)
        left.addWidget(hero_body)
        left.addSpacing(8)
        left.addLayout(actions)
        left.addStretch()

        readiness = card("readinessCard")
        readiness.setFixedWidth(360)
        ready_lay = add_shadowless_card_layout(readiness, (20, 18, 20, 18), 10)
        ready_head = QHBoxLayout()
        ready_title = label("Assessment readiness", "sectionTitle")
        set_font(ready_title, 12.5, QFont.Weight.DemiBold, 0.3)
        self.readiness_value = label("0 / 4", "readinessValue")
        set_font(self.readiness_value, 10.5, QFont.Weight.DemiBold, 0.35)
        ready_head.addWidget(ready_title)
        ready_head.addStretch()
        ready_head.addWidget(self.readiness_value)
        ready_lay.addLayout(ready_head)

        self.readiness_bar = QProgressBar()
        self.readiness_bar.setObjectName("readinessBar")
        self.readiness_bar.setRange(0, 4)
        self.readiness_bar.setTextVisible(False)
        self.readiness_bar.setFixedHeight(8)
        ready_lay.addWidget(self.readiness_bar)

        self.readiness_labels = {}
        for key, txt in (
            ("authorised", "Authorised private target"),
            ("scan", "Reconnaissance complete"),
            ("findings", "Verified findings available"),
            ("ai", "Local AI explanation ready"),
        ):
            row = QHBoxLayout()
            dot = label("●", "stateDot")
            text_w = label(txt, "stateText")
            set_font(dot, 9.2, QFont.Weight.Bold)
            set_font(text_w, 9.25, QFont.Weight.Medium, 0.08)
            row.addWidget(dot)
            row.addWidget(text_w, 1)
            ready_lay.addLayout(row)
            self.readiness_labels[key] = dot
        ready_lay.addStretch()

        hero_lay.addLayout(left, 1)
        hero_lay.addWidget(readiness)
        outer.addWidget(hero)

        metrics = QHBoxLayout()
        metrics.setSpacing(13)
        self.metric_target = MetricCard("Target", "Not selected", "Private lab IP", "teal")
        self.metric_services = MetricCard("Services", "0", "Detected by Nmap", "blue")
        self.metric_findings = MetricCard("Findings", "0", "Verified NVD results", "violet")
        self.metric_gate = MetricCard("Test gate", "Locked", "Human approval required", "amber")
        for w in (self.metric_target, self.metric_services, self.metric_findings, self.metric_gate):
            metrics.addWidget(w, 1)
        outer.addLayout(metrics)

        bottom = QHBoxLayout()
        bottom.setSpacing(13)

        workflow = card("panel")
        flow_lay = add_shadowless_card_layout(workflow, (22, 20, 22, 20), 13)
        flow_lay.addLayout(self.section_title("Guided workflow", "Four clear stages instead of a wall of tools."))

        flow_grid = QGridLayout()
        flow_grid.setHorizontalSpacing(10)
        flow_grid.setVerticalSpacing(10)
        stages = [
            ("01", "AUTHORISE", "Confirm target and scope", "teal"),
            ("02", "DISCOVER", "Scan services and versions", "blue"),
            ("03", "UNDERSTAND", "Match CVEs and explain", "violet"),
            ("04", "VERIFY", "Approve, test, record", "amber"),
        ]
        for col, (num, name, desc, accent) in enumerate(stages):
            stage = card("stageCard")
            stage.setProperty("accent", accent)
            sl = QVBoxLayout(stage)
            sl.setContentsMargins(16, 15, 16, 15)
            sl.setSpacing(6)
            num_w = label(num, "stageNumber")
            name_w = label(name, "stageName")
            desc_w = label(desc, "stageDescription", True)
            set_font(num_w, 8.3, QFont.Weight.DemiBold, 0.8)
            set_font(name_w, 10.0, QFont.Weight.DemiBold, 0.45)
            set_font(desc_w, 8.8, QFont.Weight.Normal, 0.03)
            sl.addWidget(num_w)
            sl.addWidget(name_w)
            sl.addWidget(desc_w)
            flow_grid.addWidget(stage, 0, col)
        flow_lay.addLayout(flow_grid)
        flow_lay.addStretch()

        quick = card("panel")
        quick.setFixedWidth(345)
        quick_lay = add_shadowless_card_layout(quick, (22, 20, 22, 20), 11)
        quick_lay.addLayout(self.section_title("Quick actions", "Jump straight to the work you need."))
        for text, slot in (
            ("Run reconnaissance", self.open_scan_page),
            ("Analyse vulnerabilities", self.open_vulnerability_page),
            ("Review evidence", self.open_evidence_page),
            ("Generate report", self.open_report_page),
        ):
            quick_lay.addWidget(self.make_secondary(text, slot))
        quick_lay.addStretch()

        bottom.addWidget(workflow, 1)
        bottom.addWidget(quick)
        outer.addLayout(bottom, 1)
        return page

    def build_target_page(self):
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(16)
        outer.addLayout(self.page_header("Step 1 · Authorisation", "Target + Scope", "Define exactly what may be tested before any scanning begins."))

        body = QHBoxLayout()
        body.setSpacing(14)

        form = card("panel")
        form_lay = add_shadowless_card_layout(form, (24, 22, 24, 22), 12)
        form_lay.addLayout(self.section_title("Assessment details", "These details follow the assessment into evidence and reporting."))

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(8)

        self.project_name.setPlaceholderText("e.g. Metasploitable validation")
        self.target_ip.setPlaceholderText("e.g. 192.168.3.129")
        self.tester_name.setPlaceholderText("Tester name")
        self.scope_notes.setPlaceholderText("Describe what is authorised and any limits on testing...")
        self.scope_notes.setMinimumHeight(120)
        self.scope_notes.setMaximumHeight(170)

        grid.addWidget(self.form_label("Project name"), 0, 0)
        grid.addWidget(self.form_label("Tester"), 0, 1)
        grid.addWidget(self.project_name, 1, 0)
        grid.addWidget(self.tester_name, 1, 1)
        grid.addWidget(self.form_label("Private target IP"), 2, 0, 1, 2)
        grid.addWidget(self.target_ip, 3, 0, 1, 2)
        grid.addWidget(self.form_label("Authorised scope"), 4, 0, 1, 2)
        grid.addWidget(self.scope_notes, 5, 0, 1, 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        form_lay.addLayout(grid)

        auth_box = card("authorisationBox")
        auth_lay = QHBoxLayout(auth_box)
        auth_lay.setContentsMargins(15, 13, 15, 13)
        auth_title = QVBoxLayout()
        a1 = label("Authorisation required", "authTitle")
        a2 = label("The prototype accepts private laboratory IP addresses only.", "authText", True)
        set_font(a1, 9.5, QFont.Weight.DemiBold, 0.2)
        set_font(a2, 8.8, QFont.Weight.Normal, 0.03)
        auth_title.addWidget(a1)
        auth_title.addWidget(a2)
        auth_lay.addLayout(auth_title, 1)
        auth_lay.addWidget(self.authorised_checkbox)
        form_lay.addWidget(auth_box)

        save_row = QHBoxLayout()
        save_row.addStretch()
        save_row.addWidget(self.make_secondary("Save target", self.save_target))
        save_row.addWidget(self.make_primary("Save + continue", self.save_target_and_continue))
        form_lay.addLayout(save_row)

        side = card("infoPanel")
        side.setFixedWidth(360)
        side_lay = add_shadowless_card_layout(side, (22, 21, 22, 21), 12)
        side_lay.addLayout(self.section_title("Before you scan", "A clean scope keeps the rest of the workflow trustworthy."))
        for n, title_text, desc in (
            ("01", "Use a private lab IP", "Public targets are blocked by the backend."),
            ("02", "Write the scope", "Record what is allowed before running tools."),
            ("03", "Confirm permission", "Scanning is disabled until authorisation is saved."),
        ):
            item = card("tipCard")
            il = QHBoxLayout(item)
            il.setContentsMargins(13, 12, 13, 12)
            num = label(n, "tipNumber")
            set_font(num, 8.2, QFont.Weight.DemiBold, 0.7)
            texts = QVBoxLayout()
            texts.setSpacing(2)
            t1 = label(title_text, "tipTitle")
            t2 = label(desc, "tipText", True)
            set_font(t1, 9.2, QFont.Weight.DemiBold, 0.12)
            set_font(t2, 8.5, QFont.Weight.Normal)
            texts.addWidget(t1)
            texts.addWidget(t2)
            il.addWidget(num)
            il.addLayout(texts, 1)
            side_lay.addWidget(item)
        side_lay.addStretch()

        body.addWidget(form, 1)
        body.addWidget(side)
        outer.addLayout(body, 1)
        return page

    def save_target_and_continue(self):
        before = self.saved_target
        self.save_target()
        if self.saved_target and (self.saved_target != before or self.target_authorised):
            self.open_scan_page()

    def build_scan_page(self):
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(14)
        outer.addLayout(self.page_header("Step 2 · Discovery", "Reconnaissance", "Identify open ports, services and version information on the authorised target."))

        summary = QHBoxLayout()
        summary.setSpacing(13)

        target_card = card("miniPanel")
        tc = add_shadowless_card_layout(target_card, (20, 17, 20, 17), 5)
        target_eyebrow = label("AUTHORISED TARGET", "miniEyebrow")
        set_font(target_eyebrow, 7.8, QFont.Weight.DemiBold, 1.0)
        self.scan_target_label.setObjectName("bigInlineValue")
        set_font(self.scan_target_label, 12.0, QFont.Weight.DemiBold, 0.28)
        tc.addWidget(target_eyebrow)
        tc.addWidget(self.scan_target_label)
        tc.addStretch()

        action_card = card("miniPanel")
        ac = QHBoxLayout(action_card)
        ac.setContentsMargins(20, 16, 20, 16)
        status_box = QVBoxLayout()
        status_box.setSpacing(4)
        small = label("SCAN STATUS", "miniEyebrow")
        set_font(small, 7.8, QFont.Weight.DemiBold, 1.0)
        self.scan_status.setObjectName("statusText")
        set_font(self.scan_status, 10.0, QFont.Weight.DemiBold, 0.15)
        status_box.addWidget(small)
        status_box.addWidget(self.scan_status)
        ac.addLayout(status_box, 1)
        ac.addWidget(self.start_scan_button)

        summary.addWidget(target_card, 1)
        summary.addWidget(action_card, 2)
        outer.addLayout(summary)

        table_card = card("panel")
        tl = add_shadowless_card_layout(table_card, (20, 18, 20, 18), 10)
        head = QHBoxLayout()
        head.addLayout(self.section_title("Discovered services", "Nmap service/version detection from the latest authorised scan."))
        head.addStretch()
        self.services_badge = self.make_soft_badge("0 SERVICES", "blue")
        head.addWidget(self.services_badge)
        tl.addLayout(head)
        tl.addWidget(self.scan_table, 1)
        outer.addWidget(table_card, 1)
        return page

    def build_vulnerability_page(self):
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(14)
        outer.addLayout(self.page_header("Step 3 · Analysis", "Vulnerabilities + AI", "Use NVD for technical findings, then let local Ollama explain what those verified findings mean."))

        actions = card("actionBar")
        al = QHBoxLayout(actions)
        al.setContentsMargins(18, 14, 18, 14)
        status_box = QVBoxLayout()
        status_box.setSpacing(3)
        s1 = label("ANALYSIS STATUS", "miniEyebrow")
        set_font(s1, 7.8, QFont.Weight.DemiBold, 1.0)
        self.vulnerability_status.setObjectName("statusText")
        set_font(self.vulnerability_status, 9.7, QFont.Weight.DemiBold, 0.15)
        status_box.addWidget(s1)
        status_box.addWidget(self.vulnerability_status)
        al.addLayout(status_box, 1)
        al.addWidget(self.analyse_button)
        al.addWidget(self.ai_button)
        outer.addWidget(actions)

        findings_card = card("panel")
        fl = add_shadowless_card_layout(findings_card, (20, 18, 20, 18), 9)
        head = QHBoxLayout()
        head.addLayout(self.section_title("Verified findings", "CVE, CVSS and description data are sourced from the vulnerability analysis layer."))
        head.addStretch()
        self.findings_badge = self.make_soft_badge("0 FINDINGS", "violet")
        head.addWidget(self.findings_badge)
        fl.addLayout(head)
        self.vulnerability_table.setMinimumHeight(260)
        fl.addWidget(self.vulnerability_table, 1)
        outer.addWidget(findings_card, 3)

        ai_card = card("panel")
        ail = add_shadowless_card_layout(ai_card, (20, 17, 20, 18), 9)
        ai_head = QHBoxLayout()
        ai_head.addLayout(self.section_title("Local AI explanation", "Interpretation only — the model does not choose or execute tests."))
        ai_head.addStretch()
        self.ai_status.setObjectName("statusPillText")
        set_font(self.ai_status, 8.8, QFont.Weight.Medium, 0.1)
        ai_head.addWidget(self.ai_status)
        ail.addLayout(ai_head)
        self.ai_output.setMinimumHeight(150)
        ail.addWidget(self.ai_output, 1)
        outer.addWidget(ai_card, 2)
        return page

    def build_testing_page(self):
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(14)
        outer.addLayout(self.page_header("Step 4 · Controlled verification", "Controlled Testing", "The AI has no execution authority. Python checks the fixed rule, then the human must approve."))

        guard = card("safetyBanner")
        gl = QHBoxLayout(guard)
        gl.setContentsMargins(16, 12, 16, 12)
        shield = label("SAFETY GATE", "safetyBannerTitle")
        msg = label("Only a predefined verification against the private authorised lab target can be executed.", "safetyBannerText", True)
        set_font(shield, 8.0, QFont.Weight.DemiBold, 1.0)
        set_font(msg, 9.1, QFont.Weight.Medium, 0.05)
        gl.addWidget(shield)
        gl.addSpacing(12)
        gl.addWidget(msg, 1)
        outer.addWidget(guard)

        top = QHBoxLayout()
        top.setSpacing(13)

        test_card = card("panel")
        tc = add_shadowless_card_layout(test_card, (21, 19, 21, 19), 10)
        tc.addLayout(self.section_title("Approved verification", "This test is fixed by the Python safety catalogue, not generated by AI."))
        self.testing_target_label.setObjectName("infoLine")
        self.recommendation_label.setObjectName("infoLine")
        set_font(self.testing_target_label, 9.3, QFont.Weight.Medium, 0.06)
        set_font(self.recommendation_label, 9.3, QFont.Weight.Medium, 0.06)
        tc.addWidget(self.testing_target_label)
        tc.addWidget(self.recommendation_label)
        self.test_info.setObjectName("codeInfo")
        self.test_info.setWordWrap(True)
        self.test_info.setText(
            "APPROVED TEST\nvsFTPd 2.3.4 Backdoor Verification\n\n"
            "MODULE\nexploit/unix/ftp/vsftpd_234_backdoor\n\n"
            "HARMLESS VERIFICATION\nid"
        )
        self.test_info.setFont(font_for(9.2, QFont.Weight.Medium, 0.10, QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family()))
        tc.addWidget(self.test_info)
        top.addWidget(test_card, 3)

        gate = card("gateCard")
        gate.setFixedWidth(395)
        gc = add_shadowless_card_layout(gate, (21, 19, 21, 19), 11)
        gc.addLayout(self.section_title("Human approval gate", "All three conditions must be true before the button can run."))
        self.gate_rows = {}
        for key, text in (
            ("authorised", "Private target is authorised"),
            ("approved", "Approved test match exists"),
            ("human", "Explicit human approval checked"),
        ):
            r = card("gateRow")
            rl = QHBoxLayout(r)
            rl.setContentsMargins(12, 10, 12, 10)
            dot = label("●", "gateDot")
            txt = label(text, "gateText")
            set_font(dot, 9.0, QFont.Weight.Bold)
            set_font(txt, 9.0, QFont.Weight.Medium, 0.08)
            rl.addWidget(dot)
            rl.addWidget(txt, 1)
            gc.addWidget(r)
            self.gate_rows[key] = dot
        gc.addWidget(self.approve_test_checkbox)
        gc.addWidget(self.run_test_button)
        top.addWidget(gate)
        outer.addLayout(top)

        output = card("panel")
        ol = add_shadowless_card_layout(output, (20, 17, 20, 18), 9)
        out_head = QHBoxLayout()
        out_head.addLayout(self.section_title("Verification output", "Metasploit evidence appears here only after the approved test runs."))
        out_head.addStretch()
        self.testing_status.setObjectName("statusPillText")
        set_font(self.testing_status, 8.8, QFont.Weight.Medium, 0.1)
        out_head.addWidget(self.testing_status)
        ol.addLayout(out_head)
        self.testing_output.setMinimumHeight(180)
        ol.addWidget(self.testing_output, 1)
        outer.addWidget(output, 1)
        return page

    def build_evidence_page(self):
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(14)
        outer.addLayout(self.page_header("Step 5 · Audit trail", "Evidence", "Keep a readable history of the controlled tests that were actually performed."))

        bar = card("actionBar")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(18, 13, 18, 13)
        self.evidence_status.setObjectName("statusText")
        set_font(self.evidence_status, 9.5, QFont.Weight.DemiBold, 0.12)
        bl.addWidget(self.evidence_status)
        bl.addStretch()
        bl.addWidget(self.make_secondary("Refresh evidence", self.refresh_evidence))
        outer.addWidget(bar)

        split = QHBoxLayout()
        split.setSpacing(13)

        list_card = card("panel")
        ll = add_shadowless_card_layout(list_card, (20, 18, 20, 18), 9)
        ll.addLayout(self.section_title("Evidence records", "Select a row to inspect the full authorised test record."))
        ll.addWidget(self.evidence_table, 1)

        detail_card = card("panel")
        detail_card.setMinimumWidth(400)
        dl = add_shadowless_card_layout(detail_card, (20, 18, 20, 18), 9)
        dl.addLayout(self.section_title("Selected record", "Target, AI explanation, result and saved evidence."))
        dl.addWidget(self.evidence_output, 1)

        split.addWidget(list_card, 3)
        split.addWidget(detail_card, 2)
        outer.addLayout(split, 1)
        return page

    def build_report_page(self):
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(14)
        outer.addLayout(self.page_header("Step 6 · Communication", "Report", "Generate a structured report from the current assessment and evidence."))

        bar = card("actionBar")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(18, 13, 18, 13)
        self.report_status.setObjectName("statusText")
        set_font(self.report_status, 9.5, QFont.Weight.DemiBold, 0.12)
        bl.addWidget(self.report_status)
        bl.addStretch()
        bl.addWidget(self.make_secondary("Generate report", self.generate_report))
        bl.addWidget(self.make_primary("Save report", self.save_report))
        outer.addWidget(bar)

        editor = card("panel")
        el = add_shadowless_card_layout(editor, (20, 18, 20, 18), 9)
        el.addLayout(self.section_title("Report workspace", "Review and edit the generated text before saving it."))
        el.addWidget(self.report_output, 1)
        outer.addWidget(editor, 1)
        return page

    def build_validation_page(self):
        page = QWidget()
        page.setObjectName("page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(13)
        outer.addLayout(self.page_header("Step 7 · Benchmark", "Validation", "Measure service capture, safe recommendations, evidence logging and unauthorised actions."))

        goals = QHBoxLayout()
        goals.setSpacing(10)
        for title_text, value, helper, accent in (
            ("SERVICE CAPTURE", "≥ 95%", "Project target", "teal"),
            ("SAFE / RELEVANT", "≥ 80%", "Recommendation target", "violet"),
            ("UNAUTHORISED", "0", "Required actions", "amber"),
        ):
            goals.addWidget(MetricCard(title_text, value, helper, accent), 1)
        outer.addLayout(goals)

        middle = QHBoxLayout()
        middle.setSpacing(13)

        form = card("panel")
        form.setMaximumWidth(430)
        fl = add_shadowless_card_layout(form, (20, 18, 20, 18), 8)
        fl.addLayout(self.section_title("Record benchmark case", "Add a manual case when you want to capture a specific validation run."))
        for text, widget in (
            ("Case name", self.case_name_input),
            ("Expected known services", self.expected_services_input),
            ("Correctly detected services", self.detected_services_input),
        ):
            fl.addWidget(self.form_label(text))
            fl.addWidget(widget)
        fl.addWidget(self.recommendation_relevant_checkbox)
        fl.addWidget(self.approved_test_success_checkbox)
        fl.addWidget(self.evidence_logged_checkbox)
        fl.addWidget(self.form_label("Unauthorised actions"))
        fl.addWidget(self.unauthorised_actions_input)
        row = QHBoxLayout()
        row.addWidget(self.make_secondary("Refresh", self.refresh_validation_summary))
        row.addWidget(self.make_primary("Save case", self.save_validation_case))
        fl.addLayout(row)

        summary = card("panel")
        sl = add_shadowless_card_layout(summary, (20, 18, 20, 18), 8)
        summary_head = QHBoxLayout()
        summary_head.addLayout(self.section_title("Validation summary", "Automated and manual benchmark information."))
        summary_head.addStretch()
        self.validation_status.setObjectName("statusPillText")
        set_font(self.validation_status, 8.7, QFont.Weight.Medium, 0.08)
        summary_head.addWidget(self.validation_status)
        sl.addLayout(summary_head)
        sl.addWidget(self.validation_summary, 1)

        middle.addWidget(form)
        middle.addWidget(summary, 1)
        outer.addLayout(middle, 2)

        table_card = card("panel")
        tl = add_shadowless_card_layout(table_card, (20, 16, 20, 18), 8)
        tl.addLayout(self.section_title("Recorded cases", "Pass/fail history for benchmark runs."))
        self.validation_table.setMinimumHeight(190)
        tl.addWidget(self.validation_table, 1)
        outer.addWidget(table_card, 2)
        return page

    def configure_backend_widgets(self):
        self.start_scan_button.setText("Run service scan")
        self.analyse_button.setText("Analyse vulnerabilities")
        self.ai_button.setText("Explain with local AI")
        self.run_test_button.setText("Run approved verification")

        for b in (self.start_scan_button, self.analyse_button, self.ai_button, self.run_test_button):
            b.setProperty("role", "primary")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumHeight(44)
            set_font(b, 9.8, QFont.Weight.DemiBold, 0.22)

        for edit in (self.project_name, self.target_ip, self.tester_name, self.case_name_input, self.expected_services_input, self.detected_services_input, self.unauthorised_actions_input):
            edit.setMinimumHeight(43)
            set_font(edit, 9.8, QFont.Weight.Normal, 0.04)

        for area in (self.scope_notes, self.ai_output, self.testing_output, self.evidence_output, self.report_output, self.validation_summary):
            set_font(area, 9.5, QFont.Weight.Normal, 0.04)

        for cb in (
            self.authorised_checkbox,
            self.approve_test_checkbox,
            self.recommendation_relevant_checkbox,
            self.approved_test_success_checkbox,
            self.evidence_logged_checkbox,
        ):
            set_font(cb, 9.2, QFont.Weight.Medium, 0.05)

        for table in (self.scan_table, self.vulnerability_table, self.evidence_table, self.validation_table):
            table.setAlternatingRowColors(True)
            table.setShowGrid(False)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            table.verticalHeader().setVisible(False)
            table.setSortingEnabled(False)
            table.setWordWrap(False)
            set_font(table, 9.2, QFont.Weight.Normal, 0.03)
            table.horizontalHeader().setMinimumHeight(40)
            set_font(table.horizontalHeader(), 8.8, QFont.Weight.DemiBold, 0.3)

        self.scan_table.verticalHeader().setDefaultSectionSize(39)
        self.vulnerability_table.verticalHeader().setDefaultSectionSize(42)
        self.evidence_table.verticalHeader().setDefaultSectionSize(40)
        self.validation_table.verticalHeader().setDefaultSectionSize(40)

        self.scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.evidence_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.validation_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        h = self.vulnerability_table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

    def on_page_changed(self, index):
        if 0 <= index < len(self.PAGE_META):
            title_text, subtitle, kicker = self.PAGE_META[index]
            self.top_title.setText(title_text)
            self.top_subtitle.setText(subtitle)
            self.top_kicker.setText(kicker)

        for i, b in enumerate(self.nav_buttons):
            b.setProperty("active", i == index)
            self._repolish(b)

        current = self.stack.currentWidget()
        if current:
            effect = QGraphicsOpacityEffect(current)
            current.setGraphicsEffect(effect)
            animation = QPropertyAnimation(effect, b"opacity", self)
            animation.setDuration(170)
            animation.setStartValue(0.68)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            animation.finished.connect(lambda: current.setGraphicsEffect(None))
            self._page_animation = animation
            animation.start()

        self.refresh_live_state()

    def refresh_live_state(self):
        target = self.saved_target or ""
        authorised = bool(self.target_authorised and target)
        scan_done = bool(self.latest_scan_file)
        finding_count = len(self.current_findings or [])
        findings_ready = finding_count > 0
        ai_ready = bool((self.ai_analysis_text or "").strip())
        approved = bool(self.approved_test_available)
        human = bool(self.approve_test_checkbox.isChecked())
        services = self.scan_table.rowCount()

        # Keep the verification button visually locked until every gate is true.
        # Do not re-enable it while a verification is already running.
        running_test = "running controlled test" in self.testing_status.text().lower()
        self.run_test_button.setEnabled(approved and human and not running_test)

        self.target_pill.setText(target if target else "NO TARGET")
        self.target_pill.setProperty("ready", bool(target))
        self._repolish(self.target_pill)

        self.metric_target.value.setText(target if target else "Not selected")
        self.metric_target.helper.setText("Authorised private target" if authorised else "Private lab IP required")
        self.metric_services.value.setText(str(services))
        self.metric_findings.value.setText(str(finding_count))
        self.metric_gate.value.setText("Available" if approved else "Locked")
        self.metric_gate.helper.setText("Human approval still required" if approved else "No approved match yet")

        self.services_badge.setText(f"{services} SERVICE{'S' if services != 1 else ''}")
        self.findings_badge.setText(f"{finding_count} FINDING{'S' if finding_count != 1 else ''}")

        states = {
            "authorised": authorised,
            "scan": scan_done,
            "findings": findings_ready,
            "ai": ai_ready,
        }
        complete = sum(states.values())
        self.readiness_bar.setValue(complete)
        self.readiness_value.setText(f"{complete} / 4")
        for key, value in states.items():
            dot = self.readiness_labels[key]
            dot.setProperty("ready", value)
            self._repolish(dot)

        gate_states = {
            "authorised": authorised,
            "approved": approved,
            "human": human,
        }
        for key, value in gate_states.items():
            dot = self.gate_rows[key]
            dot.setProperty("ready", value)
            self._repolish(dot)

        if self.vulnerability_table.rowCount() != self._last_vuln_rows:
            self._last_vuln_rows = self.vulnerability_table.rowCount()
            self.decorate_vulnerability_table()
        if self.validation_table.rowCount() != self._last_validation_rows:
            self._last_validation_rows = self.validation_table.rowCount()
            self.decorate_validation_table()
        if self.evidence_table.rowCount() != self._last_evidence_rows:
            self._last_evidence_rows = self.evidence_table.rowCount()
            self.decorate_evidence_table()

    def decorate_vulnerability_table(self):
        palette = {
            "CRITICAL": ("#FF6B8A", "#351826"),
            "HIGH": ("#FF9F6E", "#342018"),
            "MEDIUM": ("#F7D56B", "#302A17"),
            "LOW": ("#75D7C7", "#17302D"),
        }
        for row in range(self.vulnerability_table.rowCount()):
            item = self.vulnerability_table.item(row, 5)
            if not item:
                continue
            severity = item.text().strip().upper()
            fg, bg = palette.get(severity, ("#B8C4D6", "#111B2C"))
            item.setForeground(QBrush(QColor(fg)))
            item.setBackground(QBrush(QColor(bg)))

    def decorate_validation_table(self):
        for row in range(self.validation_table.rowCount()):
            for col in range(self.validation_table.columnCount()):
                item = self.validation_table.item(row, col)
                if not item:
                    continue
                txt = item.text().strip().upper()
                if txt == "PASS":
                    item.setForeground(QBrush(QColor("#67E8C8")))
                elif txt == "FAIL":
                    item.setForeground(QBrush(QColor("#FF7D98")))

    def decorate_evidence_table(self):
        for row in range(self.evidence_table.rowCount()):
            item = self.evidence_table.item(row, 1)
            if not item:
                continue
            txt = item.text().lower()
            if any(word in txt for word in ("success", "pass", "verified")):
                item.setForeground(QBrush(QColor("#67E8C8")))
            elif any(word in txt for word in ("fail", "error")):
                item.setForeground(QBrush(QColor("#FF7D98")))

    def _repolish(self, widget):
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def apply_theme(self):
        family = best_family()
        self.setStyleSheet(
            f"""
            * {{
                font-family: \"{family}\";
                color: #DDE6F4;
            }}

            QMainWindow, QWidget#root, QWidget#mainArea, QWidget#content, QWidget#page {{
                background: #080D18;
            }}

            QFrame#sidebar {{
                background: #0B1220;
                border-right: 1px solid #172238;
            }}

            QLabel#logoBadge {{
                color: #07151A;
                background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #69F0D2, stop:1 #7CA8FF);
                border-radius: 14px;
            }}
            QLabel#brand {{ color: #F7FAFF; }}
            QLabel#brandSub, QLabel#sideLabel, QLabel#topKicker, QLabel#pageEyebrow,
            QLabel#miniEyebrow, QLabel#metricEyebrow, QLabel#heroKicker {{ color: #7486A2; }}

            QPushButton#navButton {{
                text-align: left;
                padding: 0 13px;
                border: 1px solid transparent;
                border-radius: 11px;
                background: transparent;
                color: #8D9CB4;
            }}
            QPushButton#navButton:hover {{
                background: #101B2F;
                border-color: #1C2A44;
                color: #EAF1FB;
            }}
            QPushButton#navButton[active="true"] {{
                background: #12253A;
                border-color: #245A62;
                color: #70EBD4;
            }}

            QFrame#labCard {{
                background: #0D211F;
                border: 1px solid #1D554C;
                border-radius: 13px;
            }}
            QLabel#labTitle {{ color: #6CE8CD; }}
            QLabel#labText {{ color: #91AEA9; }}

            QFrame#topbar {{
                background: #0A1120;
                border-bottom: 1px solid #172238;
            }}
            QLabel#topTitle {{ color: #F7FAFF; }}
            QLabel#topSubtitle {{ color: #8493A9; }}
            QLabel#targetPill, QLabel#aiPill {{
                min-width: 92px;
                padding: 8px 12px;
                border-radius: 10px;
                background: #101A2D;
                border: 1px solid #25334D;
                color: #B8C7DE;
            }}
            QLabel#targetPill[ready="true"] {{
                background: #10241F;
                border-color: #236052;
                color: #74E8CF;
            }}
            QLabel#aiPill {{
                background: #17162B;
                border-color: #3A3561;
                color: #BFB5FF;
            }}

            QLabel#pageTitle {{ color: #F7FAFF; }}
            QLabel#pageDescription, QLabel#sectionSub {{ color: #8999B0; }}
            QLabel#sectionTitle {{ color: #EFF4FB; }}

            QFrame#hero {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #101D32, stop:0.55 #0F1A2D, stop:1 #15172C);
                border: 1px solid #213855;
                border-radius: 18px;
            }}
            QLabel#heroTitle {{ color: #F8FBFF; }}
            QLabel#heroBody {{ color: #A4B2C5; }}
            QLabel#heroKicker {{ color: #71E8D3; }}

            QFrame#readinessCard {{
                background: rgba(8, 14, 26, 180);
                border: 1px solid #273A57;
                border-radius: 15px;
            }}
            QLabel#readinessValue {{ color: #75E8D2; }}
            QProgressBar#readinessBar {{
                background: #152036;
                border: 0;
                border-radius: 4px;
            }}
            QProgressBar#readinessBar::chunk {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #67E7CC, stop:1 #819BFF);
                border-radius: 4px;
            }}
            QLabel#stateDot, QLabel#gateDot {{ color: #41506A; }}
            QLabel#stateDot[ready="true"], QLabel#gateDot[ready="true"] {{ color: #69E9D0; }}
            QLabel#stateText, QLabel#gateText {{ color: #C0CBDA; }}

            QFrame#metricCard, QFrame#panel, QFrame#miniPanel, QFrame#actionBar,
            QFrame#infoPanel, QFrame#gateCard {{
                background: #0E1728;
                border: 1px solid #1C2A43;
                border-radius: 15px;
            }}
            QFrame#metricCard[accent="teal"] {{ border-top: 2px solid #63E6CB; }}
            QFrame#metricCard[accent="blue"] {{ border-top: 2px solid #76A7FF; }}
            QFrame#metricCard[accent="violet"] {{ border-top: 2px solid #AA95FF; }}
            QFrame#metricCard[accent="amber"] {{ border-top: 2px solid #E6C36B; }}
            QLabel#metricValue {{ color: #F5F8FD; }}
            QLabel#metricHelp {{ color: #77879E; }}

            QFrame#stageCard {{
                background: #111D31;
                border: 1px solid #22314C;
                border-radius: 12px;
            }}
            QFrame#stageCard[accent="teal"] {{ border-top: 2px solid #63E6CB; }}
            QFrame#stageCard[accent="blue"] {{ border-top: 2px solid #76A7FF; }}
            QFrame#stageCard[accent="violet"] {{ border-top: 2px solid #AA95FF; }}
            QFrame#stageCard[accent="amber"] {{ border-top: 2px solid #E6C36B; }}
            QLabel#stageNumber {{ color: #70819A; }}
            QLabel#stageName {{ color: #EAF0F8; }}
            QLabel#stageDescription {{ color: #8191A8; }}

            QFrame#authorisationBox {{
                background: #10241F;
                border: 1px solid #225D51;
                border-radius: 12px;
            }}
            QLabel#authTitle {{ color: #74E8CF; }}
            QLabel#authText {{ color: #8EA9A4; }}

            QFrame#tipCard, QFrame#gateRow {{
                background: #101B2D;
                border: 1px solid #1F2E47;
                border-radius: 11px;
            }}
            QLabel#tipNumber {{ color: #76E5D2; }}
            QLabel#tipTitle {{ color: #E6EDF7; }}
            QLabel#tipText {{ color: #7F8FA7; }}

            QFrame#safetyBanner {{
                background: #10231F;
                border: 1px solid #245A50;
                border-radius: 12px;
            }}
            QLabel#safetyBannerTitle {{ color: #69E7CE; }}
            QLabel#safetyBannerText {{ color: #A0B9B3; }}

            QLabel#softBadge {{
                padding: 7px 10px;
                border-radius: 9px;
                background: #131D31;
                border: 1px solid #273650;
                color: #AAB8CC;
            }}
            QLabel#softBadge[kind="blue"] {{ color: #8CB4FF; border-color: #2D4C78; background: #101B31; }}
            QLabel#softBadge[kind="violet"] {{ color: #B8A8FF; border-color: #463B75; background: #19172E; }}

            QLabel#formLabel {{ color: #A8B5C8; }}
            QLabel#bigInlineValue, QLabel#infoLine {{ color: #EAF0F8; }}
            QLabel#statusText {{ color: #77E6D0; }}
            QLabel#statusPillText {{
                color: #91A2B8;
                background: #101A2B;
                border: 1px solid #24334D;
                border-radius: 9px;
                padding: 7px 10px;
            }}
            QLabel#codeInfo {{
                color: #C4D2E6;
                background: #09111F;
                border: 1px solid #21304A;
                border-radius: 11px;
                padding: 14px;
            }}

            QLineEdit, QTextEdit, QTableWidget {{
                background: #0A1322;
                color: #DDE6F4;
                border: 1px solid #22324D;
                border-radius: 10px;
                selection-background-color: #235C62;
                selection-color: white;
            }}
            QLineEdit {{ padding: 0 12px; }}
            QTextEdit {{ padding: 10px; }}
            QLineEdit:focus, QTextEdit:focus, QTableWidget:focus {{
                border: 1px solid #55CDBB;
            }}

            QCheckBox {{ color: #CAD5E4; spacing: 9px; }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border: 1px solid #4A5A73;
                border-radius: 5px;
                background: #0A1322;
            }}
            QCheckBox::indicator:hover {{ border-color: #6DDEC9; }}
            QCheckBox::indicator:checked {{
                background: #65E5CC;
                border-color: #65E5CC;
            }}

            QPushButton {{
                border-radius: 10px;
                padding: 9px 16px;
            }}
            QPushButton[role="primary"] {{
                color: #071A1C;
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #67E7CC, stop:1 #75D8E6);
                border: 1px solid #74E6D4;
            }}
            QPushButton[role="primary"]:hover {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #7AF1D9, stop:1 #89E5EF);
            }}
            QPushButton[role="secondary"] {{
                color: #D7E1EF;
                background: #121E33;
                border: 1px solid #2A3A57;
            }}
            QPushButton[role="secondary"]:hover {{
                background: #182741;
                border-color: #3A506F;
            }}
            QPushButton:disabled {{
                color: #56657C;
                background: #0E1727;
                border: 1px solid #1C2940;
            }}

            QTableWidget {{
                alternate-background-color: #0D1829;
                gridline-color: transparent;
                outline: 0;
            }}
            QTableWidget::item {{
                padding: 8px;
                border-bottom: 1px solid #152239;
            }}
            QTableWidget::item:selected {{
                background: #173341;
                color: #F4FAFF;
            }}
            QHeaderView::section {{
                background: #111D31;
                color: #9DACBF;
                border: 0;
                border-bottom: 1px solid #263650;
                padding: 10px 8px;
            }}

            QScrollBar:vertical {{
                background: transparent;
                width: 9px;
                margin: 2px;
            }}
            QScrollBar::handle:vertical {{
                background: #34445E;
                min-height: 30px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical:hover {{ background: #526581; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                height: 0px;
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 9px;
                margin: 2px;
            }}
            QScrollBar::handle:horizontal {{
                background: #34445E;
                min-width: 30px;
                border-radius: 4px;
            }}
            """
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("CyberShield")
    app.setStyle("Fusion")
    app.setFont(font_for(10.0, QFont.Weight.Normal, 0.02))

    window = PremiumMainWindow()
    window.showMaximized()
    sys.exit(app.exec())
