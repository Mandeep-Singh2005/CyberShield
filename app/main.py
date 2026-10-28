import sys
import os
import re
import json
import ipaddress
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QTextEdit,
    QCheckBox,
    QMessageBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView
)

from vulnerability_engine import query_nvd


# =========================================================
# NMAP SCAN WORKER
# =========================================================

class ScanWorker(QThread):

    scan_finished = Signal(str)
    scan_failed = Signal(str)

    def __init__(self, target, output_file):
        super().__init__()
        self.target = target
        self.output_file = output_file

    def run(self):

        try:
            command = [
                "nmap",
                "-sV",
                "-oX",
                self.output_file,
                self.target
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180
            )

            if result.returncode != 0:
                error_message = result.stderr.strip()

                if not error_message:
                    error_message = "Nmap scan failed."

                self.scan_failed.emit(error_message)
                return

            self.scan_finished.emit(self.output_file)

        except Exception as e:
            self.scan_failed.emit(str(e))


# =========================================================
# VULNERABILITY ANALYSIS WORKER
# =========================================================

class VulnerabilityWorker(QThread):

    analysis_finished = Signal(list)
    analysis_failed = Signal(str)
    progress = Signal(str)

    def __init__(self, xml_file):
        super().__init__()
        self.xml_file = xml_file

    def run(self):

        try:
            tree = ET.parse(self.xml_file)
            root = tree.getroot()

            findings = []
            checked_cpes = set()

            for port in root.findall(".//port"):

                port_number = port.get("portid", "")
                service_element = port.find("service")

                if service_element is None:
                    continue

                service_name = service_element.get("name", "")
                product = service_element.get("product", "")
                version_number = service_element.get("version", "")
                extra_info = service_element.get("extrainfo", "")

                version_text = " ".join(
                    part
                    for part in [
                        product,
                        version_number,
                        extra_info
                    ]
                    if part
                )

                cpe_elements = service_element.findall("cpe")

                for cpe_element in cpe_elements:

                    if cpe_element.text is None:
                        continue

                    cpe = cpe_element.text.strip()

                    if not cpe.startswith("cpe:/a:"):
                        continue

                    if cpe in checked_cpes:
                        continue

                    parts = cpe[5:].split(":")

                    if len(parts) < 4:
                        continue

                    if not parts[3]:
                        continue

                    checked_cpes.add(cpe)

                    self.progress.emit(
                        f"Checking {service_name} "
                        f"{version_number}..."
                    )

                    try:
                        cve_results = query_nvd(cpe)

                    except Exception as e:
                        print(f"NVD error for {cpe}: {e}")
                        continue

                    for result in cve_results:

                        findings.append(
                            {
                                "port": port_number,
                                "service": service_name,
                                "version": version_text,
                                "cve": result["cve"],
                                "cvss": result["cvss"],
                                "severity": result["severity"],
                                "description": result["description"],
                                "cpe": cpe
                            }
                        )

            findings.sort(
                key=lambda item: (
                    item["cvss"]
                    if isinstance(item["cvss"], (int, float))
                    else -1
                ),
                reverse=True
            )

            self.analysis_finished.emit(findings)

        except Exception as e:
            self.analysis_failed.emit(str(e))


# =========================================================
# OLLAMA AI WORKER
# =========================================================

class OllamaWorker(QThread):

    analysis_finished = Signal(str)
    analysis_failed = Signal(str)

    def __init__(self, findings):
        super().__init__()
        self.findings = findings

    def run(self):

        try:
            top_findings = self.findings[:12]

            finding_lines = []

            for finding in top_findings:

                finding_lines.append(
                    "Port: {port} | Service: {service} | "
                    "Version: {version} | CVE: {cve} | "
                    "CVSS: {cvss} | Severity: {severity} | "
                    "Description: {description}".format(
                        **finding
                    )
                )

            findings_text = "\n".join(finding_lines)

            prompt = f"""
You are the local AI analysis component of an AUTHORISED
university penetration-testing prototype.

The environment is an authorised isolated laboratory target.

Your job is defensive and educational.

Analyse these vulnerability findings:

{findings_text}

The AI is an interpretation layer only.

Do NOT select, recommend or discuss exploits, payloads,
Metasploit modules or controlled tests.

The Python application handles all approved-test selection
separately after the AI response.

Do NOT provide attack instructions, payload development,
persistence steps or exploitation guidance.

ACCURACY RULES:
Use ONLY the vulnerability information supplied above.
Do NOT invent Metasploit modules, exploit names, CVEs, CVSS
scores, vulnerability types, affected components or technical
details.

Do NOT describe a vulnerability as denial of service, remote
code execution, SQL injection, authentication bypass, or any
other vulnerability type unless that information is explicitly
stated in the supplied finding.

Do NOT suggest that a vulnerability can be exploited with
Metasploit unless it is the explicitly approved vsFTPd 2.3.4
test described above.

When explaining a finding, use only the supplied Description
field.

Do NOT claim remote code execution, denial of service,
authentication bypass, privilege escalation, injection or any
other vulnerability behaviour unless that behaviour is
explicitly stated in the supplied Description.

If the supplied description does not support a technical claim,
say that further verification is required.

Write a concise report with exactly these headings:

SUMMARY
Explain the most important findings in simple language.

PRIORITY
Describe the important findings in the order they are provided.
The findings are already ordered by the Python/NVD analysis layer.

Do NOT recalculate, change, compare or reinterpret CVSS scores.
Do NOT claim that one finding has a higher score than another.
Do NOT invent CVEs, versions, severity ratings or vulnerability data.

SAFETY
Explain that this is an isolated authorised laboratory and
that explicit user approval is required before any controlled
test is executed.

MITIGATION
Give only general defensive mitigation advice relevant to the
services actually present in the supplied findings.

Do NOT give FTP-specific mitigation unless vsFTPd or another
FTP service is actually present in the supplied findings.

Only discuss mitigation for services and vulnerabilities that
actually appear in the supplied findings.

Keep mitigation general and defensive: use supported software,
apply appropriate vendor security updates, reduce unnecessary
exposure, review configuration and retest after remediation.

Do NOT mention absent services.
Do NOT invent configuration options, commands or settings that
are not present in the supplied data.

IMPORTANT:
Do NOT decide which exploit or controlled test should run.
Do NOT create an APPROVED TEST RECOMMENDATION section.
The Python application makes that decision deterministically
from the verified vulnerability findings.
""".strip()

            data = json.dumps(
                {
                    "model": "llama3.2:3b",
                    "prompt": prompt,
                    "stream": False
                }
            ).encode("utf-8")

            request = urllib.request.Request(
                "http://127.0.0.1:11434/api/generate",
                data=data,
                headers={
                    "Content-Type": "application/json"
                }
            )

            with urllib.request.urlopen(
                request,
                timeout=180
            ) as response:

                result = json.loads(
                    response.read().decode("utf-8")
                )

            ai_text = result.get("response", "").strip()

            if not ai_text:
                ai_text = "Ollama returned an empty response."

            self.analysis_finished.emit(ai_text)

        except Exception as e:
            self.analysis_failed.emit(str(e))


# =========================================================
# CONTROLLED METASPLOIT TEST WORKER
# =========================================================

class MetasploitWorker(QThread):

    test_finished = Signal(str)
    test_failed = Signal(str)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):

        try:

            resource_commands = (
                "use exploit/unix/ftp/vsftpd_234_backdoor; "
                f"set RHOSTS {self.target}; "
                "set RPORT 21; "
                "set PAYLOAD cmd/unix/generic; "
                "set CMD id; "
                "set VERBOSE true; "
                "run; "
                "exit -y"
            )

            command = [
                "msfconsole",
                "-q",
                "-x",
                resource_commands
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120
            )

            output = (
                (result.stdout or "")
                + "\n"
                + (result.stderr or "")
            ).strip()

            ansi_escape = re.compile(
                r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
            )

            output = ansi_escape.sub("", output)

            if not output:
                output = "Metasploit produced no output."

            self.test_finished.emit(output)

        except subprocess.TimeoutExpired:

            self.test_failed.emit(
                "Metasploit test timed out after 120 seconds."
            )

        except FileNotFoundError:

            self.test_failed.emit(
                "msfconsole was not found on this system."
            )

        except Exception as e:
            self.test_failed.emit(str(e))


# =========================================================
# MAIN APPLICATION
# =========================================================

class MainWindow(QMainWindow):

    def __init__(self):

        super().__init__()

        self.setWindowTitle(
            "Penetration Testing Management & Automation Tool"
        )

        self.resize(1200, 800)

        self.saved_target = ""
        self.saved_project = ""
        self.saved_tester = ""
        self.saved_scope = ""

        self.target_authorised = False
        self.latest_scan_file = ""

        self.current_findings = []
        self.ai_analysis_text = ""

        self.approved_test_available = False

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.home_page = self.create_home_page()
        self.target_page = self.create_target_page()
        self.scan_page = self.create_scan_page()

        self.vulnerability_page = (
            self.create_vulnerability_page()
        )

        self.testing_page = (
            self.create_testing_page()
        )

        self.evidence_page = (
            self.create_evidence_page()
        )

        self.report_page = (
            self.create_report_page()
        )

        self.validation_page = (
            self.create_validation_page()
        )

        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.target_page)
        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.vulnerability_page)
        self.stack.addWidget(self.testing_page)
        self.stack.addWidget(self.evidence_page)
        self.stack.addWidget(self.report_page)
        self.stack.addWidget(self.validation_page)


    # =====================================================
    # DASHBOARD
    # =====================================================

    def create_home_page(self):

        page = QWidget()
        layout = QVBoxLayout()

        title = QLabel(
            "Penetration Testing Management & Automation Tool"
        )

        title.setStyleSheet(
            "font-size: 24px; font-weight: bold;"
        )

        subtitle = QLabel(
            "Authorised Target → Scan → Analyse → "
            "AI Recommendation → Approve → Test → Evidence"
        )

        layout.addWidget(title)
        layout.addWidget(subtitle)

        buttons = [
            ("Dashboard", None),
            ("Target & Scope", self.open_target_page),
            ("Scan", self.open_scan_page),
            ("Vulnerabilities & AI", self.open_vulnerability_page),
            ("Testing", self.open_testing_page),
            ("Evidence", self.open_evidence_page),
            ("Report", self.open_report_page),
            ("Validation / Benchmark", self.open_validation_page)
        ]

        for text, action in buttons:

            button = QPushButton(text)
            button.setMinimumHeight(45)

            if action is not None:
                button.clicked.connect(action)

            layout.addWidget(button)

        page.setLayout(layout)

        return page


    # =====================================================
    # TARGET & SCOPE PAGE
    # =====================================================

    def create_target_page(self):

        page = QWidget()
        layout = QVBoxLayout()

        title = QLabel("Target & Scope")

        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        self.project_name = QLineEdit()

        self.project_name.setPlaceholderText(
            "Project name"
        )

        self.target_ip = QLineEdit()

        self.target_ip.setPlaceholderText(
            "Target IP address"
        )

        self.tester_name = QLineEdit()

        self.tester_name.setPlaceholderText(
            "Tester name"
        )

        self.tester_name.setText(
            "Mandeep Singh"
        )

        self.scope_notes = QTextEdit()

        self.scope_notes.setPlaceholderText(
            "Describe the authorised scope "
            "of this penetration test"
        )

        self.authorised_checkbox = QCheckBox(
            "I confirm that I am authorised "
            "to test this target"
        )

        save_button = QPushButton(
            "Save Target & Scope"
        )

        save_button.clicked.connect(
            self.save_target
        )

        back_button = QPushButton(
            "Back to Dashboard"
        )

        back_button.clicked.connect(
            self.open_home_page
        )

        layout.addWidget(title)
        layout.addWidget(QLabel("Project Name"))
        layout.addWidget(self.project_name)
        layout.addWidget(QLabel("Target IP"))
        layout.addWidget(self.target_ip)
        layout.addWidget(QLabel("Tester"))
        layout.addWidget(self.tester_name)
        layout.addWidget(QLabel("Scope"))
        layout.addWidget(self.scope_notes)
        layout.addWidget(self.authorised_checkbox)
        layout.addWidget(save_button)
        layout.addWidget(back_button)

        page.setLayout(layout)

        return page


    # =====================================================
    # SCAN PAGE
    # =====================================================

    def create_scan_page(self):

        page = QWidget()
        layout = QVBoxLayout()

        title = QLabel(
            "Reconnaissance & Scanning"
        )

        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        self.scan_target_label = QLabel(
            "Target: Not selected"
        )

        self.scan_status = QLabel(
            "Status: Ready"
        )

        self.start_scan_button = QPushButton(
            "Run Nmap Service Scan"
        )

        self.start_scan_button.setMinimumHeight(45)

        self.start_scan_button.clicked.connect(
            self.start_scan
        )

        self.scan_table = QTableWidget()

        self.scan_table.setColumnCount(4)

        self.scan_table.setHorizontalHeaderLabels(
            [
                "Port",
                "State",
                "Service",
                "Version"
            ]
        )

        self.scan_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        back_button = QPushButton(
            "Back to Dashboard"
        )

        back_button.clicked.connect(
            self.open_home_page
        )

        layout.addWidget(title)
        layout.addWidget(self.scan_target_label)
        layout.addWidget(self.scan_status)
        layout.addWidget(self.start_scan_button)
        layout.addWidget(self.scan_table)
        layout.addWidget(back_button)

        page.setLayout(layout)

        return page


    # =====================================================
    # VULNERABILITY + AI PAGE
    # =====================================================

    def create_vulnerability_page(self):

        page = QWidget()
        layout = QVBoxLayout()

        title = QLabel(
            "Vulnerability Analysis & AI Recommendation"
        )

        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        info = QLabel(
            "Analyse detected services against known "
            "vulnerability information, then ask the local "
            "AI to explain and prioritise the findings."
        )

        self.vulnerability_status = QLabel(
            "Status: Ready"
        )

        self.analyse_button = QPushButton(
            "Analyse Vulnerabilities"
        )

        self.analyse_button.setMinimumHeight(45)

        self.analyse_button.clicked.connect(
            self.start_vulnerability_analysis
        )

        self.vulnerability_table = QTableWidget()

        self.vulnerability_table.setColumnCount(7)

        self.vulnerability_table.setHorizontalHeaderLabels(
            [
                "Port",
                "Service",
                "Version",
                "CVE",
                "CVSS",
                "Severity",
                "Description"
            ]
        )

        header = self.vulnerability_table.horizontalHeader()

        header.setSectionResizeMode(
            QHeaderView.ResizeToContents
        )

        header.setSectionResizeMode(
            6,
            QHeaderView.Stretch
        )

        self.ai_button = QPushButton(
            "Ask Ollama to Explain & Recommend"
        )

        self.ai_button.setMinimumHeight(45)

        self.ai_button.clicked.connect(
            self.start_ai_analysis
        )

        self.ai_button.setEnabled(False)

        self.ai_status = QLabel(
            "AI Status: Waiting for vulnerability analysis"
        )

        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)

        self.ai_output.setPlaceholderText(
            "Ollama analysis will appear here."
        )

        back_button = QPushButton(
            "Back to Dashboard"
        )

        back_button.clicked.connect(
            self.open_home_page
        )

        layout.addWidget(title)
        layout.addWidget(info)
        layout.addWidget(self.vulnerability_status)
        layout.addWidget(self.analyse_button)
        layout.addWidget(self.vulnerability_table)
        layout.addWidget(self.ai_button)
        layout.addWidget(self.ai_status)
        layout.addWidget(self.ai_output)
        layout.addWidget(back_button)

        page.setLayout(layout)

        return page


    # =====================================================
    # CONTROLLED TESTING PAGE
    # =====================================================

    def create_testing_page(self):

        page = QWidget()
        layout = QVBoxLayout()

        title = QLabel(
            "Controlled Vulnerability Testing"
        )

        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        warning = QLabel(
            "Only approved tests against the isolated "
            "authorised lab target may be executed."
        )

        self.testing_target_label = QLabel(
            "Target: Not selected"
        )

        self.recommendation_label = QLabel(
            "Approved recommendation: Not available"
        )

        self.test_info = QLabel(
            "Approved test:\n"
            "vsFTPd 2.3.4 Backdoor Verification\n\n"
            "Module:\n"
            "exploit/unix/ftp/vsftpd_234_backdoor\n\n"
            "Verification command:\n"
            "id"
        )

        self.approve_test_checkbox = QCheckBox(
            "I explicitly approve execution of "
            "this controlled vulnerability test"
        )

        self.run_test_button = QPushButton(
            "Run Approved vsFTPd Test"
        )

        self.run_test_button.setMinimumHeight(45)

        self.run_test_button.clicked.connect(
            self.run_approved_test
        )

        self.run_test_button.setEnabled(False)

        self.testing_status = QLabel(
            "Status: Waiting for an approved recommendation"
        )

        self.testing_output = QTextEdit()
        self.testing_output.setReadOnly(True)

        self.testing_output.setPlaceholderText(
            "Metasploit test output will appear here."
        )

        back_button = QPushButton(
            "Back to Dashboard"
        )

        back_button.clicked.connect(
            self.open_home_page
        )

        layout.addWidget(title)
        layout.addWidget(warning)
        layout.addWidget(self.testing_target_label)
        layout.addWidget(self.recommendation_label)
        layout.addWidget(self.test_info)
        layout.addWidget(self.approve_test_checkbox)
        layout.addWidget(self.run_test_button)
        layout.addWidget(self.testing_status)
        layout.addWidget(self.testing_output)
        layout.addWidget(back_button)

        page.setLayout(layout)

        return page


    # =====================================================
    # EVIDENCE PAGE
    # =====================================================

    def create_evidence_page(self):

        page = QWidget()
        layout = QVBoxLayout()

        title = QLabel(
            "Testing Evidence & Audit Records"
        )

        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        info = QLabel(
            "Evidence generated by completed controlled "
            "vulnerability tests."
        )

        self.evidence_status = QLabel(
            "Status: Ready"
        )

        refresh_button = QPushButton(
            "Refresh Evidence"
        )

        refresh_button.setMinimumHeight(40)

        refresh_button.clicked.connect(
            self.refresh_evidence
        )

        self.evidence_table = QTableWidget()

        self.evidence_table.setColumnCount(3)

        self.evidence_table.setHorizontalHeaderLabels(
            [
                "Date / Time",
                "Result",
                "Evidence File"
            ]
        )

        self.evidence_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        self.evidence_table.cellClicked.connect(
            self.load_evidence_record
        )

        details_label = QLabel(
            "Selected Evidence Record"
        )

        details_label.setStyleSheet(
            "font-weight: bold;"
        )

        self.evidence_output = QTextEdit()
        self.evidence_output.setReadOnly(True)

        self.evidence_output.setPlaceholderText(
            "Select an evidence record above to view "
            "the full authorised target, AI analysis, "
            "test result and Metasploit evidence."
        )

        back_button = QPushButton(
            "Back to Dashboard"
        )

        back_button.clicked.connect(
            self.open_home_page
        )

        layout.addWidget(title)
        layout.addWidget(info)
        layout.addWidget(self.evidence_status)
        layout.addWidget(refresh_button)
        layout.addWidget(self.evidence_table)
        layout.addWidget(details_label)
        layout.addWidget(self.evidence_output)
        layout.addWidget(back_button)

        page.setLayout(layout)

        return page


    # =====================================================
    # REPORT PAGE
    # =====================================================

    def create_report_page(self):

        page = QWidget()
        layout = QVBoxLayout()

        title = QLabel(
            "Penetration Testing Report"
        )

        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        info = QLabel(
            "Generate a structured report from the "
            "latest completed evidence record."
        )

        self.report_status = QLabel(
            "Status: Ready"
        )

        generate_button = QPushButton(
            "Generate Report from Latest Evidence"
        )

        generate_button.setMinimumHeight(45)

        generate_button.clicked.connect(
            self.generate_report
        )

        save_button = QPushButton(
            "Save Report"
        )

        save_button.setMinimumHeight(45)

        save_button.clicked.connect(
            self.save_report
        )

        self.report_output = QTextEdit()
        self.report_output.setReadOnly(False)

        self.report_output.setPlaceholderText(
            "Generated penetration testing report "
            "will appear here."
        )

        back_button = QPushButton(
            "Back to Dashboard"
        )

        back_button.clicked.connect(
            self.open_home_page
        )

        layout.addWidget(title)
        layout.addWidget(info)
        layout.addWidget(self.report_status)
        layout.addWidget(generate_button)
        layout.addWidget(save_button)
        layout.addWidget(self.report_output)
        layout.addWidget(back_button)

        page.setLayout(layout)

        return page


    # =====================================================
    # VALIDATION / BENCHMARK PAGE
    # =====================================================

    def create_validation_page(self):

        page = QWidget()
        layout = QVBoxLayout()

        title = QLabel(
            "Validation / Benchmark"
        )

        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        info = QLabel(
            "Record benchmark cases and measure the prototype "
            "against the project success criteria."
        )

        self.validation_status = QLabel(
            "Status: Ready"
        )

        self.case_name_input = QLineEdit()
        self.case_name_input.setPlaceholderText(
            "Case name, e.g. Metasploitable baseline 01"
        )

        self.expected_services_input = QLineEdit()
        self.expected_services_input.setPlaceholderText(
            "Expected known port/service count"
        )

        self.detected_services_input = QLineEdit()
        self.detected_services_input.setPlaceholderText(
            "Correctly detected port/service count"
        )

        self.recommendation_relevant_checkbox = QCheckBox(
            "AI / recommendation was safe and relevant"
        )

        self.approved_test_success_checkbox = QCheckBox(
            "Approved controlled test completed correctly"
        )

        self.evidence_logged_checkbox = QCheckBox(
            "Evidence / audit record was created"
        )

        self.unauthorised_actions_input = QLineEdit()
        self.unauthorised_actions_input.setPlaceholderText(
            "Unauthorised actions count (normally 0)"
        )
        self.unauthorised_actions_input.setText("0")

        add_button = QPushButton(
            "Save Benchmark Case"
        )

        add_button.setMinimumHeight(45)

        add_button.clicked.connect(
            self.save_validation_case
        )

        refresh_button = QPushButton(
            "Refresh Validation Summary"
        )

        refresh_button.clicked.connect(
            self.refresh_validation_summary
        )

        self.validation_table = QTableWidget()
        self.validation_table.setColumnCount(7)

        self.validation_table.setHorizontalHeaderLabels(
            [
                "Case",
                "Capture %",
                "Relevant",
                "Test Success",
                "Evidence",
                "Unauthorised",
                "Overall"
            ]
        )

        self.validation_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        self.validation_summary = QTextEdit()
        self.validation_summary.setReadOnly(True)

        self.validation_summary.setPlaceholderText(
            "Validation metrics will appear here."
        )

        back_button = QPushButton(
            "Back to Dashboard"
        )

        back_button.clicked.connect(
            self.open_home_page
        )

        layout.addWidget(title)
        layout.addWidget(info)
        layout.addWidget(self.validation_status)

        layout.addWidget(QLabel("Benchmark Case"))
        layout.addWidget(self.case_name_input)

        layout.addWidget(QLabel("Expected Known Services"))
        layout.addWidget(self.expected_services_input)

        layout.addWidget(QLabel("Correctly Detected Services"))
        layout.addWidget(self.detected_services_input)

        layout.addWidget(self.recommendation_relevant_checkbox)
        layout.addWidget(self.approved_test_success_checkbox)
        layout.addWidget(self.evidence_logged_checkbox)

        layout.addWidget(QLabel("Unauthorised Actions"))
        layout.addWidget(self.unauthorised_actions_input)

        layout.addWidget(add_button)
        layout.addWidget(refresh_button)
        layout.addWidget(self.validation_table)
        layout.addWidget(self.validation_summary)
        layout.addWidget(back_button)

        page.setLayout(layout)

        return page


    # =====================================================
    # NAVIGATION
    # =====================================================

    def open_home_page(self):

        self.stack.setCurrentWidget(
            self.home_page
        )


    def open_target_page(self):

        self.stack.setCurrentWidget(
            self.target_page
        )


    def open_scan_page(self):

        if self.saved_target:
            self.scan_target_label.setText(
                f"Target: {self.saved_target}"
            )

        else:
            self.scan_target_label.setText(
                "Target: Not selected"
            )

        self.stack.setCurrentWidget(
            self.scan_page
        )


    def open_vulnerability_page(self):

        self.stack.setCurrentWidget(
            self.vulnerability_page
        )


    def open_testing_page(self):

        if self.saved_target:

            self.testing_target_label.setText(
                f"Target: {self.saved_target}"
            )

        else:

            self.testing_target_label.setText(
                "Target: Not selected"
            )

        if self.approved_test_available:

            self.recommendation_label.setText(
                "Approved recommendation: "
                "vsFTPd 2.3.4 Backdoor Verification"
            )

            self.run_test_button.setEnabled(True)

            self.testing_status.setText(
                "Status: Approved test available - "
                "user approval required"
            )

        else:

            self.recommendation_label.setText(
                "Approved recommendation: Not available"
            )

            self.run_test_button.setEnabled(False)

            self.testing_status.setText(
                "Status: No approved test recommendation"
            )

        self.stack.setCurrentWidget(
            self.testing_page
        )


    def open_evidence_page(self):

        self.refresh_evidence()

        self.stack.setCurrentWidget(
            self.evidence_page
        )


    def open_report_page(self):

        self.stack.setCurrentWidget(
            self.report_page
        )


    def open_validation_page(self):

        self.refresh_validation_summary()

        self.stack.setCurrentWidget(
            self.validation_page
        )


    # =====================================================
    # SAVE TARGET
    # =====================================================

    def save_target(self):

        project = self.project_name.text().strip()
        target = self.target_ip.text().strip()
        tester = self.tester_name.text().strip()
        scope = self.scope_notes.toPlainText().strip()

        if not project:

            QMessageBox.warning(
                self,
                "Missing Information",
                "Enter a project name."
            )

            return

        if not target:

            QMessageBox.warning(
                self,
                "Missing Information",
                "Enter a target IP."
            )

            return

        try:
            ip = ipaddress.ip_address(target)

        except ValueError:

            QMessageBox.warning(
                self,
                "Invalid Target",
                "Enter a valid IP address."
            )

            return

        if not ip.is_private:

            QMessageBox.warning(
                self,
                "Private Lab Target Required",
                "This prototype only accepts "
                "private laboratory IP addresses."
            )

            return

        if not self.authorised_checkbox.isChecked():

            QMessageBox.warning(
                self,
                "Authorisation Required",
                "You must confirm that you are "
                "authorised to test this target."
            )

            return

        self.saved_project = project
        self.saved_target = target
        self.saved_tester = tester
        self.saved_scope = scope

        self.target_authorised = True

        QMessageBox.information(
            self,
            "Saved",
            "Target and scope information "
            "saved successfully."
        )


    # =====================================================
    # START NMAP SCAN
    # =====================================================

    def start_scan(self):

        if not self.saved_target:

            QMessageBox.warning(
                self,
                "No Target",
                "Please save an authorised target first."
            )

            return

        if not self.target_authorised:

            QMessageBox.warning(
                self,
                "Not Authorised",
                "Target authorisation is required."
            )

            return

        os.makedirs("scans", exist_ok=True)

        output_file = os.path.abspath(
            "scans/gui_scan.xml"
        )

        self.scan_table.setRowCount(0)

        self.scan_status.setText(
            "Status: Scanning..."
        )

        self.start_scan_button.setEnabled(False)

        self.worker = ScanWorker(
            self.saved_target,
            output_file
        )

        self.worker.scan_finished.connect(
            self.scan_complete
        )

        self.worker.scan_failed.connect(
            self.scan_error
        )

        self.worker.start()


    def scan_complete(self, xml_file):

        self.latest_scan_file = xml_file

        self.scan_status.setText(
            "Status: Scan completed"
        )

        self.start_scan_button.setEnabled(True)

        self.load_nmap_results(xml_file)

        QMessageBox.information(
            self,
            "Scan Complete",
            "Nmap scan completed successfully."
        )


    def scan_error(self, error):

        self.scan_status.setText(
            "Status: Scan failed"
        )

        self.start_scan_button.setEnabled(True)

        QMessageBox.critical(
            self,
            "Scan Error",
            error
        )


    # =====================================================
    # LOAD NMAP XML
    # =====================================================

    def load_nmap_results(self, xml_file):

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            ports = root.findall(".//port")

            self.scan_table.setRowCount(
                len(ports)
            )

            for row, port in enumerate(ports):

                port_number = port.get("portid", "")

                state_element = port.find("state")

                state = ""

                if state_element is not None:
                    state = state_element.get(
                        "state",
                        ""
                    )

                service_element = port.find("service")

                service_name = ""
                version = ""

                if service_element is not None:

                    service_name = service_element.get(
                        "name",
                        ""
                    )

                    product = service_element.get(
                        "product",
                        ""
                    )

                    version_number = service_element.get(
                        "version",
                        ""
                    )

                    extra = service_element.get(
                        "extrainfo",
                        ""
                    )

                    version = " ".join(
                        part
                        for part in [
                            product,
                            version_number,
                            extra
                        ]
                        if part
                    )

                self.scan_table.setItem(
                    row,
                    0,
                    QTableWidgetItem(port_number)
                )

                self.scan_table.setItem(
                    row,
                    1,
                    QTableWidgetItem(state)
                )

                self.scan_table.setItem(
                    row,
                    2,
                    QTableWidgetItem(service_name)
                )

                self.scan_table.setItem(
                    row,
                    3,
                    QTableWidgetItem(version)
                )

        except Exception as e:

            QMessageBox.critical(
                self,
                "XML Error",
                "Could not read scan results:\n"
                + str(e)
            )


    # =====================================================
    # VULNERABILITY ANALYSIS
    # =====================================================

    def start_vulnerability_analysis(self):

        scan_file = self.latest_scan_file

        if not scan_file:

            fallback = os.path.abspath(
                "scans/gui_scan.xml"
            )

            if os.path.exists(fallback):
                scan_file = fallback

        if (
            not scan_file
            or not os.path.exists(scan_file)
        ):

            QMessageBox.warning(
                self,
                "No Scan Results",
                "Run an Nmap scan before "
                "analysing vulnerabilities."
            )

            return

        self.current_findings = []
        self.ai_analysis_text = ""
        self.approved_test_available = False

        self.ai_output.clear()
        self.ai_button.setEnabled(False)

        self.vulnerability_table.setRowCount(0)

        self.vulnerability_status.setText(
            "Status: Analysing vulnerabilities..."
        )

        self.analyse_button.setEnabled(False)

        self.vulnerability_worker = VulnerabilityWorker(
            scan_file
        )

        self.vulnerability_worker.progress.connect(
            self.update_vulnerability_progress
        )

        self.vulnerability_worker.analysis_finished.connect(
            self.vulnerability_analysis_complete
        )

        self.vulnerability_worker.analysis_failed.connect(
            self.vulnerability_analysis_failed
        )

        self.vulnerability_worker.start()


    def update_vulnerability_progress(
        self,
        message
    ):

        self.vulnerability_status.setText(
            f"Status: {message}"
        )


    def vulnerability_analysis_complete(
        self,
        findings
    ):

        self.current_findings = findings

        self.analyse_button.setEnabled(True)

        self.vulnerability_status.setText(
            "Status: Analysis complete - "
            f"{len(findings)} findings"
        )

        self.vulnerability_table.setRowCount(
            len(findings)
        )

        for row, finding in enumerate(findings):

            cvss_value = finding["cvss"]

            if cvss_value is None:
                cvss_text = "N/A"

            else:
                cvss_text = str(cvss_value)

            values = [
                finding["port"],
                finding["service"],
                finding["version"],
                finding["cve"],
                cvss_text,
                finding["severity"],
                finding["description"]
            ]

            for column, value in enumerate(values):

                self.vulnerability_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value))
                )

        if findings:

            self.ai_button.setEnabled(True)

            self.ai_status.setText(
                "AI Status: Ready for local Ollama analysis"
            )

        else:

            self.ai_status.setText(
                "AI Status: No findings available"
            )

        QMessageBox.information(
            self,
            "Analysis Complete",
            "Vulnerability analysis completed.\n\n"
            f"{len(findings)} findings were identified."
        )


    def vulnerability_analysis_failed(
        self,
        error
    ):

        self.analyse_button.setEnabled(True)

        self.vulnerability_status.setText(
            "Status: Analysis failed"
        )

        QMessageBox.critical(
            self,
            "Vulnerability Analysis Error",
            error
        )


    # =====================================================
    # OLLAMA AI ANALYSIS
    # =====================================================

    def start_ai_analysis(self):

        if not self.current_findings:

            QMessageBox.warning(
                self,
                "No Findings",
                "Run vulnerability analysis first."
            )

            return

        self.ai_button.setEnabled(False)

        self.ai_status.setText(
            "AI Status: Ollama is analysing findings..."
        )

        self.ai_output.clear()

        self.ollama_worker = OllamaWorker(
            self.current_findings
        )

        self.ollama_worker.analysis_finished.connect(
            self.ai_analysis_complete
        )

        self.ollama_worker.analysis_failed.connect(
            self.ai_analysis_failed
        )

        self.ollama_worker.start()


    def clean_ai_text(self, text):

        if not text:
            return ""

        # Remove basic Markdown so the GUI, evidence logs,
        # and final report use clean plain text.
        text = re.sub(
            r"\*\*(.*?)\*\*",
            r"\1",
            text
        )

        text = re.sub(
            r"^\s*\*\s+",
            "- ",
            text,
            flags=re.MULTILINE
        )

        text = re.sub(
            r"^\s*\+\s+",
            "  - ",
            text,
            flags=re.MULTILINE
        )

        return text.strip()


    def ai_analysis_complete(
        self,
        analysis_text
    ):

        analysis_text = self.clean_ai_text(
            analysis_text
        )

        self.ai_button.setEnabled(True)

        self.ai_status.setText(
            "AI Status: Analysis complete"
        )

        # Deterministic safety gate.
        #
        # Ollama explains and prioritises findings.
        # It does NOT control exploit selection.
        # The application checks the verified NVD findings
        # against the small approved-test catalogue.

        self.approved_test_available = any(
            (
                finding["cve"].upper()
                == "CVE-2011-2523"
            )
            or (
                "vsftpd 2.3.4"
                in finding["version"].lower()
            )
            for finding in self.current_findings
        )

        if self.approved_test_available:

            recommendation_text = (
                "APPROVED TEST RECOMMENDATION\n"
                "vsFTPd 2.3.4 Backdoor Verification\n\n"
                "Reason: The verified vulnerability findings "
                "include vsFTPd 2.3.4 / CVE-2011-2523, which "
                "matches the team's approved controlled test.\n\n"
                "Execution is NOT automatic. Explicit user "
                "approval is required on the Testing page."
            )

            self.recommendation_label.setText(
                "Approved recommendation: "
                "vsFTPd 2.3.4 Backdoor Verification"
            )

        else:

            recommendation_text = (
                "APPROVED TEST RECOMMENDATION\n"
                "No approved controlled test currently "
                "matches the verified vulnerability findings.\n\n"
                "No exploitation action has been enabled."
            )

            self.recommendation_label.setText(
                "Approved recommendation: "
                "No approved test matches the findings"
            )

        final_analysis = (
            analysis_text.strip()
            + "\n\n"
            + recommendation_text
        )

        self.ai_analysis_text = final_analysis

        self.ai_output.setPlainText(
            final_analysis
        )

        QMessageBox.information(
            self,
            "AI Analysis Complete",
            "Ollama has analysed the vulnerability findings."
        )


    def ai_analysis_failed(
        self,
        error
    ):

        self.ai_button.setEnabled(True)

        self.ai_status.setText(
            "AI Status: Analysis failed"
        )

        QMessageBox.critical(
            self,
            "Ollama Error",
            error
        )


    # =====================================================
    # RUN APPROVED TEST
    # =====================================================

    def run_approved_test(self):

        if not self.saved_target:

            QMessageBox.warning(
                self,
                "No Target",
                "Save an authorised target first."
            )

            return

        if not self.target_authorised:

            QMessageBox.warning(
                self,
                "Not Authorised",
                "The target has not been authorised."
            )

            return

        if not self.approved_test_available:

            QMessageBox.warning(
                self,
                "No Approved Recommendation",
                "The vulnerability analysis has not "
                "identified an approved test for this target."
            )

            return

        try:
            ip = ipaddress.ip_address(
                self.saved_target
            )

        except ValueError:

            QMessageBox.warning(
                self,
                "Invalid Target",
                "The saved target IP is invalid."
            )

            return

        if not ip.is_private:

            QMessageBox.warning(
                self,
                "Private Lab Target Required",
                "Controlled exploitation is restricted "
                "to private laboratory IP addresses."
            )

            return

        if not self.approve_test_checkbox.isChecked():

            QMessageBox.warning(
                self,
                "Explicit Approval Required",
                "Tick the approval checkbox before "
                "running the controlled test."
            )

            return

        confirmation = QMessageBox.question(
            self,
            "Final Confirmation",
            "Run the approved vsFTPd 2.3.4 "
            "backdoor verification against:\n\n"
            f"{self.saved_target}\n\n"
            "The verification command is only: id",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if confirmation != QMessageBox.Yes:
            return

        self.testing_output.clear()

        self.testing_status.setText(
            "Status: Running controlled test..."
        )

        self.run_test_button.setEnabled(False)

        self.test_worker = MetasploitWorker(
            self.saved_target
        )

        self.test_worker.test_finished.connect(
            self.controlled_test_complete
        )

        self.test_worker.test_failed.connect(
            self.controlled_test_failed
        )

        self.test_worker.start()


    def controlled_test_complete(
        self,
        output
    ):

        self.run_test_button.setEnabled(True)

        self.testing_output.setPlainText(
            output
        )

        root_verified = (
            "uid=0(root)" in output
        )

        backdoor_spawned = (
            "Backdoor has been spawned" in output
        )

        if root_verified:

            result_text = (
                "SUCCESS - root command execution verified"
            )

            self.testing_status.setText(
                "Status: SUCCESS - root execution verified"
            )

        elif backdoor_spawned:

            result_text = (
                "PARTIAL - backdoor spawned but "
                "root verification was not captured"
            )

            self.testing_status.setText(
                "Status: PARTIAL - backdoor spawned"
            )

        else:

            result_text = (
                "NOT VERIFIED - expected evidence "
                "was not detected"
            )

            self.testing_status.setText(
                "Status: Test completed - not verified"
            )

        log_file = self.write_test_log(
            result_text,
            output
        )

        QMessageBox.information(
            self,
            "Controlled Test Complete",
            f"{result_text}\n\n"
            f"Audit log:\n{log_file}"
        )

        self.approve_test_checkbox.setChecked(False)


    def controlled_test_failed(
        self,
        error
    ):

        self.run_test_button.setEnabled(True)

        self.testing_status.setText(
            "Status: Test failed"
        )

        self.testing_output.setPlainText(
            error
        )

        log_file = self.write_test_log(
            "ERROR",
            error
        )

        QMessageBox.critical(
            self,
            "Controlled Test Error",
            f"{error}\n\n"
            f"Audit log:\n{log_file}"
        )

        self.approve_test_checkbox.setChecked(False)


    # =====================================================
    # EVIDENCE RECORDS
    # =====================================================

    def refresh_evidence(self):

        os.makedirs(
            "logs",
            exist_ok=True
        )

        log_directory = os.path.abspath(
            "logs"
        )

        files = [
            filename
            for filename in os.listdir(log_directory)
            if (
                filename.startswith("controlled_test_")
                and filename.endswith(".log")
            )
        ]

        files.sort(
            reverse=True
        )

        self.evidence_table.setRowCount(
            len(files)
        )

        for row, filename in enumerate(files):

            path = os.path.join(
                log_directory,
                filename
            )

            date_text = ""
            result_text = ""

            try:

                with open(
                    path,
                    "r",
                    encoding="utf-8"
                ) as file:

                    contents = file.read()

                for line in contents.splitlines():

                    if line.startswith("Date/Time:"):
                        date_text = line.split(
                            ":",
                            1
                        )[1].strip()

                    elif line.startswith("Result:"):
                        result_text = line.split(
                            ":",
                            1
                        )[1].strip()

            except Exception as e:

                result_text = (
                    "Could not read: "
                    + str(e)
                )

            self.evidence_table.setItem(
                row,
                0,
                QTableWidgetItem(
                    date_text
                )
            )

            self.evidence_table.setItem(
                row,
                1,
                QTableWidgetItem(
                    result_text
                )
            )

            self.evidence_table.setItem(
                row,
                2,
                QTableWidgetItem(
                    filename
                )
            )

        self.evidence_status.setText(
            "Status: "
            f"{len(files)} evidence record(s) available"
        )

        if not files:

            self.evidence_output.clear()


    def load_evidence_record(
        self,
        row,
        column
    ):

        filename_item = (
            self.evidence_table.item(
                row,
                2
            )
        )

        if filename_item is None:
            return

        filename = filename_item.text()

        path = os.path.abspath(
            os.path.join(
                "logs",
                filename
            )
        )

        try:

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as file:

                contents = file.read()

            self.evidence_output.setPlainText(
                contents
            )

            self.evidence_status.setText(
                "Status: Viewing "
                + filename
            )

        except Exception as e:

            QMessageBox.critical(
                self,
                "Evidence Error",
                "Could not read evidence record:\n"
                + str(e)
            )


    # =====================================================
    # REPORT GENERATION
    # =====================================================

    def generate_report(self):

        # -------------------------------------------------
        # Report the CURRENT authorised run.
        # This avoids assuming every target was exploited
        # using the vsFTPd controlled test.
        # -------------------------------------------------

        if not self.saved_target:

            QMessageBox.warning(
                self,
                "No Current Target",
                "Save an authorised target and run a scan "
                "before generating a current-run report."
            )

            return

        # -------------------------------------------------
        # Read current Nmap scan results
        # -------------------------------------------------

        scan_services = []

        scan_file = self.latest_scan_file

        if not scan_file:

            fallback = os.path.abspath(
                "scans/gui_scan.xml"
            )

            if os.path.exists(fallback):
                scan_file = fallback

        if scan_file and os.path.exists(scan_file):

            try:

                tree = ET.parse(
                    scan_file
                )

                root = tree.getroot()

                for port in root.findall(".//port"):

                    port_number = port.get(
                        "portid",
                        ""
                    )

                    protocol = port.get(
                        "protocol",
                        ""
                    )

                    state_element = port.find(
                        "state"
                    )

                    state = ""

                    if state_element is not None:

                        state = state_element.get(
                            "state",
                            ""
                        )

                    service_element = port.find(
                        "service"
                    )

                    service_name = ""
                    version_text = ""

                    if service_element is not None:

                        service_name = (
                            service_element.get(
                                "name",
                                ""
                            )
                        )

                        product = (
                            service_element.get(
                                "product",
                                ""
                            )
                        )

                        version_number = (
                            service_element.get(
                                "version",
                                ""
                            )
                        )

                        extra = (
                            service_element.get(
                                "extrainfo",
                                ""
                            )
                        )

                        version_text = " ".join(
                            part
                            for part in [
                                product,
                                version_number,
                                extra
                            ]
                            if part
                        )

                    scan_services.append(
                        {
                            "port": port_number,
                            "protocol": protocol,
                            "state": state,
                            "service": service_name,
                            "version": version_text
                        }
                    )

            except Exception as e:

                QMessageBox.critical(
                    self,
                    "Report Error",
                    "Could not read the current scan:\n"
                    + str(e)
                )

                return

        if scan_services:

            scan_text = "\n".join(
                (
                    f"{item['port']}/{item['protocol']} | "
                    f"{item['state']} | "
                    f"{item['service']} | "
                    f"{item['version'] or 'Version not identified'}"
                )
                for item in scan_services
            )

        else:

            scan_text = (
                "No current scan results were available."
            )

        # -------------------------------------------------
        # Verified vulnerability findings
        # -------------------------------------------------

        if self.current_findings:

            verified_findings = (
                self.get_verified_findings_text()
            )

        else:

            verified_findings = (
                "No verified vulnerability findings were "
                "identified for this target using the current "
                "service/version-based NVD analysis."
            )

        # -------------------------------------------------
        # AI interpretation
        # -------------------------------------------------

        ai_analysis = (
            self.ai_analysis_text.strip()
            if self.ai_analysis_text.strip()
            else
            "AI analysis was not performed for this run."
        )

        # -------------------------------------------------
        # Determine controlled-test state
        # -------------------------------------------------

        testing_output = (
            self.testing_output
            .toPlainText()
            .strip()
        )

        root_verified = (
            "uid=0(root)"
            in testing_output
        )

        backdoor_spawned = (
            "Backdoor has been spawned"
            in testing_output
        )

        test_executed = (
            root_verified
            or backdoor_spawned
        )

        if self.approved_test_available:

            approved_test_text = (
                "An approved controlled test matched the "
                "verified findings:\n\n"
                "vsFTPd 2.3.4 Backdoor Verification\n\n"
                "The executable test is selected by Python "
                "from the approved-test catalogue. Ollama "
                "does not control exploit selection."
            )

        else:

            approved_test_text = (
                "No approved controlled test matched the "
                "verified vulnerability findings for this "
                "target. Controlled exploitation remained "
                "disabled."
            )

        if root_verified:

            test_result_text = (
                "CONTROLLED TEST EXECUTED\n\n"
                "Test: vsFTPd 2.3.4 Backdoor Verification\n"
                "Verification command: id\n"
                "Result: SUCCESS\n"
                "Root verification: uid=0(root) returned."
            )

            evidence_text = testing_output

            conclusion_test_text = (
                "The approved controlled test was executed "
                "after explicit user approval and successfully "
                "verified root-level command execution."
            )

        elif backdoor_spawned:

            test_result_text = (
                "CONTROLLED TEST EXECUTED\n\n"
                "The approved vsFTPd controlled test was run, "
                "but root verification was not captured."
            )

            evidence_text = testing_output

            conclusion_test_text = (
                "The approved controlled test was executed, "
                "but complete root verification was not recorded."
            )

        elif self.approved_test_available:

            test_result_text = (
                "APPROVED TEST AVAILABLE - NOT EXECUTED\n\n"
                "The verified findings matched the approved "
                "vsFTPd 2.3.4 controlled test, but no controlled "
                "test execution is recorded in this current run."
            )

            evidence_text = (
                "No Metasploit execution evidence is recorded "
                "for this current run."
            )

            conclusion_test_text = (
                "An approved controlled test was available, "
                "but no execution was recorded for this run."
            )

        else:

            test_result_text = (
                "NO CONTROLLED TEST PERFORMED\n\n"
                "No approved controlled test matched the "
                "verified findings. The application therefore "
                "did not enable exploitation."
            )

            evidence_text = (
                "No Metasploit evidence exists because no "
                "controlled test was authorised or executed."
            )

            conclusion_test_text = (
                "No approved controlled test matched this "
                "target, so no exploitation was performed."
            )

        # -------------------------------------------------
        # Dynamic executive summary
        # -------------------------------------------------

        findings_count = len(
            self.current_findings
        )

        services_count = len(
            scan_services
        )

        if findings_count:

            finding_summary = (
                f"{findings_count} potential vulnerability "
                "finding(s) were identified from detected "
                "service/version information."
            )

        else:

            finding_summary = (
                "No verified NVD vulnerability findings were "
                "identified from the available service/version "
                "information."
            )

        current_time = datetime.now().isoformat()

        # -------------------------------------------------
        # Final dynamic report
        # -------------------------------------------------

        report = f"""
AI-ASSISTED AUTOMATED PENETRATION TESTING PROTOTYPE
CURRENT TARGET ANALYSIS REPORT
============================================================

1. EXECUTIVE SUMMARY
------------------------------------------------------------

This report documents the current authorised laboratory run.

Target:
{self.saved_target}

The prototype detected {services_count} open/service result(s).
{finding_summary}

{conclusion_test_text}


2. PROJECT INFORMATION
------------------------------------------------------------

Project:
{self.saved_project}

Tester:
{self.saved_tester}

Report Generated:
{current_time}

Target:
{self.saved_target}

Authorised:
{self.target_authorised}

Authorised Scope:
{self.saved_scope}


3. METHODOLOGY
------------------------------------------------------------

The current workflow used the following stages:

1. The user entered and explicitly authorised the target.
2. Nmap performed service and version detection.
3. Python analysed detected software information against NVD data.
4. Ollama provided an interpretation of verified findings where
   AI analysis was requested.
5. Python checked verified findings against the approved-test
   catalogue.
6. Controlled testing was enabled only when an approved match
   existed and still required explicit user approval.


4. SCAN RESULTS
------------------------------------------------------------

{scan_text}


5. VERIFIED VULNERABILITY FINDINGS
------------------------------------------------------------

The following information comes from the Python/NVD analysis
layer and is the authoritative source for CVE IDs, CVSS scores,
severity and detected software versions.

{verified_findings}


6. AI-ASSISTED INTERPRETATION
------------------------------------------------------------

The following section is generated by the local Ollama model.
It is an interpretation layer only and does not control
approved-test selection or execution.

{ai_analysis}


7. APPROVED-TEST DECISION
------------------------------------------------------------

{approved_test_text}


8. CONTROLLED TEST RESULT
------------------------------------------------------------

{test_result_text}


9. EVIDENCE
------------------------------------------------------------

{evidence_text}


10. MITIGATION AND RECOMMENDATIONS
------------------------------------------------------------

General defensive recommendations for the current target are:

- Use supported software versions.
- Apply appropriate vendor security updates.
- Reduce unnecessary network exposure.
- Review service configuration.
- Monitor relevant system and network logs.
- Retest after remediation.

Specific technical mitigation should be based on the verified
findings and vendor guidance rather than AI-generated assumptions.


11. VALIDATION / BENCHMARK RESULTS
------------------------------------------------------------

{self.get_automated_validation_summary()}


12. SAFETY AND AUTHORISATION
------------------------------------------------------------

Testing was restricted to the explicitly authorised laboratory
target.

Ollama cannot directly execute exploits.

Python controls the approved-test catalogue, and controlled
testing requires explicit user approval before execution.

{conclusion_test_text}


13. CONCLUSION
------------------------------------------------------------

The prototype demonstrated the following workflow:

Target Authorisation
→ Nmap Scanning
→ NVD Vulnerability Analysis
→ Local AI Interpretation
→ Deterministic Approved-Test Decision
→ Human Approval Where Required
→ Controlled Testing Where Approved
→ Evidence
→ Report Generation

Target analysed:
{self.saved_target}

{finding_summary}

{conclusion_test_text}

============================================================
END OF REPORT
============================================================
""".strip()

        self.report_output.setPlainText(
            report
        )

        self.report_status.setText(
            "Status: Current-run report generated"
        )


    def save_report(self):

        report_text = (
            self.report_output
            .toPlainText()
            .strip()
        )

        if not report_text:

            QMessageBox.warning(
                self,
                "No Report",
                "Generate the report before saving it."
            )

            return

        os.makedirs(
            "reports",
            exist_ok=True
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        filename = (
            "penetration_test_report_"
            + timestamp
            + ".txt"
        )

        path = os.path.abspath(
            os.path.join(
                "reports",
                filename
            )
        )

        try:

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    report_text
                )

        except Exception as e:

            QMessageBox.critical(
                self,
                "Save Error",
                "Could not save report:\n"
                + str(e)
            )

            return

        self.report_status.setText(
            "Status: Report saved"
        )

        QMessageBox.information(
            self,
            "Report Saved",
            "Report saved successfully:\n\n"
            + path
        )


    # =====================================================
    # VALIDATION / BENCHMARK METHODS
    # =====================================================

    def get_validation_file(self):

        os.makedirs(
            "data",
            exist_ok=True
        )

        return os.path.abspath(
            "data/validation_cases.json"
        )


    def load_validation_cases(self):

        path = self.get_validation_file()

        if not os.path.exists(path):
            return []

        try:

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as file:

                return json.load(file)

        except Exception:
            return []


    def save_validation_case(self):

        case_name = (
            self.case_name_input
            .text()
            .strip()
        )

        if not case_name:

            QMessageBox.warning(
                self,
                "Missing Case Name",
                "Enter a benchmark case name."
            )

            return

        try:

            expected = int(
                self.expected_services_input
                .text()
                .strip()
            )

            detected = int(
                self.detected_services_input
                .text()
                .strip()
            )

            unauthorised = int(
                self.unauthorised_actions_input
                .text()
                .strip()
            )

        except ValueError:

            QMessageBox.warning(
                self,
                "Invalid Numbers",
                "Expected services, detected services and "
                "unauthorised actions must be whole numbers."
            )

            return

        if expected <= 0:

            QMessageBox.warning(
                self,
                "Invalid Baseline",
                "Expected services must be greater than zero."
            )

            return

        if detected < 0 or detected > expected:

            QMessageBox.warning(
                self,
                "Invalid Detection Count",
                "Detected services must be between 0 "
                "and the expected count."
            )

            return

        if unauthorised < 0:

            QMessageBox.warning(
                self,
                "Invalid Action Count",
                "Unauthorised actions cannot be negative."
            )

            return

        capture_rate = (
            detected / expected
        ) * 100.0

        relevant = (
            self.recommendation_relevant_checkbox
            .isChecked()
        )

        test_success = (
            self.approved_test_success_checkbox
            .isChecked()
        )

        evidence_logged = (
            self.evidence_logged_checkbox
            .isChecked()
        )

        overall_pass = (
            capture_rate >= 95.0
            and relevant
            and test_success
            and evidence_logged
            and unauthorised == 0
        )

        record = {
            "case": case_name,
            "timestamp": datetime.now().isoformat(),
            "expected_services": expected,
            "detected_services": detected,
            "capture_rate": round(
                capture_rate,
                2
            ),
            "recommendation_relevant": relevant,
            "approved_test_success": test_success,
            "evidence_logged": evidence_logged,
            "unauthorised_actions": unauthorised,
            "overall_pass": overall_pass
        }

        cases = self.load_validation_cases()
        cases.append(record)

        path = self.get_validation_file()

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                cases,
                file,
                indent=2
            )

        self.validation_status.setText(
            "Status: Benchmark case saved"
        )

        self.case_name_input.clear()
        self.expected_services_input.clear()
        self.detected_services_input.clear()

        self.recommendation_relevant_checkbox.setChecked(
            False
        )

        self.approved_test_success_checkbox.setChecked(
            False
        )

        self.evidence_logged_checkbox.setChecked(
            False
        )

        self.unauthorised_actions_input.setText(
            "0"
        )

        self.refresh_validation_summary()

        QMessageBox.information(
            self,
            "Benchmark Saved",
            "Validation case saved successfully."
        )


    def refresh_validation_summary(self):

        cases = self.load_validation_cases()

        self.validation_table.setRowCount(
            len(cases)
        )

        for row, case in enumerate(cases):

            values = [
                case.get("case", ""),
                f"{case.get('capture_rate', 0):.2f}%",
                (
                    "PASS"
                    if case.get(
                        "recommendation_relevant",
                        False
                    )
                    else "FAIL"
                ),
                (
                    "PASS"
                    if case.get(
                        "approved_test_success",
                        False
                    )
                    else "FAIL"
                ),
                (
                    "PASS"
                    if case.get(
                        "evidence_logged",
                        False
                    )
                    else "FAIL"
                ),
                str(
                    case.get(
                        "unauthorised_actions",
                        0
                    )
                ),
                (
                    "PASS"
                    if case.get(
                        "overall_pass",
                        False
                    )
                    else "FAIL"
                )
            ]

            for column, value in enumerate(values):

                self.validation_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(
                        str(value)
                    )
                )

        if not cases:

            automated_summary = (
                self.get_automated_validation_summary()
            )

            self.validation_summary.setPlainText(
                automated_summary
                + "\n\n"
                + "No manual benchmark cases recorded."
            )

            self.validation_status.setText(
                "Status: Automated validation loaded"
            )

            return

        total_cases = len(cases)

        average_capture = sum(
            case.get(
                "capture_rate",
                0
            )
            for case in cases
        ) / total_cases

        relevant_count = sum(
            1
            for case in cases
            if case.get(
                "recommendation_relevant",
                False
            )
        )

        test_success_count = sum(
            1
            for case in cases
            if case.get(
                "approved_test_success",
                False
            )
        )

        evidence_count = sum(
            1
            for case in cases
            if case.get(
                "evidence_logged",
                False
            )
        )

        unauthorised_total = sum(
            case.get(
                "unauthorised_actions",
                0
            )
            for case in cases
        )

        relevant_rate = (
            relevant_count / total_cases
        ) * 100.0

        test_success_rate = (
            test_success_count / total_cases
        ) * 100.0

        evidence_rate = (
            evidence_count / total_cases
        ) * 100.0

        capture_pass = (
            average_capture >= 95.0
        )

        recommendation_pass = (
            relevant_rate >= 80.0
        )

        unauthorised_pass = (
            unauthorised_total == 0
        )

        summary = (
            "PROJECT VALIDATION SUMMARY\n"
            "========================================\n"
            f"Benchmark cases recorded: {total_cases}\n\n"

            "1. Port / Service Capture\n"
            f"Average capture rate: {average_capture:.2f}%\n"
            "Target: >= 95%\n"
            f"Result: {'PASS' if capture_pass else 'FAIL'}\n\n"

            "2. Safe / Relevant Recommendations\n"
            f"Relevant recommendation rate: {relevant_rate:.2f}%\n"
            "Target: >= 80%\n"
            f"Result: {'PASS' if recommendation_pass else 'FAIL'}\n\n"

            "3. Approved Test Completion\n"
            f"Successful controlled tests: "
            f"{test_success_count}/{total_cases} "
            f"({test_success_rate:.2f}%)\n\n"

            "4. Evidence Logging\n"
            f"Evidence successfully recorded: "
            f"{evidence_count}/{total_cases} "
            f"({evidence_rate:.2f}%)\n\n"

            "5. Unauthorised Actions\n"
            f"Total unauthorised actions: {unauthorised_total}\n"
            "Target: 0\n"
            f"Result: {'PASS' if unauthorised_pass else 'FAIL'}\n\n"

            "OVERALL PROJECT TARGET STATUS\n"
            "----------------------------------------\n"
            f"Scan capture target: "
            f"{'PASS' if capture_pass else 'FAIL'}\n"
            f"Recommendation target: "
            f"{'PASS' if recommendation_pass else 'FAIL'}\n"
            f"Safety target: "
            f"{'PASS' if unauthorised_pass else 'FAIL'}"
        )

        automated_summary = (
            self.get_automated_validation_summary()
        )

        combined_summary = (
            automated_summary
            + "\n\n"
            + "MANUAL BENCHMARK CASE SUMMARY\n"
            + "========================================\n"
            + summary
        )

        self.validation_summary.setPlainText(
            combined_summary
        )

        self.validation_status.setText(
            "Status: "
            f"{total_cases} manual benchmark case(s) "
            "plus automated validation"
        )


    # =====================================================
    # AUTOMATED VALIDATION RESULTS
    # =====================================================

    def get_automated_validation_summary(self):

        service_file = os.path.abspath(
            "data/service_capture_20.json"
        )

        recommendation_file = os.path.abspath(
            "data/recommendation_20.json"
        )

        service_cases = []
        recommendation_cases = []

        try:
            if os.path.exists(service_file):
                with open(
                    service_file,
                    "r",
                    encoding="utf-8"
                ) as file:
                    service_cases = json.load(file)
        except Exception:
            service_cases = []

        try:
            if os.path.exists(recommendation_file):
                with open(
                    recommendation_file,
                    "r",
                    encoding="utf-8"
                ) as file:
                    recommendation_cases = json.load(file)
        except Exception:
            recommendation_cases = []

        service_total = len(service_cases)

        service_passed = sum(
            1
            for case in service_cases
            if case.get("pass", False)
        )

        service_rate = (
            service_passed / service_total * 100.0
            if service_total
            else 0.0
        )

        recommendation_total = len(
            recommendation_cases
        )

        recommendation_passed = sum(
            1
            for case in recommendation_cases
            if case.get("pass", False)
        )

        recommendation_rate = (
            recommendation_passed
            / recommendation_total
            * 100.0
            if recommendation_total
            else 0.0
        )

        unauthorised_recommendations = sum(
            1
            for case in recommendation_cases
            if not case.get("safe", True)
        )

        approved_recommendations = sum(
            1
            for case in recommendation_cases
            if (
                case.get(
                    "actual_recommendation",
                    ""
                )
                != "No approved controlled test"
            )
        )

        service_target_pass = (
            service_rate >= 95.0
        )

        recommendation_target_pass = (
            recommendation_rate >= 80.0
        )

        recommendation_safety_pass = (
            unauthorised_recommendations == 0
        )

        latest_test_success = False
        root_verified = False
        evidence_available = False

        os.makedirs(
            "logs",
            exist_ok=True
        )

        logs = [
            filename
            for filename in os.listdir("logs")
            if (
                filename.startswith(
                    "controlled_test_"
                )
                and filename.endswith(".log")
            )
        ]

        logs.sort(
            reverse=True
        )

        latest_evidence_file = ""

        if logs:

            latest_evidence_file = logs[0]

            try:

                with open(
                    os.path.join(
                        "logs",
                        latest_evidence_file
                    ),
                    "r",
                    encoding="utf-8"
                ) as file:

                    evidence_text = file.read()

                evidence_available = True

                latest_test_success = (
                    "SUCCESS - root command execution verified"
                    in evidence_text
                )

                root_verified = (
                    "uid=0(root)"
                    in evidence_text
                )

            except Exception:
                pass

        summary = (
            "AUTOMATED VALIDATION RESULTS\n"
            "========================================\n\n"

            "1. SERVICE CAPTURE BENCHMARK\n"
            "----------------------------------------\n"
            f"Cases: {service_total}\n"
            f"Passed: {service_passed}\n"
            f"Capture rate: {service_rate:.2f}%\n"
            "Project target: >= 95%\n"
            f"Result: "
            f"{'PASS' if service_target_pass else 'FAIL'}\n\n"

            "2. APPROVED-TEST RECOMMENDATION LOGIC\n"
            "----------------------------------------\n"
            f"Cases: {recommendation_total}\n"
            f"Passed: {recommendation_passed}\n"
            f"Safe / relevant rate: "
            f"{recommendation_rate:.2f}%\n"
            "Project target: >= 80%\n"
            f"Unauthorised recommendations: "
            f"{unauthorised_recommendations}\n"
            f"Approved tests recommended: "
            f"{approved_recommendations}\n"
            f"Result: "
            f"{'PASS' if (
                recommendation_target_pass
                and recommendation_safety_pass
            ) else 'FAIL'}\n\n"

            "3. CONTROLLED TEST VALIDATION\n"
            "----------------------------------------\n"
            f"Latest evidence file: "
            f"{latest_evidence_file or 'None'}\n"
            f"Controlled test success: "
            f"{'PASS' if latest_test_success else 'FAIL'}\n"
            f"Root verification: "
            f"{'PASS' if root_verified else 'FAIL'}\n"
            f"Evidence available: "
            f"{'PASS' if evidence_available else 'FAIL'}\n\n"

            "OVERALL VALIDATION STATUS\n"
            "----------------------------------------\n"
            f"Service capture target: "
            f"{'PASS' if service_target_pass else 'FAIL'}\n"
            f"Recommendation target: "
            f"{'PASS' if recommendation_target_pass else 'FAIL'}\n"
            f"Recommendation safety: "
            f"{'PASS' if recommendation_safety_pass else 'FAIL'}\n"
            f"Controlled test: "
            f"{'PASS' if latest_test_success else 'FAIL'}\n"
            f"Evidence logging: "
            f"{'PASS' if evidence_available else 'FAIL'}"
        )

        return summary


    # =====================================================
    # VERIFIED VULNERABILITY FINDINGS
    # =====================================================

    def get_verified_findings_text(self):

        if not self.current_findings:
            return (
                "No verified vulnerability findings "
                "were available."
            )

        lines = []

        for index, finding in enumerate(
            self.current_findings,
            start=1
        ):

            cvss = finding.get("cvss")

            if cvss is None:
                cvss_text = "N/A"
            else:
                cvss_text = str(cvss)

            lines.append(
                f"{index}. "
                f"Port {finding.get('port', '')} | "
                f"Service: {finding.get('service', '')} | "
                f"Version: {finding.get('version', '')} | "
                f"CVE: {finding.get('cve', '')} | "
                f"CVSS: {cvss_text} | "
                f"Severity: {finding.get('severity', '')}"
            )

        return "\n".join(lines)


    # =====================================================
    # AUDIT LOG
    # =====================================================

    def write_test_log(
        self,
        result,
        output
    ):

        os.makedirs(
            "logs",
            exist_ok=True
        )

        timestamp = datetime.now()

        filename = (
            "controlled_test_"
            + timestamp.strftime(
                "%Y%m%d_%H%M%S"
            )
            + ".log"
        )

        path = os.path.abspath(
            os.path.join(
                "logs",
                filename
            )
        )

        log_text = (
            "PENETRATION TEST AUDIT RECORD\n"
            "========================================\n"
            f"Date/Time: {timestamp.isoformat()}\n"
            f"Project: {self.saved_project}\n"
            f"Tester: {self.saved_tester}\n"
            f"Target: {self.saved_target}\n"
            f"Authorised: {self.target_authorised}\n"
            f"Scope: {self.saved_scope}\n"
            "\n"
            "VERIFIED VULNERABILITY FINDINGS\n"
            "========================================\n"
            f"{self.get_verified_findings_text()}\n"
            "\n"
            "AI ANALYSIS - INTERPRETATION ONLY\n"
            "========================================\n"
            f"{self.ai_analysis_text}\n"
            "\n"
            "APPROVED TEST\n"
            "========================================\n"
            "VSFTPD 2.3.4 Backdoor Verification\n"
            "\n"
            "Metasploit Module:\n"
            "exploit/unix/ftp/vsftpd_234_backdoor\n"
            "\n"
            "Verification Command:\n"
            "id\n"
            "\n"
            f"Result: {result}\n"
            "\n"
            "METASPLOIT OUTPUT\n"
            "========================================\n"
            f"{output}\n"
        )

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(log_text)

        return path


# =========================================================
# START APPLICATION
# =========================================================

app = QApplication(
    sys.argv
)

window = MainWindow()

window.show()

sys.exit(
    app.exec()
)
