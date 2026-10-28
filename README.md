# CyberShield

AI-Assisted Automated Penetration Testing Prototype

Team C04 - UTS Cybersecurity Capstone Studio

## About the Project

CyberShield is a Python application for guided penetration
testing in an authorised lab environment.

It uses Nmap to scan targets, CVE/CVSS information to
analyse findings, Ollama to explain vulnerabilities,
and Metasploit for approved controlled verification.

The user must approve testing actions.

## Requirements

- Kali Linux
- Python 3
- Nmap
- Metasploit Framework
- Ollama with llama3.2:3b
- PySide6
- Requests

## How to Run

Create and activate a Python virtual environment:

python3 -m venv venv
source venv/bin/activate

Install Python dependencies:

pip install -r requirements.txt

Run the Premium UI:

python3 app/premium_ui.py

## Important

This is an educational prototype.

Only test systems you own or have permission to test.
The controlled testing feature is intended for an isolated lab.

AI explains findings but does not authorise test execution.
