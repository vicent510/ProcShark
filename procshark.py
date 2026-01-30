#!/usr/bin/env python
"""
ProcShark - Network Traffic Analyzer with Process Correlation

A lightweight network capture tool for Windows that correlates network
traffic with processes in real-time.

Usage:
    python procshark.py [OPTIONS]

Examples:
    python procshark.py
    python procshark.py -f "C:\\Path\\to\\app.exe"
    python procshark.py -p http,dns --export capture.json

Requirements:
    - Windows 10/11
    - Python 3.9+
    - Administrator privileges
    - pip install -r requirements.txt
"""

import sys

from core.cli import main

if __name__ == "__main__":
    sys.exit(main())
