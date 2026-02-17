#!/usr/bin/env python3
"""
Backward-compatible shim — delegates to the refactored package.

This file exists so that any code doing `from html_report import generate_html_report`
continues to work without changes.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xc_troubleshoot.reports.html import generate_html_report  # noqa: F401
