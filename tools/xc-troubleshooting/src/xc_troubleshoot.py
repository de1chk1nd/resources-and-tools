#!/usr/bin/env python3
"""
Backward-compatible entry point.

Usage remains the same:
    python3 src/xc_troubleshoot.py --req-id "abc123"

This shim delegates to the refactored xc_troubleshoot package.
"""

import sys
import os

# Ensure the src/ directory is on the Python path so the package can be found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xc_troubleshoot.cli import main

if __name__ == "__main__":
    main()
