"""
pytest configuration file.
Adds the gateway source directory to sys.path so unit tests can import
database.py and rules_engine.py directly without installing them as packages.
"""

import sys
import os

# Allow tests to import gateway modules without Docker
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "gateway"))
