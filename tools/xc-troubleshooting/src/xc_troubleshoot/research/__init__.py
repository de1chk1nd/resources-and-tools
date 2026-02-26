"""
Public research — search F5 documentation and community for known issues.

Split into submodules:
  - queries: Derive search queries from events
  - google: Google search client
  - formatters: Report section generation
"""

from .queries import build_research_queries
from .google import run_public_research
from .formatters import generate_research_report_section

__all__ = [
    "build_research_queries",
    "run_public_research",
    "generate_research_report_section",
]
