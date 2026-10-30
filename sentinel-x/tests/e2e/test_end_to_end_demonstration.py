"""Root End-to-End System Demonstration Flow (Section 47 & Section 9).

Validates the full demonstration lifecycle from dataset ingestion to report generation.
"""

from pathlib import Path
import sys

# Ensure backend directory is in python path
backend_dir = Path(__file__).resolve().parents[2] / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from tests.integration.test_e2e_flow import test_complete_17_step_end_to_end_demonstration_flow

__all__ = ["test_complete_17_step_end_to_end_demonstration_flow"]
