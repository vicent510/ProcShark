"""
ProcShark - Network traffic analyzer with process correlation.

A lightweight network capture tool that correlates network traffic with processes,
providing real-time visibility into which applications are communicating over the network.
"""

__version__ = "1.0.0"
__author__ = "ProcShark Contributors"
__license__ = "MIT"

from core.capture import PacketCapture
from core.process import ProcessCorrelator
from core.protocols import ProtocolAnalyzer
from core.display import Display
from core.export import Exporter
from core.stats import Statistics

__all__ = [
    "PacketCapture",
    "ProcessCorrelator",
    "ProtocolAnalyzer",
    "Display",
    "Exporter",
    "Statistics",
    "__version__",
]
