"""
FRAGMENTUM - AI-Powered Penetration Testing Framework

Um framework de pentesting autônomo com suporte a múltiplos LLMs,
MCP Server, e interface web.
"""

__version__ = "2.0.0"
__author__ = "FRAGMENTUM Team"

from fragmentum.core import FragmentumEngine, Config, Session
from fragmentum.tools import get_tool_registry

__all__ = [
    "FragmentumEngine",
    "Config", 
    "Session",
    "get_tool_registry",
    "__version__"
]
