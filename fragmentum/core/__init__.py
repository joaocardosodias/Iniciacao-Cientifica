"""
FRAGMENTUM Core - Motor principal do sistema
"""

from .engine import FragmentumEngine
from .config import Config
from .session import Session, SessionManager

__all__ = ["FragmentumEngine", "Config", "Session", "SessionManager"]
__version__ = "2.0.0"
