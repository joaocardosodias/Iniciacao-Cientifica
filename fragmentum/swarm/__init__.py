"""
FRAGMENTUM Swarm - Multi-Agent Parallel Pentesting

Sistema de agentes especializados que trabalham em paralelo,
compartilhando descobertas em tempo real.
"""

from .agents import (
    BaseAgent,
    ReconAgent,
    WebAgent,
    NetworkAgent,
    ExploitAgent,
    PostExploitAgent,
    PasswordAgent,
    OSINTAgent
)
from .swarm import SwarmController, SwarmSession, SwarmConfig
from .shared_memory import SharedMemory

__all__ = [
    "BaseAgent",
    "ReconAgent", 
    "WebAgent",
    "NetworkAgent",
    "ExploitAgent",
    "PostExploitAgent",
    "PasswordAgent",
    "OSINTAgent",
    "SwarmController",
    "SwarmSession",
    "SwarmConfig",
    "SharedMemory"
]
