"""
FRAGMENTUM MCP Server - Model Context Protocol
"""

try:
    from .server import FragmentumMCPServer, start_server, HAS_MCP
    __all__ = ["FragmentumMCPServer", "start_server", "HAS_MCP"]
except ImportError:
    HAS_MCP = False
    __all__ = ["HAS_MCP"]
