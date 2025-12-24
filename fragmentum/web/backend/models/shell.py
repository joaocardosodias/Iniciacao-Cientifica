"""
Shell Manager data models.

Based on the Shell Manager design document.
Requirements: 1.1, 1.2, 3.1, 3.3, 5.1, 5.2
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Any
from dataclasses import dataclass, field
import socket


class ShellType(str, Enum):
    """Type of shell connection.
    
    Requirements: 1.1 - Shell metadata includes type
    """
    REVERSE = "reverse"
    BIND = "bind"


class ShellStatus(str, Enum):
    """Status of a shell connection.
    
    Requirements: 1.2 - Display shells with status (connected, disconnected, idle)
    """
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    IDLE = "idle"


class ListenerStatus(str, Enum):
    """Status of a listener.
    
    Requirements: 3.4 - Display listener status
    """
    ACTIVE = "active"
    STOPPED = "stopped"


@dataclass
class ShellConnection:
    """Represents a shell connection to a remote system.
    
    Requirements: 1.1 - Register connection with metadata (target IP, port, type, timestamp)
    """
    id: str
    target_ip: str
    target_port: int
    local_port: int
    shell_type: ShellType
    status: ShellStatus
    is_pty: bool
    created_at: datetime
    last_activity: datetime
    source: str  # fragmentum, external, metasploit, etc.
    socket_obj: Optional[Any] = field(default=None, repr=False)  # TCP socket connection
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "local_port": self.local_port,
            "shell_type": self.shell_type.value,
            "status": self.status.value,
            "is_pty": self.is_pty,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "source": self.source,
        }


@dataclass
class Listener:
    """Represents a listener waiting for reverse shell connections.
    
    Requirements: 3.1, 3.3 - Create listener with port, protocol configuration
    Requirements: 3.4 - Display status and connection count
    """
    id: str
    port: int
    protocol: str  # tcp, udp
    status: ListenerStatus
    connection_count: int
    created_at: datetime
    server_socket: Optional[Any] = field(default=None, repr=False)  # Server socket
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status.value,
            "connection_count": self.connection_count,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class HistoryEntry:
    """Represents a single command/output entry in shell history.
    
    Requirements: 5.1 - Log command with timestamp
    Requirements: 5.2 - Display commands and outputs chronologically
    """
    id: str
    shell_id: str
    command: str
    output: str
    timestamp: datetime
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "shell_id": self.shell_id,
            "command": self.command,
            "output": self.output,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ShellHistory:
    """Collection of history entries for a shell session.
    
    Requirements: 5.2 - Display commands chronologically
    Requirements: 5.4 - Preserve history after shell disconnect
    """
    shell_id: str
    entries: List[HistoryEntry] = field(default_factory=list)
    
    def add_entry(self, entry: HistoryEntry) -> None:
        """Add a new entry to the history."""
        self.entries.append(entry)
    
    def get_entries_sorted(self) -> List[HistoryEntry]:
        """Get entries sorted by timestamp (chronological order)."""
        return sorted(self.entries, key=lambda e: e.timestamp)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "shell_id": self.shell_id,
            "entries": [e.to_dict() for e in self.get_entries_sorted()],
        }
