"""
Shell History service for managing command history.

Requirements:
- 5.1: Log command with timestamp to session history
- 5.2: Display commands and outputs chronologically
- 5.3: Generate formatted log file with timestamps
- 5.4: Preserve history after shell disconnect
"""

import os
import uuid
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict

from fragmentum.web.backend.models.shell import HistoryEntry, ShellHistory


# Default history storage directory
DEFAULT_HISTORY_DIR = Path.home() / ".fragmentum" / "shell_history"


class ShellHistoryService:
    """
    Service for managing shell command history.
    
    Requirements:
    - 5.1: Log command with timestamp to session history
    - 5.2: Display commands and outputs chronologically
    - 5.3: Generate formatted log file with timestamps
    - 5.4: Preserve history after shell disconnect
    """
    
    def __init__(self, history_dir: Optional[Path] = None, persist_to_file: bool = True):
        """
        Initialize the ShellHistoryService.
        
        Args:
            history_dir: Directory for storing history files (default: ~/.fragmentum/shell_history)
            persist_to_file: Whether to persist history to files
        """
        self._histories: Dict[str, ShellHistory] = {}
        self._persist_to_file = persist_to_file
        self._history_dir = history_dir or DEFAULT_HISTORY_DIR
        
        # Create history directory if persistence is enabled
        if self._persist_to_file:
            self._history_dir.mkdir(parents=True, exist_ok=True)
    
    # =========================================================================
    # Core Methods (Requirements 5.1, 5.2, 5.3)
    # =========================================================================
    
    def add_entry(
        self,
        shell_id: str,
        command: str,
        output: str = "",
        timestamp: Optional[datetime] = None
    ) -> HistoryEntry:
        """
        Add a new entry to shell history.
        
        Requirements 5.1: Log command with timestamp to session history
        
        Args:
            shell_id: The shell ID
            command: The command that was executed
            output: The output from the command (can be empty initially)
            timestamp: Optional timestamp (defaults to now)
            
        Returns:
            The created HistoryEntry
        """
        # Ensure history exists for this shell
        if shell_id not in self._histories:
            self._histories[shell_id] = ShellHistory(shell_id=shell_id)
        
        # Create the entry
        entry = HistoryEntry(
            id=str(uuid.uuid4()),
            shell_id=shell_id,
            command=command,
            output=output,
            timestamp=timestamp or datetime.now(timezone.utc),
        )
        
        # Add to in-memory history
        self._histories[shell_id].add_entry(entry)
        
        # Persist to file if enabled
        if self._persist_to_file:
            self._persist_history(shell_id)
        
        return entry
    
    def get_history(self, shell_id: str) -> Optional[ShellHistory]:
        """
        Get the history for a shell.
        
        Requirements 5.2: Display commands and outputs chronologically
        Requirements 5.4: Preserve history after shell disconnect
        
        Args:
            shell_id: The shell ID
            
        Returns:
            ShellHistory if found, None otherwise
        """
        # Try in-memory first
        if shell_id in self._histories:
            return self._histories[shell_id]
        
        # Try loading from file if persistence is enabled
        if self._persist_to_file:
            history = self._load_history(shell_id)
            if history:
                self._histories[shell_id] = history
                return history
        
        return None
    
    def get_entries(self, shell_id: str) -> List[HistoryEntry]:
        """
        Get history entries for a shell, sorted chronologically.
        
        Requirements 5.2: Display commands and outputs chronologically
        
        Args:
            shell_id: The shell ID
            
        Returns:
            List of HistoryEntry objects sorted by timestamp
        """
        history = self.get_history(shell_id)
        if not history:
            return []
        return history.get_entries_sorted()
    
    def export_history(self, shell_id: str, format: str = "text") -> Optional[str]:
        """
        Export shell history to a formatted string.
        
        Requirements 5.3: Generate formatted log file with timestamps
        
        Args:
            shell_id: The shell ID
            format: Export format ("text" or "json")
            
        Returns:
            Formatted history string, or None if shell not found
        """
        history = self.get_history(shell_id)
        if not history:
            return None
        
        entries = history.get_entries_sorted()
        
        if format == "json":
            return self._export_json(shell_id, entries)
        else:
            return self._export_text(shell_id, entries)
    
    def _export_text(self, shell_id: str, entries: List[HistoryEntry]) -> str:
        """Export history as formatted text."""
        lines = [
            f"# Shell History Export",
            f"# Shell ID: {shell_id}",
            f"# Exported: {datetime.now(timezone.utc).isoformat()}",
            f"# Total Commands: {len(entries)}",
            "",
            "=" * 80,
            "",
        ]
        
        for entry in entries:
            timestamp_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"[{timestamp_str}] $ {entry.command}")
            if entry.output:
                # Indent output lines
                for line in entry.output.split('\n'):
                    lines.append(f"  {line}")
            lines.append("")
        
        return '\n'.join(lines)
    
    def _export_json(self, shell_id: str, entries: List[HistoryEntry]) -> str:
        """Export history as JSON."""
        data = {
            "shell_id": shell_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_commands": len(entries),
            "entries": [entry.to_dict() for entry in entries],
        }
        return json.dumps(data, indent=2)
    
    # =========================================================================
    # Additional Methods
    # =========================================================================
    
    def update_output(self, shell_id: str, entry_id: str, output: str) -> bool:
        """
        Update the output of a specific history entry.
        
        Args:
            shell_id: The shell ID
            entry_id: The entry ID to update
            output: The output to set
            
        Returns:
            True if updated, False if not found
        """
        history = self.get_history(shell_id)
        if not history:
            return False
        
        for entry in history.entries:
            if entry.id == entry_id:
                entry.output = output
                if self._persist_to_file:
                    self._persist_history(shell_id)
                return True
        
        return False
    
    def append_output(self, shell_id: str, output: str) -> bool:
        """
        Append output to the last history entry.
        
        Args:
            shell_id: The shell ID
            output: The output to append
            
        Returns:
            True if appended, False if no entries exist
        """
        history = self.get_history(shell_id)
        if not history or not history.entries:
            return False
        
        # Get the last entry (by insertion order)
        last_entry = history.entries[-1]
        last_entry.output += output
        
        if self._persist_to_file:
            self._persist_history(shell_id)
        
        return True
    
    def clear_history(self, shell_id: str) -> bool:
        """
        Clear all history for a shell.
        
        Args:
            shell_id: The shell ID
            
        Returns:
            True if cleared, False if not found
        """
        if shell_id in self._histories:
            self._histories[shell_id].entries.clear()
            
            # Remove persisted file
            if self._persist_to_file:
                history_file = self._get_history_file_path(shell_id)
                if history_file.exists():
                    history_file.unlink()
            
            return True
        return False
    
    def list_shell_ids(self) -> List[str]:
        """
        List all shell IDs that have history.
        
        Returns:
            List of shell IDs
        """
        shell_ids = set(self._histories.keys())
        
        # Also include shells with persisted history
        if self._persist_to_file and self._history_dir.exists():
            for file in self._history_dir.glob("*.json"):
                shell_ids.add(file.stem)
        
        return list(shell_ids)
    
    # =========================================================================
    # Persistence Methods (Requirement 5.4)
    # =========================================================================
    
    def _get_history_file_path(self, shell_id: str) -> Path:
        """Get the file path for a shell's history."""
        return self._history_dir / f"{shell_id}.json"
    
    def _persist_history(self, shell_id: str) -> None:
        """
        Persist shell history to file.
        
        Requirements 5.4: Preserve history after shell disconnect
        """
        history = self._histories.get(shell_id)
        if not history:
            return
        
        history_file = self._get_history_file_path(shell_id)
        
        data = {
            "shell_id": shell_id,
            "entries": [
                {
                    "id": e.id,
                    "shell_id": e.shell_id,
                    "command": e.command,
                    "output": e.output,
                    "timestamp": e.timestamp.isoformat(),
                }
                for e in history.entries
            ],
        }
        
        with open(history_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _load_history(self, shell_id: str) -> Optional[ShellHistory]:
        """
        Load shell history from file.
        
        Requirements 5.4: Preserve history after shell disconnect
        """
        history_file = self._get_history_file_path(shell_id)
        
        if not history_file.exists():
            return None
        
        try:
            with open(history_file, 'r') as f:
                data = json.load(f)
            
            history = ShellHistory(shell_id=shell_id)
            
            for entry_data in data.get("entries", []):
                entry = HistoryEntry(
                    id=entry_data["id"],
                    shell_id=entry_data["shell_id"],
                    command=entry_data["command"],
                    output=entry_data["output"],
                    timestamp=datetime.fromisoformat(entry_data["timestamp"]),
                )
                history.add_entry(entry)
            
            return history
            
        except (json.JSONDecodeError, KeyError, ValueError):
            return None
    
    def load_all_histories(self) -> None:
        """Load all persisted histories into memory."""
        if not self._persist_to_file or not self._history_dir.exists():
            return
        
        for file in self._history_dir.glob("*.json"):
            shell_id = file.stem
            if shell_id not in self._histories:
                history = self._load_history(shell_id)
                if history:
                    self._histories[shell_id] = history


# Global shell history service instance
_shell_history_service: Optional[ShellHistoryService] = None


def get_shell_history_service() -> ShellHistoryService:
    """Get the global shell history service instance."""
    global _shell_history_service
    if _shell_history_service is None:
        _shell_history_service = ShellHistoryService()
    return _shell_history_service
