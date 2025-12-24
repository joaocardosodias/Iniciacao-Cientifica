"""
Shell Manager service for managing shell connections.

Requirements:
- 1.1: Register connection with metadata (target IP, port, type, timestamp)
- 1.2: Display list of all active shells with status
- 1.3: Mark shells as idle after 5 minutes of inactivity
- 1.4: Update status to disconnected on connection loss
- 2.2: Send commands to remote shell via WebSocket
- 2.3: Display output in terminal in real-time
- 4.1, 4.2, 4.3: PTY upgrade functionality
"""

import asyncio
import uuid
import socket
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List, AsyncIterator, Any, TYPE_CHECKING
from dataclasses import dataclass, field

from fragmentum.web.backend.models.shell import (
    ShellConnection,
    ShellType,
    ShellStatus,
    HistoryEntry,
    ShellHistory,
)

if TYPE_CHECKING:
    from fragmentum.web.backend.services.shell_history import ShellHistoryService


# Constants
IDLE_TIMEOUT_MINUTES = 5
PTY_UPGRADE_COMMANDS = [
    # Python PTY spawn
    "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
    # Script command
    "script -qc /bin/bash /dev/null",
    # Socat
    "socat exec:'bash -li',pty,stderr,setsid,sigint,sane -",
]


class ShellManager:
    """
    Manages all active shell connections.
    
    Requirements:
    - 1.1: Register connection with metadata
    - 1.2: Display list of all active shells with status
    - 1.3: Mark shells as idle after 5 minutes
    - 1.4: Update status on connection loss
    """
    
    def __init__(self, history_service: Optional["ShellHistoryService"] = None):
        self._shells: Dict[str, ShellConnection] = {}
        self._histories: Dict[str, ShellHistory] = {}  # Fallback in-memory history
        self._history_service: Optional["ShellHistoryService"] = history_service
        self._idle_check_task: Optional[asyncio.Task] = None
        self._websocket_hub = None
        self._running = False
    
    def set_history_service(self, service: "ShellHistoryService") -> None:
        """Set the shell history service for persistent history management."""
        self._history_service = service
    
    def set_websocket_hub(self, hub) -> None:
        """Set the WebSocket hub for real-time notifications."""
        self._websocket_hub = hub
    
    # =========================================================================
    # Shell Registration and Retrieval (Requirements 1.1, 1.2)
    # =========================================================================
    
    def register_shell(self, connection: ShellConnection) -> str:
        """
        Register a new shell connection.
        
        Requirements 1.1: Register connection with metadata (target IP, port, type, timestamp)
        
        Args:
            connection: The ShellConnection to register
            
        Returns:
            The shell ID
        """
        self._shells[connection.id] = connection
        # Initialize history for this shell
        self._histories[connection.id] = ShellHistory(shell_id=connection.id)
        return connection.id
    
    def get_shell(self, shell_id: str) -> Optional[ShellConnection]:
        """
        Get a shell by ID.
        
        Args:
            shell_id: The shell ID
            
        Returns:
            ShellConnection if found, None otherwise
        """
        return self._shells.get(shell_id)
    
    def list_shells(self) -> List[ShellConnection]:
        """
        List all registered shells.
        
        Requirements 1.2: Display list of all active shells with status
        
        Returns:
            List of all ShellConnection objects
        """
        return list(self._shells.values())
    
    def get_shells_by_status(self, status: ShellStatus) -> List[ShellConnection]:
        """
        Get shells filtered by status.
        
        Args:
            status: The status to filter by
            
        Returns:
            List of shells with the given status
        """
        return [s for s in self._shells.values() if s.status == status]
    
    # =========================================================================
    # Status Management (Requirements 1.3, 1.4)
    # =========================================================================
    
    def update_status(self, shell_id: str, status: ShellStatus) -> bool:
        """
        Update the status of a shell.
        
        Requirements 1.3, 1.4: Update shell status
        
        Args:
            shell_id: The shell ID
            status: The new status
            
        Returns:
            True if updated, False if shell not found
        """
        shell = self._shells.get(shell_id)
        if not shell:
            return False
        
        shell.status = status
        if status == ShellStatus.CONNECTED:
            shell.last_activity = datetime.now(timezone.utc)
        
        return True
    
    def update_activity(self, shell_id: str) -> bool:
        """
        Update the last activity timestamp for a shell.
        
        Args:
            shell_id: The shell ID
            
        Returns:
            True if updated, False if shell not found
        """
        shell = self._shells.get(shell_id)
        if not shell:
            return False
        
        shell.last_activity = datetime.now(timezone.utc)
        # If shell was idle, mark it as connected again
        if shell.status == ShellStatus.IDLE:
            shell.status = ShellStatus.CONNECTED
        
        return True
    
    async def check_idle_shells(self) -> None:
        """
        Check for idle shells and update their status.
        
        Requirements 1.3: Mark shells as idle after 5 minutes of inactivity
        """
        idle_threshold = datetime.now(timezone.utc) - timedelta(minutes=IDLE_TIMEOUT_MINUTES)
        
        for shell in self._shells.values():
            if shell.status == ShellStatus.CONNECTED:
                if shell.last_activity < idle_threshold:
                    shell.status = ShellStatus.IDLE
                    # Notify via WebSocket if available
                    if self._websocket_hub:
                        await self._websocket_hub.broadcast_shell_status(
                            shell.id, ShellStatus.IDLE.value
                        )
    
    async def start_idle_checker(self) -> None:
        """
        Start the background task for idle detection.
        
        Requirements 1.3: Background task for idle detection (5 min threshold)
        """
        self._running = True
        while self._running:
            await self.check_idle_shells()
            await asyncio.sleep(60)  # Check every minute
    
    def stop_idle_checker(self) -> None:
        """Stop the idle checker background task."""
        self._running = False
        if self._idle_check_task:
            self._idle_check_task.cancel()
            self._idle_check_task = None
    
    # =========================================================================
    # Shell I/O Methods (Requirements 2.2, 2.3)
    # =========================================================================
    
    async def send_command(self, shell_id: str, command: str) -> bool:
        """
        Send a command to a shell.
        
        Requirements 2.2: Send command to remote shell
        
        Args:
            shell_id: The shell ID
            command: The command to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        shell = self._shells.get(shell_id)
        if not shell or shell.status == ShellStatus.DISCONNECTED:
            return False
        
        if not shell.socket_obj:
            return False
        
        try:
            # Ensure command ends with newline
            if not command.endswith('\n'):
                command += '\n'
            
            # Send command to socket
            loop = asyncio.get_event_loop()
            await loop.sock_sendall(shell.socket_obj, command.encode('utf-8'))
            
            # Update activity timestamp
            self.update_activity(shell_id)
            
            # Log command to history
            self._add_history_entry(shell_id, command.strip(), "")
            
            return True
            
        except (socket.error, OSError) as e:
            # Connection lost
            shell.status = ShellStatus.DISCONNECTED
            return False
    
    async def receive_output(self, shell_id: str, timeout: float = 0.1) -> AsyncIterator[str]:
        """
        Receive output from a shell as an async iterator.
        
        Requirements 2.3: Display output in terminal in real-time
        
        Args:
            shell_id: The shell ID
            timeout: Read timeout in seconds
            
        Yields:
            Output chunks from the shell
        """
        shell = self._shells.get(shell_id)
        if not shell or not shell.socket_obj:
            return
        
        loop = asyncio.get_event_loop()
        shell.socket_obj.setblocking(False)
        
        while shell.status != ShellStatus.DISCONNECTED:
            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(shell.socket_obj, 4096),
                    timeout=timeout
                )
                
                if not data:
                    # Connection closed
                    shell.status = ShellStatus.DISCONNECTED
                    break
                
                output = data.decode('utf-8', errors='replace')
                self.update_activity(shell_id)
                yield output
                
            except asyncio.TimeoutError:
                # No data available, continue
                yield ""
            except (socket.error, OSError):
                shell.status = ShellStatus.DISCONNECTED
                break
    
    # =========================================================================
    # PTY Upgrade (Requirements 4.1, 4.2, 4.3)
    # =========================================================================
    
    async def upgrade_to_pty(self, shell_id: str) -> bool:
        """
        Attempt to upgrade a shell to a PTY.
        
        Requirements 4.1: Attempt to spawn PTY using Python, script, or socat
        Requirements 4.2: Enable full terminal emulation on success
        Requirements 4.3: Notify user and continue with basic shell on failure
        
        Args:
            shell_id: The shell ID
            
        Returns:
            True if upgrade succeeded, False otherwise
        """
        shell = self._shells.get(shell_id)
        if not shell or shell.status == ShellStatus.DISCONNECTED:
            return False
        
        if shell.is_pty:
            return True  # Already a PTY
        
        # Try each PTY upgrade command
        for cmd in PTY_UPGRADE_COMMANDS:
            success = await self._try_pty_upgrade(shell, cmd)
            if success:
                shell.is_pty = True
                return True
        
        # All methods failed
        return False
    
    async def _try_pty_upgrade(self, shell: ShellConnection, command: str) -> bool:
        """
        Try a single PTY upgrade command.
        
        Args:
            shell: The shell connection
            command: The PTY upgrade command to try
            
        Returns:
            True if upgrade succeeded, False otherwise
        """
        if not shell.socket_obj:
            return False
        
        try:
            loop = asyncio.get_event_loop()
            
            # Send the upgrade command
            await loop.sock_sendall(shell.socket_obj, f"{command}\n".encode('utf-8'))
            
            # Wait a bit for the command to execute
            await asyncio.sleep(0.5)
            
            # Try to read response
            shell.socket_obj.setblocking(False)
            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(shell.socket_obj, 4096),
                    timeout=2.0
                )
                
                # Check if we got a prompt or error
                response = data.decode('utf-8', errors='replace')
                
                # If we get an error message, the upgrade failed
                if 'not found' in response.lower() or 'error' in response.lower():
                    return False
                
                # If we get a prompt or no error, assume success
                return True
                
            except asyncio.TimeoutError:
                # No response might mean success (waiting for input)
                return True
                
        except (socket.error, OSError):
            return False
    
    async def send_resize(self, shell_id: str, cols: int, rows: int) -> bool:
        """
        Send terminal resize event to a PTY shell.
        
        Requirements 4.4: Support terminal resize events
        
        Args:
            shell_id: The shell ID
            cols: Number of columns
            rows: Number of rows
            
        Returns:
            True if sent successfully, False otherwise
        """
        shell = self._shells.get(shell_id)
        if not shell or not shell.is_pty:
            return False
        
        # Send SIGWINCH via stty if possible
        resize_cmd = f"stty cols {cols} rows {rows}\n"
        return await self.send_command(shell_id, resize_cmd)
    
    # =========================================================================
    # Shell Lifecycle
    # =========================================================================
    
    def close_shell(self, shell_id: str) -> bool:
        """
        Close a shell connection.
        
        Args:
            shell_id: The shell ID
            
        Returns:
            True if closed, False if not found
        """
        shell = self._shells.get(shell_id)
        if not shell:
            return False
        
        # Close the socket if open
        if shell.socket_obj:
            try:
                shell.socket_obj.close()
            except:
                pass
            shell.socket_obj = None
        
        shell.status = ShellStatus.DISCONNECTED
        return True
    
    def remove_shell(self, shell_id: str) -> bool:
        """
        Remove a shell from the manager (but preserve history).
        
        Args:
            shell_id: The shell ID
            
        Returns:
            True if removed, False if not found
        """
        if shell_id not in self._shells:
            return False
        
        # Close the shell first
        self.close_shell(shell_id)
        
        # Remove from shells dict (history is preserved)
        del self._shells[shell_id]
        return True
    
    # =========================================================================
    # History Management
    # =========================================================================
    
    def _add_history_entry(self, shell_id: str, command: str, output: str) -> None:
        """Add an entry to shell history."""
        # Use history service if available
        if self._history_service:
            self._history_service.add_entry(shell_id, command, output)
            return
        
        # Fallback to in-memory history
        if shell_id not in self._histories:
            self._histories[shell_id] = ShellHistory(shell_id=shell_id)
        
        entry = HistoryEntry(
            id=str(uuid.uuid4()),
            shell_id=shell_id,
            command=command,
            output=output,
            timestamp=datetime.now(timezone.utc),
        )
        self._histories[shell_id].add_entry(entry)
    
    def get_history(self, shell_id: str) -> Optional[ShellHistory]:
        """
        Get the history for a shell.
        
        Requirements 5.4: Preserve history after shell disconnect
        
        Args:
            shell_id: The shell ID
            
        Returns:
            ShellHistory if found, None otherwise
        """
        # Use history service if available
        if self._history_service:
            return self._history_service.get_history(shell_id)
        
        # Fallback to in-memory history
        return self._histories.get(shell_id)
    
    def update_last_output(self, shell_id: str, output: str) -> None:
        """
        Update the output of the last history entry.
        
        Args:
            shell_id: The shell ID
            output: The output to append
        """
        # Use history service if available
        if self._history_service:
            self._history_service.append_output(shell_id, output)
            return
        
        # Fallback to in-memory history
        history = self._histories.get(shell_id)
        if history and history.entries:
            last_entry = history.entries[-1]
            last_entry.output += output


# Global shell manager instance
_shell_manager: Optional[ShellManager] = None


def get_shell_manager() -> ShellManager:
    """Get the global shell manager instance."""
    global _shell_manager
    if _shell_manager is None:
        _shell_manager = ShellManager()
    return _shell_manager
