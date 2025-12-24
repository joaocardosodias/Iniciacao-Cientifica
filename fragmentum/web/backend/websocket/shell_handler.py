"""
WebSocket handler for shell terminal interaction.

Requirements:
- 2.1: Open web-based terminal interface
- 2.2: Send commands to remote shell via WebSocket
- 2.3: Display output in terminal in real-time
- 2.4: Transmit appropriate escape sequences for special keys
- 4.4: Support terminal resize events
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum

from fastapi import WebSocket, WebSocketDisconnect

from fragmentum.web.backend.services.shell_manager import get_shell_manager, ShellManager
from fragmentum.web.backend.models.shell import ShellStatus


class ShellMessageType(str, Enum):
    """WebSocket message types for shell communication."""
    INPUT = "input"           # User input from terminal
    OUTPUT = "output"         # Shell output to display
    RESIZE = "resize"         # Terminal resize event
    STATUS = "status"         # Shell status update
    ERROR = "error"           # Error message
    CONNECTED = "connected"   # Connection established
    SPECIAL_KEY = "special_key"  # Special key press (Ctrl+C, etc.)


# =============================================================================
# Special Key Escape Sequences (Requirements 2.4)
# =============================================================================

SPECIAL_KEY_SEQUENCES: Dict[str, bytes] = {
    # Control characters
    "ctrl+c": b"\x03",        # ETX - Interrupt
    "ctrl+d": b"\x04",        # EOT - End of transmission
    "ctrl+z": b"\x1a",        # SUB - Suspend
    "ctrl+l": b"\x0c",        # FF - Form feed (clear screen)
    "ctrl+a": b"\x01",        # SOH - Start of heading (beginning of line)
    "ctrl+e": b"\x05",        # ENQ - End of line
    "ctrl+u": b"\x15",        # NAK - Clear line before cursor
    "ctrl+k": b"\x0b",        # VT - Clear line after cursor
    "ctrl+w": b"\x17",        # ETB - Delete word before cursor
    "ctrl+r": b"\x12",        # DC2 - Reverse search
    "ctrl+p": b"\x10",        # DLE - Previous command
    "ctrl+n": b"\x0e",        # SO - Next command
    
    # Tab
    "tab": b"\t",             # Horizontal tab
    
    # Arrow keys (ANSI escape sequences)
    "arrow_up": b"\x1b[A",    # Cursor up
    "arrow_down": b"\x1b[B",  # Cursor down
    "arrow_right": b"\x1b[C", # Cursor right
    "arrow_left": b"\x1b[D",  # Cursor left
    
    # Other navigation keys
    "home": b"\x1b[H",        # Home
    "end": b"\x1b[F",         # End
    "page_up": b"\x1b[5~",    # Page up
    "page_down": b"\x1b[6~",  # Page down
    "insert": b"\x1b[2~",     # Insert
    "delete": b"\x1b[3~",     # Delete
    
    # Function keys
    "f1": b"\x1bOP",
    "f2": b"\x1bOQ",
    "f3": b"\x1bOR",
    "f4": b"\x1bOS",
    "f5": b"\x1b[15~",
    "f6": b"\x1b[17~",
    "f7": b"\x1b[18~",
    "f8": b"\x1b[19~",
    "f9": b"\x1b[20~",
    "f10": b"\x1b[21~",
    "f11": b"\x1b[23~",
    "f12": b"\x1b[24~",
    
    # Enter/Return
    "enter": b"\r",
    "return": b"\r",
    
    # Backspace
    "backspace": b"\x7f",
    
    # Escape
    "escape": b"\x1b",
}


def get_escape_sequence(key: str) -> Optional[bytes]:
    """
    Get the escape sequence for a special key.
    
    Requirements 2.4: Transmit appropriate escape sequences for special keys.
    
    Args:
        key: The key name (e.g., "ctrl+c", "arrow_up", "tab")
        
    Returns:
        The escape sequence bytes, or None if not found
    """
    return SPECIAL_KEY_SEQUENCES.get(key.lower())


@dataclass
class ShellWebSocketMessage:
    """WebSocket message structure for shell communication."""
    type: ShellMessageType
    data: Any
    timestamp: datetime = None
    shell_id: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
    
    def to_json(self) -> str:
        """Convert message to JSON string."""
        return json.dumps({
            "type": self.type.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "shell_id": self.shell_id,
        })
    
    @classmethod
    def from_json(cls, json_str: str) -> "ShellWebSocketMessage":
        """Parse a JSON string into a message."""
        data = json.loads(json_str)
        return cls(
            type=ShellMessageType(data.get("type", "input")),
            data=data.get("data"),
            shell_id=data.get("shell_id"),
        )


class ShellWebSocketHandler:
    """
    Handles WebSocket communication for shell terminal interaction.
    
    Requirements:
    - 2.1: Open web-based terminal interface
    - 2.2: Send commands to remote shell via WebSocket
    - 2.3: Display output in terminal in real-time
    - 2.4: Transmit appropriate escape sequences for special keys
    - 4.4: Support terminal resize events
    """
    
    def __init__(self, websocket: WebSocket, shell_id: str):
        self.websocket = websocket
        self.shell_id = shell_id
        self.shell_manager: ShellManager = get_shell_manager()
        self._running = False
        self._output_task: Optional[asyncio.Task] = None
    
    async def connect(self) -> bool:
        """
        Establish WebSocket connection for shell terminal.
        
        Requirements 2.1: Open web-based terminal interface.
        
        Returns:
            True if connection successful, False otherwise
        """
        # Verify shell exists and is accessible
        shell = self.shell_manager.get_shell(self.shell_id)
        if not shell:
            await self.websocket.close(code=4004, reason="Shell not found")
            return False
        
        if shell.status == ShellStatus.DISCONNECTED:
            await self.websocket.close(code=4003, reason="Shell is disconnected")
            return False
        
        # Accept the WebSocket connection
        await self.websocket.accept()
        
        # Send connection confirmation
        await self._send_message(ShellWebSocketMessage(
            type=ShellMessageType.CONNECTED,
            data={
                "shell_id": self.shell_id,
                "target_ip": shell.target_ip,
                "target_port": shell.target_port,
                "is_pty": shell.is_pty,
                "status": shell.status.value,
            },
            shell_id=self.shell_id,
        ))
        
        self._running = True
        return True
    
    async def handle_connection(self) -> None:
        """
        Main handler for WebSocket connection lifecycle.
        
        Manages input from terminal and output streaming.
        """
        try:
            # Start output streaming task
            self._output_task = asyncio.create_task(self._stream_output())
            
            # Handle incoming messages
            while self._running:
                try:
                    data = await self.websocket.receive_text()
                    await self._handle_message(data)
                except WebSocketDisconnect:
                    break
                except Exception as e:
                    await self._send_error(str(e))
                    break
        finally:
            await self.disconnect()
    
    async def _handle_message(self, raw_data: str) -> None:
        """
        Handle incoming WebSocket message.
        
        Args:
            raw_data: Raw JSON message from client
        """
        try:
            message = ShellWebSocketMessage.from_json(raw_data)
        except (json.JSONDecodeError, ValueError):
            # Treat as plain text input
            await self.handle_input(raw_data)
            return
        
        if message.type == ShellMessageType.INPUT:
            await self.handle_input(message.data)
        elif message.type == ShellMessageType.SPECIAL_KEY:
            await self.handle_special_key(message.data)
        elif message.type == ShellMessageType.RESIZE:
            await self.handle_resize(message.data)
        elif message.type == ShellMessageType.STATUS:
            # Client requesting status update
            await self._send_status()
    
    async def handle_input(self, data: str) -> None:
        """
        Handle text input from terminal.
        
        Requirements 2.2: Send commands to remote shell via WebSocket.
        
        Args:
            data: Text input from user
        """
        shell = self.shell_manager.get_shell(self.shell_id)
        if not shell or shell.status == ShellStatus.DISCONNECTED:
            await self._send_error("Shell is not connected")
            return
        
        if not shell.socket_obj:
            await self._send_error("Shell socket not available")
            return
        
        try:
            # Send data to shell (don't add newline - let terminal handle it)
            loop = asyncio.get_event_loop()
            await loop.sock_sendall(shell.socket_obj, data.encode('utf-8'))
            
            # Update activity timestamp and mark as connected if was idle
            self.shell_manager.update_activity(self.shell_id)
            if shell.status == ShellStatus.IDLE:
                shell.status = ShellStatus.CONNECTED
            
        except Exception as e:
            shell.status = ShellStatus.DISCONNECTED
            await self._send_error(f"Failed to send input: {e}")
            await self._send_status()
    
    async def handle_special_key(self, key_data: Any) -> None:
        """
        Handle special key press.
        
        Requirements 2.4: Transmit appropriate escape sequences for special keys.
        
        Args:
            key_data: Key identifier (string) or dict with key info
        """
        # Extract key name
        if isinstance(key_data, dict):
            key = key_data.get("key", "")
        else:
            key = str(key_data)
        
        # Get escape sequence
        sequence = get_escape_sequence(key)
        if not sequence:
            # Unknown key, ignore
            return
        
        shell = self.shell_manager.get_shell(self.shell_id)
        if not shell or shell.status == ShellStatus.DISCONNECTED:
            await self._send_error("Shell is not connected")
            return
        
        if not shell.socket_obj:
            await self._send_error("Shell socket not available")
            return
        
        try:
            # Send escape sequence to shell
            loop = asyncio.get_event_loop()
            await loop.sock_sendall(shell.socket_obj, sequence)
            
            # Update activity timestamp
            self.shell_manager.update_activity(self.shell_id)
            
        except Exception as e:
            shell.status = ShellStatus.DISCONNECTED
            await self._send_error(f"Failed to send special key: {e}")
            await self._send_status()

    
    async def handle_resize(self, resize_data: Any) -> None:
        """
        Handle terminal resize event.
        
        Requirements 4.4: Support terminal resize events.
        
        Args:
            resize_data: Dict with cols and rows
        """
        if not isinstance(resize_data, dict):
            return
        
        cols = resize_data.get("cols", 80)
        rows = resize_data.get("rows", 24)
        
        shell = self.shell_manager.get_shell(self.shell_id)
        if not shell:
            return
        
        # Only send resize for PTY shells
        if shell.is_pty:
            success = await self.shell_manager.send_resize(self.shell_id, cols, rows)
            if not success:
                # Resize failed, but don't error - just continue
                pass
    
    async def _stream_output(self) -> None:
        """
        Stream output from shell to WebSocket.
        
        Requirements 2.3: Display output in terminal in real-time.
        """
        shell = self.shell_manager.get_shell(self.shell_id)
        if not shell or not shell.socket_obj:
            return
        
        loop = asyncio.get_event_loop()
        shell.socket_obj.setblocking(False)
        
        while self._running:
            try:
                # Check if shell is still connected (IDLE is ok, DISCONNECTED is not)
                shell = self.shell_manager.get_shell(self.shell_id)
                if not shell or shell.status == ShellStatus.DISCONNECTED:
                    await self._send_status()
                    break
                
                if not shell.socket_obj:
                    break
                
                # Try to read output
                try:
                    data = await asyncio.wait_for(
                        loop.sock_recv(shell.socket_obj, 4096),
                        timeout=0.1
                    )
                    
                    if not data:
                        # Connection closed
                        shell.status = ShellStatus.DISCONNECTED
                        await self._send_status()
                        break
                    
                    # Decode and send output
                    output = data.decode('utf-8', errors='replace')
                    await self._send_output(output)
                    
                    # Update activity and history
                    self.shell_manager.update_activity(self.shell_id)
                    self.shell_manager.update_last_output(self.shell_id, output)
                    
                except asyncio.TimeoutError:
                    # No data available, continue
                    await asyncio.sleep(0.05)
                    
            except Exception as e:
                # Socket error - mark as disconnected
                if shell:
                    shell.status = ShellStatus.DISCONNECTED
                await self._send_error(f"Output stream error: {e}")
                await self._send_status()
                break
    
    async def _send_message(self, message: ShellWebSocketMessage) -> None:
        """Send a message to the WebSocket client."""
        try:
            await self.websocket.send_text(message.to_json())
        except Exception:
            # WebSocket might be closed
            pass
    
    async def _send_output(self, output: str) -> None:
        """Send shell output to the client."""
        await self._send_message(ShellWebSocketMessage(
            type=ShellMessageType.OUTPUT,
            data={"output": output},
            shell_id=self.shell_id,
        ))
    
    async def _send_error(self, error: str) -> None:
        """Send an error message to the client."""
        await self._send_message(ShellWebSocketMessage(
            type=ShellMessageType.ERROR,
            data={"error": error},
            shell_id=self.shell_id,
        ))
    
    async def _send_status(self) -> None:
        """Send current shell status to the client."""
        shell = self.shell_manager.get_shell(self.shell_id)
        status = shell.status.value if shell else "disconnected"
        is_pty = shell.is_pty if shell else False
        
        await self._send_message(ShellWebSocketMessage(
            type=ShellMessageType.STATUS,
            data={
                "status": status,
                "is_pty": is_pty,
            },
            shell_id=self.shell_id,
        ))
    
    async def disconnect(self) -> None:
        """
        Clean up WebSocket connection.
        
        Marks shell as idle when WebSocket disconnects.
        """
        self._running = False
        
        # Cancel output streaming task
        if self._output_task and not self._output_task.done():
            self._output_task.cancel()
            try:
                await self._output_task
            except asyncio.CancelledError:
                pass
        
        # Mark shell as idle (not disconnected - the TCP connection may still be alive)
        shell = self.shell_manager.get_shell(self.shell_id)
        if shell and shell.status == ShellStatus.CONNECTED:
            shell.status = ShellStatus.IDLE


# =============================================================================
# Connection Manager for tracking active WebSocket connections
# =============================================================================

class ShellConnectionManager:
    """
    Manages active WebSocket connections for shells.
    
    Ensures only one WebSocket connection per shell at a time.
    """
    
    def __init__(self):
        self._connections: Dict[str, ShellWebSocketHandler] = {}
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, shell_id: str) -> Optional[ShellWebSocketHandler]:
        """
        Create a new WebSocket connection for a shell.
        
        Args:
            websocket: The WebSocket connection
            shell_id: The shell ID
            
        Returns:
            ShellWebSocketHandler if successful, None otherwise
        """
        async with self._lock:
            # Check if there's already an active connection for this shell
            if shell_id in self._connections:
                # Disconnect the existing connection
                existing = self._connections[shell_id]
                await existing.disconnect()
                del self._connections[shell_id]
            
            # Create new handler
            handler = ShellWebSocketHandler(websocket, shell_id)
            
            # Try to connect
            if await handler.connect():
                self._connections[shell_id] = handler
                return handler
            
            return None
    
    async def disconnect(self, shell_id: str) -> None:
        """
        Disconnect a WebSocket connection for a shell.
        
        Args:
            shell_id: The shell ID
        """
        async with self._lock:
            if shell_id in self._connections:
                handler = self._connections[shell_id]
                await handler.disconnect()
                del self._connections[shell_id]
    
    def get_connection(self, shell_id: str) -> Optional[ShellWebSocketHandler]:
        """Get the active connection for a shell."""
        return self._connections.get(shell_id)
    
    def get_connection_count(self) -> int:
        """Get the number of active shell connections."""
        return len(self._connections)


# Global connection manager instance
_shell_connection_manager: Optional[ShellConnectionManager] = None


def get_shell_connection_manager() -> ShellConnectionManager:
    """Get the global shell connection manager instance."""
    global _shell_connection_manager
    if _shell_connection_manager is None:
        _shell_connection_manager = ShellConnectionManager()
    return _shell_connection_manager
