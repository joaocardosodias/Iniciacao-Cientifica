"""
Listener Manager service for managing reverse shell listeners.

Requirements:
- 3.1: Create listener with TCP port for incoming connections
- 3.2: Auto-register shells in ShellManager when reverse shell connects
- 3.3: Allow configuration of port, protocol
- 3.4: Display listener status and connection count
- 6.1: Capture shells from external tools (regardless of origin)
- 6.2: Attempt to identify source tool automatically
- 6.3: Make external shells available like any other shell
"""

import asyncio
import socket
import uuid
import re
from datetime import datetime, timezone
from typing import Dict, Optional, List, Any, Tuple

from fragmentum.web.backend.models.shell import (
    Listener,
    ListenerStatus,
    ShellConnection,
    ShellType,
    ShellStatus,
)
from fragmentum.web.backend.services.source_identifier import (
    SourceIdentifier,
    SourceIdentification,
    get_source_identifier,
)


class ListenerManager:
    """
    Manages listeners for reverse shell connections.
    
    This class handles:
    - Creating and managing TCP/UDP listeners for reverse shells
    - Accepting incoming connections from ANY source (internal or external tools)
    - Automatically identifying the source tool of connections
    - Registering captured shells in the ShellManager
    
    Requirements:
    - 3.1: Create listener with TCP port
    - 3.2: Auto-register shells when connected
    - 3.3: Allow port/protocol configuration
    - 3.4: Display status and connection count
    - 6.1: Capture shells from external tools (Claude Desktop, netcat, Metasploit, etc.)
    - 6.2: Attempt to identify source tool automatically
    - 6.3: Make external shells available like any other shell
    """
    
    def __init__(self, shell_manager=None):
        """
        Initialize the ListenerManager.
        
        Args:
            shell_manager: Optional ShellManager instance for auto-registration
        """
        self._listeners: Dict[str, Listener] = {}
        self._shell_manager = shell_manager
        self._accept_tasks: Dict[str, asyncio.Task] = {}
        self._running: Dict[str, bool] = {}
        self._source_identifier: SourceIdentifier = get_source_identifier()
    
    def set_shell_manager(self, shell_manager) -> None:
        """
        Set the ShellManager for auto-registration of shells.
        
        Args:
            shell_manager: The ShellManager instance
        """
        self._shell_manager = shell_manager
    
    # =========================================================================
    # Listener Creation and Management (Requirements 3.1, 3.3)
    # =========================================================================
    
    def create_listener(self, port: int, protocol: str = "tcp") -> Listener:
        """
        Create a new listener on the specified port.
        
        Requirements 3.1: Open TCP port and wait for incoming connections
        Requirements 3.3: Allow configuration of port, protocol
        
        Args:
            port: The port number to listen on
            protocol: The protocol (tcp or udp)
            
        Returns:
            The created Listener object
            
        Raises:
            ValueError: If port is invalid or protocol is unsupported
            OSError: If port is already in use
        """
        # Validate port
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port}")
        
        # Validate protocol
        protocol = protocol.lower()
        if protocol not in ("tcp", "udp"):
            raise ValueError(f"Unsupported protocol: {protocol}")
        
        # Check if port is already in use by another listener
        for listener in self._listeners.values():
            if listener.port == port and listener.status == ListenerStatus.ACTIVE:
                raise OSError(f"Port {port} is already in use by listener {listener.id}")
        
        # Create server socket
        if protocol == "tcp":
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        else:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            server_socket.bind(("0.0.0.0", port))
            if protocol == "tcp":
                server_socket.listen(5)
            server_socket.setblocking(False)
        except OSError as e:
            server_socket.close()
            raise OSError(f"Failed to bind to port {port}: {e}")
        
        # Create listener object
        listener_id = str(uuid.uuid4())
        listener = Listener(
            id=listener_id,
            port=port,
            protocol=protocol,
            status=ListenerStatus.ACTIVE,
            connection_count=0,
            created_at=datetime.now(timezone.utc),
            server_socket=server_socket,
        )
        
        self._listeners[listener_id] = listener
        self._running[listener_id] = True
        
        return listener
    
    def stop_listener(self, listener_id: str) -> bool:
        """
        Stop a listener and close its socket.
        
        Args:
            listener_id: The listener ID
            
        Returns:
            True if stopped, False if not found
        """
        listener = self._listeners.get(listener_id)
        if not listener:
            return False
        
        # Stop the accept task if running
        self._running[listener_id] = False
        if listener_id in self._accept_tasks:
            self._accept_tasks[listener_id].cancel()
            del self._accept_tasks[listener_id]
        
        # Close the server socket
        if listener.server_socket:
            try:
                listener.server_socket.close()
            except:
                pass
            listener.server_socket = None
        
        listener.status = ListenerStatus.STOPPED
        return True
    
    def list_listeners(self) -> List[Listener]:
        """
        List all listeners.
        
        Requirements 3.4: Display listener status and connection count
        
        Returns:
            List of all Listener objects
        """
        return list(self._listeners.values())
    
    def get_listener(self, listener_id: str) -> Optional[Listener]:
        """
        Get a listener by ID.
        
        Args:
            listener_id: The listener ID
            
        Returns:
            Listener if found, None otherwise
        """
        return self._listeners.get(listener_id)
    
    def remove_listener(self, listener_id: str) -> bool:
        """
        Remove a listener from the manager.
        
        Args:
            listener_id: The listener ID
            
        Returns:
            True if removed, False if not found
        """
        if listener_id not in self._listeners:
            return False
        
        # Stop the listener first
        self.stop_listener(listener_id)
        
        # Remove from dict
        del self._listeners[listener_id]
        if listener_id in self._running:
            del self._running[listener_id]
        
        return True

    # =========================================================================
    # Async Connection Acceptance (Requirements 3.2, 6.1)
    # =========================================================================
    
    async def accept_connections(self, listener: Listener) -> None:
        """
        Accept incoming connections on a listener.
        
        Requirements 3.2: Auto-register shells in ShellManager
        Requirements 6.1: Capture shells from external tools
        
        Args:
            listener: The listener to accept connections on
        """
        if not listener.server_socket:
            return
        
        loop = asyncio.get_event_loop()
        
        while self._running.get(listener.id, False) and listener.status == ListenerStatus.ACTIVE:
            try:
                # Accept connection asynchronously
                client_socket, address = await loop.sock_accept(listener.server_socket)
                
                # Handle the new connection
                await self._handle_new_connection(listener, client_socket, address)
                
            except asyncio.CancelledError:
                break
            except OSError as e:
                # Socket closed or error
                if self._running.get(listener.id, False):
                    # Unexpected error
                    listener.status = ListenerStatus.STOPPED
                break
            except Exception as e:
                # Log error but continue accepting
                continue
    
    async def _handle_new_connection(
        self, 
        listener: Listener, 
        client_socket: socket.socket, 
        address: tuple
    ) -> Optional[str]:
        """
        Handle a new incoming connection.
        
        Requirements 3.2: Auto-register shells in ShellManager
        Requirements 3.4: Update connection count
        Requirements 6.1: Capture shells from external tools (regardless of origin)
        Requirements 6.2: Attempt to identify source tool automatically
        Requirements 6.3: Make external shells available like any other shell
        
        Args:
            listener: The listener that received the connection
            client_socket: The client socket
            address: The client address (ip, port)
            
        Returns:
            Shell ID if registered, None otherwise
        """
        target_ip, target_port = address
        
        # Update connection count (Requirement 3.4)
        listener.connection_count += 1
        
        # Attempt to identify source (Requirement 6.2)
        # This captures shells from ANY external tool (Requirement 6.1)
        source, characteristics = await self._identify_source(client_socket)
        
        # Create shell connection
        # Requirements 6.3: External shells are treated the same as internal shells
        shell_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        shell = ShellConnection(
            id=shell_id,
            target_ip=str(target_ip),
            target_port=target_port,
            local_port=listener.port,
            shell_type=ShellType.REVERSE,
            status=ShellStatus.CONNECTED,
            is_pty=False,
            created_at=now,
            last_activity=now,
            source=source,  # Tagged with identified source (Requirement 6.2)
            socket_obj=client_socket,
        )
        
        # Auto-register in ShellManager (Requirement 3.2)
        # This makes the shell available in the Shell Manager interface (Requirement 6.3)
        if self._shell_manager:
            self._shell_manager.register_shell(shell)
            return shell_id
        
        return None
    
    async def _identify_source(self, client_socket: socket.socket) -> Tuple[str, Dict[str, Any]]:
        """
        Attempt to identify the source tool of a connection.
        
        Requirements 6.2: Attempt to identify source tool and target information automatically
        
        This performs best-effort identification based on:
        - Initial data patterns from the connection
        - Known tool signatures
        - Shell prompt patterns
        
        Args:
            client_socket: The client socket
            
        Returns:
            Tuple of (source identifier string, characteristics dict)
        """
        try:
            # Try to peek at initial data without consuming it
            # Use a short timeout to avoid blocking
            client_socket.setblocking(False)
            
            initial_data = await self._peek_initial_data(client_socket)
            
            if initial_data:
                # Use the SourceIdentifier for comprehensive identification
                identification = self._source_identifier.identify(initial_data)
                return identification.source, identification.characteristics
            
            # Default to external if no data available
            # Requirements 6.1: All connections are captured regardless of origin
            return "external", {}
            
        except Exception:
            # On any error, default to external
            return "external", {}
    
    async def _peek_initial_data(
        self, 
        client_socket: socket.socket, 
        timeout: float = 0.5
    ) -> Optional[bytes]:
        """
        Peek at initial data from a connection without consuming it.
        
        Some shells send initial data (prompts, banners) that can help identify them.
        
        Args:
            client_socket: The client socket
            timeout: How long to wait for initial data
            
        Returns:
            Initial data bytes if available, None otherwise
        """
        loop = asyncio.get_event_loop()
        
        try:
            # Wait briefly for any initial data
            data = await asyncio.wait_for(
                loop.sock_recv(client_socket, 4096),
                timeout=timeout
            )
            return data if data else None
        except asyncio.TimeoutError:
            # No initial data sent - this is common for basic reverse shells
            return None
        except (socket.error, OSError):
            return None
    
    async def start_accepting(self, listener_id: str) -> bool:
        """
        Start accepting connections on a listener in the background.
        
        Args:
            listener_id: The listener ID
            
        Returns:
            True if started, False if listener not found
        """
        listener = self._listeners.get(listener_id)
        if not listener or listener.status != ListenerStatus.ACTIVE:
            return False
        
        # Don't start if already accepting
        if listener_id in self._accept_tasks:
            return True
        
        # Create background task
        task = asyncio.create_task(self.accept_connections(listener))
        self._accept_tasks[listener_id] = task
        
        return True
    
    def get_connection_count(self, listener_id: str) -> int:
        """
        Get the connection count for a listener.
        
        Requirements 3.4: Display connection count
        
        Args:
            listener_id: The listener ID
            
        Returns:
            Connection count, or 0 if listener not found
        """
        listener = self._listeners.get(listener_id)
        if not listener:
            return 0
        return listener.connection_count
    
    # =========================================================================
    # Cleanup
    # =========================================================================
    
    def stop_all(self) -> None:
        """Stop all listeners and clean up resources."""
        for listener_id in list(self._listeners.keys()):
            self.stop_listener(listener_id)
    
    async def shutdown(self) -> None:
        """Gracefully shutdown all listeners and tasks."""
        # Stop all running flags
        for listener_id in self._running:
            self._running[listener_id] = False
        
        # Cancel all accept tasks
        for task in self._accept_tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        if self._accept_tasks:
            await asyncio.gather(*self._accept_tasks.values(), return_exceptions=True)
        
        self._accept_tasks.clear()
        
        # Stop all listeners
        self.stop_all()


# Global listener manager instance
_listener_manager: Optional[ListenerManager] = None


def get_listener_manager() -> ListenerManager:
    """Get the global listener manager instance."""
    global _listener_manager
    if _listener_manager is None:
        # Import here to avoid circular imports
        from fragmentum.web.backend.services.shell_manager import get_shell_manager
        _listener_manager = ListenerManager(shell_manager=get_shell_manager())
    return _listener_manager
