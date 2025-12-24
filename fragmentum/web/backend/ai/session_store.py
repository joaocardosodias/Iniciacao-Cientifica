"""
Chat Session Storage for AI Chat Integration.

Provides persistent storage for chat sessions, allowing users to
save, load, and restore conversation history.

Requirements:
- 5.2: Restore previous conversation history
- 5.5: Preserve tool execution output in history
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import uuid

from fragmentum.core.config import get_config
from fragmentum.web.backend.ai.models import (
    ChatSession,
    ChatSessionSummary,
    ChatMessage,
    MessageRole,
    ToolExecution,
    ToolCall,
    Finding,
)


class SessionStoreError(Exception):
    """Base exception for session store errors."""
    pass


class SessionNotFoundError(SessionStoreError):
    """Raised when a session is not found."""
    pass


class SessionStore:
    """
    Persistent storage for chat sessions.
    
    Stores sessions as JSON files in the data directory, with an
    in-memory cache for fast access to active sessions.
    
    Requirements:
    - 5.2: Restore previous conversation history
    - 5.5: Preserve tool execution output in history
    """
    
    def __init__(self, storage_dir: Optional[Path] = None):
        """
        Initialize the session store.
        
        Args:
            storage_dir: Optional custom storage directory.
                        Defaults to ~/.fragmentum/chat_sessions/
        """
        if storage_dir is None:
            config = get_config()
            storage_dir = config.data_dir / "chat_sessions"
        
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache for active sessions
        self._cache: Dict[str, ChatSession] = {}
        
        # Current active session
        self._current_session_id: Optional[str] = None
    
    @property
    def storage_dir(self) -> Path:
        """Get the storage directory path."""
        return self._storage_dir
    
    @property
    def current_session_id(self) -> Optional[str]:
        """Get the current active session ID."""
        return self._current_session_id
    
    def _get_session_path(self, session_id: str) -> Path:
        """Get the file path for a session."""
        return self._storage_dir / f"{session_id}.json"
    
    def _serialize_session(self, session: ChatSession) -> str:
        """
        Serialize a session to JSON string.
        
        Args:
            session: The session to serialize
            
        Returns:
            JSON string representation
        """
        return session.model_dump_json(indent=2)
    
    def _deserialize_session(self, data: str) -> ChatSession:
        """
        Deserialize a session from JSON string.
        
        Args:
            data: JSON string
            
        Returns:
            ChatSession object
        """
        return ChatSession.model_validate_json(data)
    
    def create(
        self,
        title: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> ChatSession:
        """
        Create a new chat session.
        
        Args:
            title: Optional title for the session
            metadata: Optional metadata dictionary
            
        Returns:
            The created ChatSession
            
        Requirements: 5.1 - Create new Chat_Session with unique identifier
        """
        session = ChatSession(
            id=str(uuid.uuid4()),
            title=title,
            metadata=metadata or {},
        )
        
        # Add to cache
        self._cache[session.id] = session
        
        # Set as current session
        self._current_session_id = session.id
        
        # Persist to disk
        self._save_to_disk(session)
        
        return session
    
    def get(self, session_id: str) -> ChatSession:
        """
        Get a session by ID.
        
        Args:
            session_id: The session ID
            
        Returns:
            The ChatSession
            
        Raises:
            SessionNotFoundError: If session doesn't exist
            
        Requirements: 5.2 - Restore previous conversation history
        """
        # Check cache first
        if session_id in self._cache:
            return self._cache[session_id]
        
        # Load from disk
        session = self._load_from_disk(session_id)
        
        # Add to cache
        self._cache[session_id] = session
        
        return session
    
    def get_or_create(
        self,
        session_id: Optional[str] = None,
        title: Optional[str] = None,
    ) -> ChatSession:
        """
        Get an existing session or create a new one.
        
        Args:
            session_id: Optional session ID to retrieve
            title: Optional title for new session
            
        Returns:
            The ChatSession (existing or new)
        """
        if session_id:
            try:
                return self.get(session_id)
            except SessionNotFoundError:
                pass
        
        return self.create(title=title)
    
    def save(self, session: ChatSession) -> None:
        """
        Save a session to persistent storage.
        
        Args:
            session: The session to save
            
        Requirements: 5.5 - Preserve tool execution output in history
        """
        # Update timestamp
        session.updated_at = datetime.utcnow()
        
        # Update cache
        self._cache[session.id] = session
        
        # Persist to disk
        self._save_to_disk(session)
    
    def _save_to_disk(self, session: ChatSession) -> None:
        """
        Save a session to disk.
        
        Args:
            session: The session to save
        """
        path = self._get_session_path(session.id)
        data = self._serialize_session(session)
        
        # Write atomically using temp file
        temp_path = path.with_suffix('.tmp')
        try:
            temp_path.write_text(data, encoding='utf-8')
            temp_path.replace(path)
        except Exception as e:
            # Clean up temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise SessionStoreError(f"Failed to save session: {e}")
    
    def _load_from_disk(self, session_id: str) -> ChatSession:
        """
        Load a session from disk.
        
        Args:
            session_id: The session ID
            
        Returns:
            The ChatSession
            
        Raises:
            SessionNotFoundError: If session file doesn't exist
        """
        path = self._get_session_path(session_id)
        
        if not path.exists():
            raise SessionNotFoundError(f"Session not found: {session_id}")
        
        try:
            data = path.read_text(encoding='utf-8')
            return self._deserialize_session(data)
        except Exception as e:
            raise SessionStoreError(f"Failed to load session: {e}")
    
    def delete(self, session_id: str) -> bool:
        """
        Delete a session.
        
        Args:
            session_id: The session ID to delete
            
        Returns:
            True if deleted, False if not found
        """
        # Remove from cache
        self._cache.pop(session_id, None)
        
        # Clear current session if it's being deleted
        if self._current_session_id == session_id:
            self._current_session_id = None
        
        # Remove from disk
        path = self._get_session_path(session_id)
        if path.exists():
            path.unlink()
            return True
        
        return False
    
    def list_sessions(
        self,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[ChatSessionSummary]:
        """
        List all sessions with summaries.
        
        Args:
            limit: Optional limit on number of sessions
            offset: Offset for pagination
            
        Returns:
            List of ChatSessionSummary objects, sorted by updated_at desc
        """
        summaries = []
        
        # Get all session files
        session_files = list(self._storage_dir.glob("*.json"))
        
        for path in session_files:
            try:
                session_id = path.stem
                session = self.get(session_id)
                summaries.append(ChatSessionSummary.from_session(session))
            except Exception:
                # Skip corrupted sessions
                continue
        
        # Sort by updated_at descending
        summaries.sort(key=lambda s: s.updated_at, reverse=True)
        
        # Apply pagination
        if offset:
            summaries = summaries[offset:]
        if limit:
            summaries = summaries[:limit]
        
        return summaries
    
    def get_current_session(self) -> Optional[ChatSession]:
        """
        Get the current active session.
        
        Returns:
            The current ChatSession or None
        """
        if self._current_session_id:
            try:
                return self.get(self._current_session_id)
            except SessionNotFoundError:
                self._current_session_id = None
        return None
    
    def set_current_session(self, session_id: str) -> ChatSession:
        """
        Set the current active session.
        
        Args:
            session_id: The session ID to set as current
            
        Returns:
            The ChatSession
            
        Raises:
            SessionNotFoundError: If session doesn't exist
        """
        session = self.get(session_id)
        self._current_session_id = session_id
        return session
    
    def add_message(
        self,
        session_id: str,
        role: MessageRole,
        content: str,
        tool_calls: Optional[List[ToolCall]] = None,
        tool_execution: Optional[ToolExecution] = None,
    ) -> ChatMessage:
        """
        Add a message to a session.
        
        Args:
            session_id: The session ID
            role: Message role
            content: Message content
            tool_calls: Optional tool calls
            tool_execution: Optional tool execution record
            
        Returns:
            The created ChatMessage
        """
        session = self.get(session_id)
        message = session.add_message(
            role=role,
            content=content,
            tool_calls=tool_calls,
            tool_execution=tool_execution,
        )
        self.save(session)
        return message
    
    def clear_cache(self) -> None:
        """Clear the in-memory cache."""
        self._cache.clear()
    
    def session_exists(self, session_id: str) -> bool:
        """
        Check if a session exists.
        
        Args:
            session_id: The session ID
            
        Returns:
            True if session exists
        """
        if session_id in self._cache:
            return True
        return self._get_session_path(session_id).exists()


# Global session store instance
_session_store: Optional[SessionStore] = None


def get_session_store() -> SessionStore:
    """
    Get the global session store instance.
    
    Returns:
        The SessionStore singleton
    """
    global _session_store
    if _session_store is None:
        _session_store = SessionStore()
    return _session_store


def reset_session_store() -> None:
    """Reset the global session store (mainly for testing)."""
    global _session_store
    _session_store = None


__all__ = [
    "SessionStore",
    "SessionStoreError",
    "SessionNotFoundError",
    "get_session_store",
    "reset_session_store",
]
