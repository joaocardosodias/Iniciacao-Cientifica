"""
Gerenciamento de sessões de pentest
"""

import uuid
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from enum import Enum
from datetime import datetime


class SessionStatus(Enum):
    """Status da sessão"""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Finding:
    """Achado durante o pentest"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: str = ""  # vuln, credential, service, etc
    severity: str = "info"  # critical, high, medium, low, info
    title: str = ""
    description: str = ""
    evidence: str = ""
    target: str = ""
    port: Optional[int] = None
    service: Optional[str] = None
    cve: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class CommandLog:
    """Log de comando executado"""
    command: str
    output: str
    success: bool
    duration: float
    timestamp: float = field(default_factory=time.time)
    tool: Optional[str] = None


@dataclass 
class Session:
    """Sessão de pentest"""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    target: Optional[str] = None
    status: SessionStatus = SessionStatus.IDLE
    
    # Timestamps
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    
    # Objetivo
    objective: str = ""
    scenario_id: Optional[str] = None
    
    # Resultados
    findings: List[Finding] = field(default_factory=list)
    command_log: List[CommandLog] = field(default_factory=list)
    
    # Shells ativas
    active_shells: Dict[str, Any] = field(default_factory=dict)
    
    # Metadados
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def session_id(self) -> str:
        """Alias para id (compatibilidade)"""
        return self.id
    
    def start(self):
        """Inicia a sessão"""
        self.status = SessionStatus.RUNNING
        self.started_at = time.time()
    
    def pause(self):
        """Pausa a sessão"""
        self.status = SessionStatus.PAUSED
    
    def resume(self):
        """Retoma a sessão"""
        self.status = SessionStatus.RUNNING
    
    def complete(self, success: bool = True):
        """Finaliza a sessão"""
        self.status = SessionStatus.COMPLETED if success else SessionStatus.FAILED
        self.finished_at = time.time()
    
    def add_finding(self, finding: Finding):
        """Adiciona um achado"""
        self.findings.append(finding)
    
    def log_command(self, command: str, output: str, success: bool, duration: float, tool: str = None):
        """Registra comando executado"""
        self.command_log.append(CommandLog(
            command=command,
            output=output,
            success=success,
            duration=duration,
            tool=tool
        ))
    
    def add_shell(self, shell_id: str, shell_info: Dict):
        """Registra shell ativa"""
        self.active_shells[shell_id] = shell_info
    
    def remove_shell(self, shell_id: str):
        """Remove shell"""
        self.active_shells.pop(shell_id, None)
    
    @property
    def duration(self) -> Optional[float]:
        """Duração da sessão em segundos"""
        if self.started_at is None:
            return None
        end = self.finished_at or time.time()
        return end - self.started_at
    
    @property
    def critical_findings(self) -> List[Finding]:
        """Achados críticos"""
        return [f for f in self.findings if f.severity == "critical"]
    
    @property
    def high_findings(self) -> List[Finding]:
        """Achados de alta severidade"""
        return [f for f in self.findings if f.severity == "high"]
    
    def to_dict(self) -> Dict:
        """Converte para dicionário"""
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "status": self.status.value,
            "objective": self.objective,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "findings_count": len(self.findings),
            "critical_count": len(self.critical_findings),
            "commands_count": len(self.command_log),
            "active_shells": len(self.active_shells),
        }


class SessionManager:
    """Gerenciador de sessões"""
    
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.current_session: Optional[Session] = None
    
    def create(self, name: str = "", target: str = None, objective: str = "") -> Session:
        """Cria nova sessão"""
        session = Session(
            name=name or f"Session-{len(self.sessions) + 1}",
            target=target,
            objective=objective
        )
        self.sessions[session.id] = session
        self.current_session = session
        return session
    
    def get(self, session_id: str) -> Optional[Session]:
        """Obtém sessão por ID"""
        return self.sessions.get(session_id)
    
    def list_all(self) -> List[Session]:
        """Lista todas as sessões"""
        return list(self.sessions.values())
    
    def list_active(self) -> List[Session]:
        """Lista sessões ativas"""
        return [s for s in self.sessions.values() if s.status == SessionStatus.RUNNING]
    
    def set_current(self, session_id: str) -> bool:
        """Define sessão atual"""
        if session := self.sessions.get(session_id):
            self.current_session = session
            return True
        return False
    
    def delete(self, session_id: str) -> bool:
        """Remove sessão"""
        if session_id in self.sessions:
            if self.current_session and self.current_session.id == session_id:
                self.current_session = None
            del self.sessions[session_id]
            return True
        return False


# Instância global
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Retorna gerenciador de sessões global"""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
