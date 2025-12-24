"""
Shared Memory - Memória compartilhada entre agentes

Permite que agentes compartilhem descobertas em tempo real.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from enum import Enum
import json


class FindingType(Enum):
    """Tipos de descobertas"""
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    SHELL = "shell"
    FILE = "file"
    USER = "user"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    TECHNOLOGY = "technology"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    INFO = "info"


class Severity(Enum):
    """Severidade das descobertas"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Uma descoberta feita por um agente"""
    type: FindingType
    value: Any
    source: str  # Nome do agente que descobriu
    target: str
    severity: Severity = Severity.INFO
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type.value,
            "value": self.value,
            "source": self.source,
            "target": self.target,
            "severity": self.severity.value,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }


class SharedMemory:
    """
    Memória compartilhada entre agentes.
    
    Permite:
    - Adicionar descobertas
    - Consultar descobertas por tipo/agente
    - Notificar agentes sobre novas descobertas
    - Evitar trabalho duplicado
    """
    
    def __init__(self):
        self._findings: List[Finding] = []
        self._ports: Dict[str, Set[int]] = {}  # target -> ports
        self._services: Dict[str, Dict[int, str]] = {}  # target -> {port: service}
        self._vulns: List[Finding] = []
        self._credentials: List[Finding] = []
        self._shells: List[Finding] = []
        self._lock = asyncio.Lock()
        self._subscribers: List[asyncio.Queue] = []
        
        # Controle de tarefas já executadas
        self._completed_tasks: Set[str] = set()
    
    async def add_finding(self, finding: Finding) -> bool:
        """Adiciona uma descoberta à memória compartilhada"""
        async with self._lock:
            # Verifica duplicata
            for f in self._findings:
                if f.type == finding.type and f.value == finding.value and f.target == finding.target:
                    return False
            
            self._findings.append(finding)
            
            # Indexa por tipo
            if finding.type == FindingType.PORT:
                if finding.target not in self._ports:
                    self._ports[finding.target] = set()
                self._ports[finding.target].add(finding.value)
            
            elif finding.type == FindingType.SERVICE:
                if finding.target not in self._services:
                    self._services[finding.target] = {}
                port = finding.details.get("port", 0)
                self._services[finding.target][port] = finding.value
            
            elif finding.type == FindingType.VULNERABILITY:
                self._vulns.append(finding)
            
            elif finding.type == FindingType.CREDENTIAL:
                self._credentials.append(finding)
            
            elif finding.type == FindingType.SHELL:
                self._shells.append(finding)
            
            # Notifica subscribers
            for queue in self._subscribers:
                await queue.put(finding)
            
            return True
    
    def subscribe(self) -> asyncio.Queue:
        """Inscreve-se para receber notificações de novas descobertas"""
        queue = asyncio.Queue()
        self._subscribers.append(queue)
        return queue
    
    def unsubscribe(self, queue: asyncio.Queue):
        """Remove inscrição"""
        if queue in self._subscribers:
            self._subscribers.remove(queue)
    
    def get_ports(self, target: str) -> Set[int]:
        """Retorna portas descobertas para um alvo"""
        return self._ports.get(target, set())
    
    def get_services(self, target: str) -> Dict[int, str]:
        """Retorna serviços descobertos para um alvo"""
        return self._services.get(target, {})
    
    def get_vulns(self, target: str = None) -> List[Finding]:
        """Retorna vulnerabilidades descobertas"""
        if target:
            return [v for v in self._vulns if v.target == target]
        return self._vulns
    
    def get_credentials(self) -> List[Finding]:
        """Retorna credenciais descobertas"""
        return self._credentials
    
    def get_shells(self) -> List[Finding]:
        """Retorna shells obtidas"""
        return self._shells
    
    def get_findings_by_type(self, finding_type: FindingType) -> List[Finding]:
        """Retorna descobertas por tipo"""
        return [f for f in self._findings if f.type == finding_type]
    
    def get_findings_by_agent(self, agent_name: str) -> List[Finding]:
        """Retorna descobertas por agente"""
        return [f for f in self._findings if f.source == agent_name]
    
    def get_all_findings(self) -> List[Finding]:
        """Retorna todas as descobertas"""
        return self._findings
    
    async def mark_task_completed(self, task_id: str):
        """Marca uma tarefa como completada"""
        async with self._lock:
            self._completed_tasks.add(task_id)
    
    def is_task_completed(self, task_id: str) -> bool:
        """Verifica se uma tarefa já foi completada"""
        return task_id in self._completed_tasks
    
    def get_summary(self) -> Dict:
        """Retorna resumo das descobertas"""
        return {
            "total_findings": len(self._findings),
            "ports": sum(len(p) for p in self._ports.values()),
            "services": sum(len(s) for s in self._services.values()),
            "vulnerabilities": len(self._vulns),
            "credentials": len(self._credentials),
            "shells": len(self._shells),
            "by_severity": {
                "critical": len([f for f in self._findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self._findings if f.severity == Severity.HIGH]),
                "medium": len([f for f in self._findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self._findings if f.severity == Severity.LOW]),
                "info": len([f for f in self._findings if f.severity == Severity.INFO])
            }
        }
    
    def to_json(self) -> str:
        """Exporta memória para JSON"""
        return json.dumps({
            "findings": [f.to_dict() for f in self._findings],
            "summary": self.get_summary()
        }, indent=2)
