"""
Swarm Controller - Orquestra múltiplos agentes em paralelo

Coordena a execução de agentes especializados, gerenciando
dependências e compartilhamento de informações.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Type
from datetime import datetime
from enum import Enum
import json

from .shared_memory import SharedMemory, Finding, Severity
from .agents import (
    BaseAgent, AgentResult,
    ReconAgent, WebAgent, NetworkAgent,
    ExploitAgent, PostExploitAgent, PasswordAgent, OSINTAgent
)


class SwarmPhase(Enum):
    """Fases do ataque"""
    RECON = "reconnaissance"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


@dataclass
class SwarmConfig:
    """Configuração do Swarm"""
    max_parallel_agents: int = 5
    timeout_per_phase: int = 600  # 10 minutos por fase
    enable_exploitation: bool = True
    enable_password_attacks: bool = True
    aggressive_mode: bool = False


@dataclass
class SwarmSession:
    """Sessão de um ataque Swarm"""
    id: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    config: SwarmConfig = field(default_factory=SwarmConfig)
    results: Dict[str, AgentResult] = field(default_factory=dict)
    memory: SharedMemory = field(default_factory=SharedMemory)
    status: str = "running"
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status,
            "summary": self.memory.get_summary(),
            "agents_completed": list(self.results.keys())
        }


class SwarmController:
    """
    Controlador do Swarm de agentes.
    
    Orquestra múltiplos agentes trabalhando em paralelo,
    com fases de ataque e compartilhamento de informações.
    """
    
    # Agentes por fase
    PHASE_AGENTS: Dict[SwarmPhase, List[Type[BaseAgent]]] = {
        SwarmPhase.RECON: [ReconAgent, OSINTAgent],
        SwarmPhase.ENUMERATION: [WebAgent, NetworkAgent],
        SwarmPhase.EXPLOITATION: [ExploitAgent, PasswordAgent],
        SwarmPhase.POST_EXPLOITATION: [PostExploitAgent],
    }
    
    def __init__(self, config: SwarmConfig = None):
        self.config = config or SwarmConfig()
        self.sessions: Dict[str, SwarmSession] = {}
        self._session_counter = 0
    
    async def attack(self, target: str, config: SwarmConfig = None) -> SwarmSession:
        """
        Inicia um ataque Swarm completo contra um alvo.
        
        Args:
            target: IP ou domínio do alvo
            config: Configuração opcional
            
        Returns:
            SwarmSession com resultados
        """
        config = config or self.config
        
        # Cria sessão
        self._session_counter += 1
        session = SwarmSession(
            id=f"swarm-{self._session_counter}",
            target=target,
            start_time=datetime.now(),
            config=config,
            memory=SharedMemory()
        )
        self.sessions[session.id] = session
        
        print(f"\n{'='*60}")
        print(f"FRAGMENTUM SWARM - Iniciando ataque")
        print(f"{'='*60}")
        print(f"Target: {target}")
        print(f"Session: {session.id}")
        print(f"{'='*60}\n")
        
        try:
            # Fase 1: Reconhecimento
            print(f"\n[PHASE 1] RECONNAISSANCE")
            print("-" * 40)
            await self._run_phase(session, SwarmPhase.RECON)
            
            # Fase 2: Enumeração
            print(f"\n[PHASE 2] ENUMERATION")
            print("-" * 40)
            await self._run_phase(session, SwarmPhase.ENUMERATION)
            
            # Fase 3: Exploração (se habilitado)
            if config.enable_exploitation:
                print(f"\n[PHASE 3] EXPLOITATION")
                print("-" * 40)
                await self._run_phase(session, SwarmPhase.EXPLOITATION)
            
            # Fase 4: Pós-exploração
            if session.memory.get_shells() or session.memory.get_credentials():
                print(f"\n[PHASE 4] POST-EXPLOITATION")
                print("-" * 40)
                await self._run_phase(session, SwarmPhase.POST_EXPLOITATION)
            
            session.status = "completed"
            
        except Exception as e:
            session.status = f"error: {str(e)}"
            print(f"\n[ERROR] {e}")
        
        finally:
            session.end_time = datetime.now()
        
        # Mostra resumo
        self._print_summary(session)
        
        return session
    
    async def _run_phase(self, session: SwarmSession, phase: SwarmPhase):
        """Executa uma fase do ataque"""
        agent_classes = self.PHASE_AGENTS.get(phase, [])
        
        if not agent_classes:
            return
        
        # Cria instâncias dos agentes
        agents = [cls(session.memory) for cls in agent_classes]
        
        # Executa em paralelo
        tasks = [
            asyncio.create_task(self._run_agent(agent, session.target))
            for agent in agents
        ]
        
        # Aguarda com timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=session.config.timeout_per_phase
            )
            
            # Processa resultados
            for agent, result in zip(agents, results):
                if isinstance(result, Exception):
                    print(f"  [{agent.name}] ERROR: {result}")
                    session.results[agent.name] = AgentResult(
                        agent_name=agent.name,
                        success=False,
                        findings=[],
                        duration=0,
                        errors=[str(result)]
                    )
                else:
                    session.results[agent.name] = result
                    print(f"  [{agent.name}] Completado: {len(result.findings)} descobertas")
                    
        except asyncio.TimeoutError:
            print(f"  [TIMEOUT] Fase {phase.value} excedeu o tempo limite")
    
    async def _run_agent(self, agent: BaseAgent, target: str) -> AgentResult:
        """Executa um agente individual"""
        try:
            return await agent.run(target)
        except Exception as e:
            return AgentResult(
                agent_name=agent.name,
                success=False,
                findings=[],
                duration=0,
                errors=[str(e)]
            )
    
    def _print_summary(self, session: SwarmSession):
        """Imprime resumo do ataque"""
        summary = session.memory.get_summary()
        duration = (session.end_time - session.start_time).total_seconds()
        
        print(f"\n{'='*60}")
        print(f"SWARM ATTACK SUMMARY")
        print(f"{'='*60}")
        print(f"Target: {session.target}")
        print(f"Duration: {duration:.1f}s")
        print(f"Status: {session.status}")
        print(f"\nDiscoveries:")
        print(f"  Ports: {summary['ports']}")
        print(f"  Services: {summary['services']}")
        print(f"  Vulnerabilities: {summary['vulnerabilities']}")
        print(f"  Credentials: {summary['credentials']}")
        print(f"  Shells: {summary['shells']}")
        print(f"\nBy Severity:")
        print(f"  Critical: {summary['by_severity']['critical']}")
        print(f"  High: {summary['by_severity']['high']}")
        print(f"  Medium: {summary['by_severity']['medium']}")
        print(f"  Low: {summary['by_severity']['low']}")
        print(f"  Info: {summary['by_severity']['info']}")
        print(f"{'='*60}\n")
        
        # Mostra descobertas críticas
        critical_findings = [
            f for f in session.memory.get_all_findings()
            if f.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        
        if critical_findings:
            print("CRITICAL/HIGH FINDINGS:")
            print("-" * 40)
            for f in critical_findings:
                print(f"  [{f.severity.value.upper()}] {f.type.value}: {f.value}")
            print()
    
    def get_session(self, session_id: str) -> Optional[SwarmSession]:
        """Retorna uma sessão pelo ID"""
        return self.sessions.get(session_id)
    
    def list_sessions(self) -> List[Dict]:
        """Lista todas as sessões"""
        return [s.to_dict() for s in self.sessions.values()]
    
    def export_session(self, session_id: str) -> str:
        """Exporta sessão para JSON"""
        session = self.sessions.get(session_id)
        if not session:
            return "{}"
        
        return json.dumps({
            "session": session.to_dict(),
            "findings": [f.to_dict() for f in session.memory.get_all_findings()]
        }, indent=2)


# Função de conveniência
async def swarm_attack(target: str, **kwargs) -> SwarmSession:
    """
    Executa um ataque Swarm contra um alvo.
    
    Args:
        target: IP ou domínio do alvo
        **kwargs: Configurações opcionais
        
    Returns:
        SwarmSession com resultados
    """
    config = SwarmConfig(**kwargs)
    controller = SwarmController(config)
    return await controller.attack(target)
