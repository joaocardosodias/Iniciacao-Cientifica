"""
FRAGMENTUM Engine - Motor principal de execução
"""

import time
import asyncio
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass

from .config import Config, get_config
from .session import Session, SessionManager, get_session_manager, Finding


@dataclass
class ExecutionResult:
    """Resultado de uma execução"""
    success: bool
    output: str
    duration: float
    tool: Optional[str] = None
    findings: List[Finding] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []


class FragmentumEngine:
    """
    Motor principal do FRAGMENTUM.
    
    Coordena execução de ferramentas, LLMs e sessões.
    """
    
    def __init__(self, config: Config = None):
        self.config = config or get_config()
        self.session_manager = get_session_manager()
        self._tools = {}
        self._llm = None
        self._initialized = False
        
        # Cria sessão padrão
        self.session = self.session_manager.create(
            name="default",
            target=self.config.target
        )
    
    async def initialize(self):
        """Inicializa o engine"""
        if self._initialized:
            return
        
        # Carrega ferramentas
        from fragmentum.tools import get_tool_registry
        self._tools = get_tool_registry()
        
        # Inicializa LLM
        # TODO: Implementar multi-LLM
        
        self._initialized = True
    
    def create_session(self, name: str = "", target: str = None, objective: str = "") -> Session:
        """Cria nova sessão de pentest"""
        session = self.session_manager.create(
            name=name,
            target=target or self.config.target,
            objective=objective
        )
        return session
    
    async def execute_tool(
        self, 
        tool_name: str, 
        target: str = None,
        options: Dict[str, Any] = None,
        timeout: int = None
    ) -> ExecutionResult:
        """
        Executa uma ferramenta de segurança.
        
        Args:
            tool_name: Nome da ferramenta (nmap, gobuster, etc)
            target: Alvo (IP, URL, etc)
            options: Opções específicas da ferramenta
            timeout: Timeout em segundos
            
        Returns:
            ExecutionResult com output e status
        """
        start_time = time.time()
        
        try:
            # Obtém ferramenta do registry
            if tool_name not in self._tools:
                return ExecutionResult(
                    success=False,
                    output=f"Ferramenta não encontrada: {tool_name}",
                    duration=0
                )
            
            tool = self._tools[tool_name]
            
            # Executa
            output, success = await tool.execute(
                target=target or self.config.target,
                options=options or {},
                timeout=timeout or self.config.default_timeout
            )
            
            duration = time.time() - start_time
            
            # Analisa output para findings
            findings = await self._analyze_output(tool_name, output)
            
            # Log na sessão atual
            if session := self.session_manager.current_session:
                session.log_command(
                    command=tool.build_command(target, options),
                    output=output,
                    success=success,
                    duration=duration,
                    tool=tool_name
                )
                for finding in findings:
                    session.add_finding(finding)
            
            return ExecutionResult(
                success=success,
                output=output,
                duration=duration,
                tool=tool_name,
                findings=findings
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return ExecutionResult(
                success=False,
                output=f"Erro: {str(e)}",
                duration=duration,
                tool=tool_name
            )
    
    async def execute_exploit(
        self,
        exploit_name: str,
        target: str,
        options: Dict[str, Any] = None,
        interactive: bool = True
    ) -> ExecutionResult:
        """
        Executa um exploit via Metasploit.
        
        Args:
            exploit_name: Nome do exploit (vsftpd, samba, etc)
            target: IP do alvo
            options: Opções do exploit
            interactive: Se deve abrir shell interativa
            
        Returns:
            ExecutionResult
        """
        from fragmentum.tools.exploits import execute_exploit
        
        start_time = time.time()
        
        output, success = await execute_exploit(
            exploit_name=exploit_name,
            target=target,
            options=options or {},
            interactive=interactive
        )
        
        duration = time.time() - start_time
        
        # Se obteve shell, registra finding
        findings = []
        if success and "SHELL_SESSION_COMPLETED" in output:
            findings.append(Finding(
                type="shell",
                severity="critical",
                title=f"Shell obtida via {exploit_name}",
                description=f"Acesso root obtido no alvo {target}",
                target=target,
                evidence=output[:500]
            ))
        
        return ExecutionResult(
            success=success,
            output=output,
            duration=duration,
            tool=f"msf:{exploit_name}",
            findings=findings
        )
    
    async def run_autonomous(
        self,
        objective: str,
        target: str = None,
        max_steps: int = None
    ) -> Session:
        """
        Executa pentest autônomo.
        
        Args:
            objective: Objetivo do pentest
            target: Alvo
            max_steps: Máximo de passos
            
        Returns:
            Session com resultados
        """
        target = target or self.config.target
        max_steps = max_steps or self.config.max_loops
        
        # Cria sessão
        session = self.create_session(
            name=f"Auto-{objective[:20]}",
            target=target,
            objective=objective
        )
        session.start()
        
        try:
            # Pipeline de 3 estágios
            from fragmentum.ai.sanitizer import sanitize_intent
            from fragmentum.ai.planner import get_next_step
            from fragmentum.ai.commander import generate_command
            
            # Estágio 1: Sanitização
            clean_goal = await sanitize_intent(objective, target)
            
            history = ""
            
            for step_num in range(1, max_steps + 1):
                # Estágio 2: Planejamento
                next_step = await get_next_step(clean_goal, history)
                
                if "TERMINADO" in next_step.upper():
                    break
                
                # Estágio 3: Geração de comando
                command = await generate_command(next_step, target)
                
                # Executa
                result = await self._execute_command(command, target)
                
                # Atualiza histórico
                status = "SUCCESS" if result.success else "FAILED"
                history += f"\nStep {step_num}: {next_step}\n"
                history += f"Command: {command}\n"
                history += f"Result: {status} - {result.output[:500]}\n"
                
                # Verifica se objetivo foi alcançado
                if self._check_objective_achieved(result.output, objective):
                    history += "\n*** OBJETIVO ALCANÇADO ***\n"
                    break
            
            session.complete(success=True)
            
        except Exception as e:
            session.complete(success=False)
            session.metadata["error"] = str(e)
        
        return session
    
    async def _execute_command(self, command: str, target: str) -> ExecutionResult:
        """Executa comando detectando tipo automaticamente"""
        from fragmentum.tools.executor import smart_execute
        
        start_time = time.time()
        output, success = await smart_execute(command, target)
        duration = time.time() - start_time
        
        return ExecutionResult(
            success=success,
            output=output,
            duration=duration
        )
    
    async def _analyze_output(self, tool: str, output: str) -> List[Finding]:
        """Analisa output para extrair findings"""
        findings = []
        output_lower = output.lower()
        
        # Detecção básica de vulnerabilidades
        vuln_patterns = {
            "critical": ["root access", "shell opened", "uid=0", "meterpreter"],
            "high": ["password found", "valid password", "sql injection", "rce"],
            "medium": ["directory listing", "information disclosure", "xss"],
            "low": ["version disclosure", "banner grab"],
        }
        
        for severity, patterns in vuln_patterns.items():
            for pattern in patterns:
                if pattern in output_lower:
                    findings.append(Finding(
                        type="vulnerability",
                        severity=severity,
                        title=f"Possível {pattern}",
                        description=f"Detectado via {tool}",
                        evidence=output[:200]
                    ))
                    break
        
        return findings
    
    def _check_objective_achieved(self, output: str, objective: str) -> bool:
        """Verifica se objetivo foi alcançado"""
        output_lower = output.lower()
        objective_lower = objective.lower()
        
        # Padrões de sucesso por tipo de objetivo
        if any(w in objective_lower for w in ["shell", "acesso", "exploit"]):
            return any(p in output_lower for p in ["session opened", "shell", "uid=0"])
        
        if any(w in objective_lower for w in ["scan", "portas", "recon"]):
            return "open" in output_lower and "tcp" in output_lower
        
        if any(w in objective_lower for w in ["credencial", "senha", "password"]):
            return any(p in output_lower for p in ["password", "credential", "root:x:"])
        
        return False
    
    def get_status(self) -> Dict:
        """Retorna status do engine"""
        return {
            "initialized": self._initialized,
            "tools_loaded": len(self._tools),
            "active_sessions": len(self.session_manager.list_active()),
            "total_sessions": len(self.session_manager.sessions),
            "config": self.config.to_dict()
        }


# Instância global
_engine: Optional[FragmentumEngine] = None


def get_engine() -> FragmentumEngine:
    """Retorna engine global"""
    global _engine
    if _engine is None:
        _engine = FragmentumEngine()
    return _engine
