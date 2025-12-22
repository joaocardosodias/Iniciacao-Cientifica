"""
PTY Executor - Rubber Ducky Style Terminal Automation

Este módulo cria pseudo-terminais e simula digitação como um rubber ducky,
permitindo interação com programas interativos como msfconsole, ftp, ssh, etc.
"""

import pexpect
import time
import re
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


class SessionType(Enum):
    """Tipos de sessão PTY suportados."""
    BASH = "bash"
    MSFCONSOLE = "msfconsole"
    FTP = "ftp"
    SSH = "ssh"
    TELNET = "telnet"
    NETCAT = "nc"
    CUSTOM = "custom"


@dataclass
class PTYSession:
    """Representa uma sessão PTY ativa."""
    id: int
    session_type: SessionType
    process: pexpect.spawn
    command: str
    created_at: float = field(default_factory=time.time)
    last_output: str = ""
    
    def is_alive(self) -> bool:
        """Verifica se o processo ainda está rodando."""
        return self.process.isalive()


class PTYExecutor:
    """
    Executor PTY estilo Rubber Ducky.
    
    Cria pseudo-terminais e envia comandos como se fossem digitados,
    permitindo interação com programas interativos.
    """
    
    def __init__(self):
        self.sessions: Dict[int, PTYSession] = {}
        self._next_id = 1
        self._default_timeout = 30
        
        # Prompts conhecidos para diferentes programas
        self.prompts = {
            SessionType.BASH: [r'\$\s*$', r'#\s*$', r'>\s*$'],
            SessionType.MSFCONSOLE: [r'msf.*>\s*$', r'msf\d?\s*>\s*$', r'msf\d?\s+\w+\([^)]+\)\s*>\s*$'],
            SessionType.FTP: [r'ftp>\s*$', r'Name.*:\s*$', r'Password:\s*$'],
            SessionType.SSH: [r'\$\s*$', r'#\s*$', r'password:\s*$', r'Password:\s*$'],
            SessionType.TELNET: [r'login:\s*$', r'Password:\s*$', r'\$\s*$', r'#\s*$'],
            SessionType.NETCAT: [r'.*'],  # Netcat não tem prompt específico
        }
    
    def spawn_session(
        self, 
        command: str, 
        session_type: SessionType = SessionType.CUSTOM,
        timeout: int = None,
        env: dict = None
    ) -> int:
        """
        Cria uma nova sessão PTY.
        
        Args:
            command: Comando para iniciar (ex: "msfconsole", "ftp 172.20.0.6")
            session_type: Tipo de sessão para determinar prompts
            timeout: Timeout padrão para operações
            env: Variáveis de ambiente adicionais
            
        Returns:
            ID da sessão criada
        """
        timeout = timeout or self._default_timeout
        
        # Detecta tipo de sessão automaticamente se não especificado
        if session_type == SessionType.CUSTOM:
            session_type = self._detect_session_type(command)
        
        # Configura ambiente
        spawn_env = {"TERM": "dumb", "COLUMNS": "200", "LINES": "50"}
        if env:
            spawn_env.update(env)
        
        # Cria o processo PTY
        process = pexpect.spawn(
            command,
            timeout=timeout,
            encoding='utf-8',
            env=spawn_env,
            maxread=65536
        )
        
        # Aguarda o prompt inicial
        try:
            self._wait_for_prompt(process, session_type, timeout=timeout)
        except pexpect.TIMEOUT:
            # Alguns programas demoram para iniciar
            pass
        
        # Registra a sessão
        session_id = self._next_id
        self._next_id += 1
        
        session = PTYSession(
            id=session_id,
            session_type=session_type,
            process=process,
            command=command,
            last_output=process.before if process.before else ""
        )
        
        self.sessions[session_id] = session
        return session_id
    
    def send_keys(
        self, 
        session_id: int, 
        text: str, 
        delay: float = 0.05,
        press_enter: bool = True
    ) -> str:
        """
        Envia texto para a sessão como se fosse digitado (rubber ducky style).
        
        Args:
            session_id: ID da sessão
            text: Texto a ser "digitado"
            delay: Delay entre caracteres (simula digitação humana)
            press_enter: Se deve pressionar Enter após o texto
            
        Returns:
            Output capturado após o comando
        """
        session = self._get_session(session_id)
        
        # Simula digitação caractere por caractere
        for char in text:
            session.process.send(char)
            if delay > 0:
                time.sleep(delay)
        
        if press_enter:
            session.process.sendline('')
        
        # Aguarda resposta
        try:
            self._wait_for_prompt(session.process, session.session_type)
            output = session.process.before or ""
        except pexpect.TIMEOUT:
            output = session.process.before or ""
        
        session.last_output = output
        return self._clean_output(output, text)
    
    def send_command(
        self, 
        session_id: int, 
        command: str, 
        timeout: int = None,
        expect_pattern: str = None
    ) -> tuple[str, bool]:
        """
        Envia um comando e aguarda resposta.
        
        Args:
            session_id: ID da sessão
            command: Comando a enviar
            timeout: Timeout específico para este comando
            expect_pattern: Padrão regex para aguardar (opcional)
            
        Returns:
            Tupla (output, success)
        """
        session = self._get_session(session_id)
        timeout = timeout or self._default_timeout
        
        # Envia o comando
        session.process.sendline(command)
        
        try:
            if expect_pattern:
                session.process.expect(expect_pattern, timeout=timeout)
            else:
                self._wait_for_prompt(session.process, session.session_type, timeout)
            
            output = session.process.before or ""
            session.last_output = output
            return self._clean_output(output, command), True
            
        except pexpect.TIMEOUT:
            output = session.process.before or ""
            session.last_output = output
            return self._clean_output(output, command) + "\n[TIMEOUT]", False
            
        except pexpect.EOF:
            output = session.process.before or ""
            session.last_output = output
            return self._clean_output(output, command) + "\n[SESSION CLOSED]", False
    
    def send_special_key(self, session_id: int, key: str) -> None:
        """
        Envia tecla especial para a sessão.
        
        Args:
            session_id: ID da sessão
            key: Nome da tecla (ctrl_c, ctrl_d, ctrl_z, tab, etc.)
        """
        session = self._get_session(session_id)
        
        special_keys = {
            'ctrl_c': '\x03',
            'ctrl_d': '\x04',
            'ctrl_z': '\x1a',
            'ctrl_l': '\x0c',
            'tab': '\t',
            'escape': '\x1b',
            'enter': '\r\n',
            'up': '\x1b[A',
            'down': '\x1b[B',
            'left': '\x1b[D',
            'right': '\x1b[C',
        }
        
        if key.lower() in special_keys:
            session.process.send(special_keys[key.lower()])
        else:
            raise ValueError(f"Tecla especial desconhecida: {key}")
    
    def read_output(self, session_id: int, timeout: float = 1.0) -> str:
        """
        Lê output disponível da sessão sem enviar comandos.
        
        Args:
            session_id: ID da sessão
            timeout: Tempo máximo para aguardar output
            
        Returns:
            Output disponível
        """
        session = self._get_session(session_id)
        
        try:
            session.process.expect(r'.+', timeout=timeout)
            output = session.process.match.group(0)
        except pexpect.TIMEOUT:
            output = ""
        except pexpect.EOF:
            output = "[SESSION CLOSED]"
        
        return output
    
    def interact(self, session_id: int) -> None:
        """
        Entra em modo interativo com a sessão (para debug).
        Ctrl+] para sair.
        """
        session = self._get_session(session_id)
        print(f"\n[*] Entrando em modo interativo (Ctrl+] para sair)")
        session.process.interact()
    
    def close_session(self, session_id: int, graceful: bool = True) -> bool:
        """
        Fecha uma sessão PTY.
        
        Args:
            session_id: ID da sessão
            graceful: Se True, tenta fechar graciosamente primeiro
            
        Returns:
            True se fechou com sucesso
        """
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        if graceful and session.is_alive():
            # Tenta fechar graciosamente baseado no tipo
            try:
                if session.session_type == SessionType.MSFCONSOLE:
                    session.process.sendline('exit')
                elif session.session_type == SessionType.FTP:
                    session.process.sendline('bye')
                elif session.session_type in [SessionType.SSH, SessionType.TELNET]:
                    session.process.sendline('exit')
                else:
                    session.process.sendline('exit')
                
                time.sleep(0.5)
            except:
                pass
        
        # Força fechamento se ainda estiver vivo
        if session.is_alive():
            session.process.terminate(force=True)
        
        del self.sessions[session_id]
        return True
    
    def close_all(self) -> None:
        """Fecha todas as sessões ativas."""
        for session_id in list(self.sessions.keys()):
            self.close_session(session_id)
    
    def list_sessions(self) -> list[dict]:
        """Lista todas as sessões ativas."""
        result = []
        for sid, session in self.sessions.items():
            result.append({
                'id': sid,
                'type': session.session_type.value,
                'command': session.command,
                'alive': session.is_alive(),
                'created': session.created_at
            })
        return result
    
    def get_session_info(self, session_id: int) -> Optional[dict]:
        """Retorna informações sobre uma sessão."""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        return {
            'id': session.id,
            'type': session.session_type.value,
            'command': session.command,
            'alive': session.is_alive(),
            'created': session.created_at,
            'last_output': session.last_output[-500:] if session.last_output else ""
        }
    
    # === Métodos auxiliares ===
    
    def _get_session(self, session_id: int) -> PTYSession:
        """Obtém sessão ou levanta exceção."""
        if session_id not in self.sessions:
            raise ValueError(f"Sessão não encontrada: {session_id}")
        return self.sessions[session_id]
    
    def _detect_session_type(self, command: str) -> SessionType:
        """Detecta o tipo de sessão baseado no comando."""
        cmd_lower = command.lower().split()[0] if command else ""
        
        type_map = {
            'msfconsole': SessionType.MSFCONSOLE,
            'ftp': SessionType.FTP,
            'ssh': SessionType.SSH,
            'telnet': SessionType.TELNET,
            'nc': SessionType.NETCAT,
            'netcat': SessionType.NETCAT,
            'bash': SessionType.BASH,
            'sh': SessionType.BASH,
            'zsh': SessionType.BASH,
        }
        
        return type_map.get(cmd_lower, SessionType.CUSTOM)
    
    def _wait_for_prompt(
        self, 
        process: pexpect.spawn, 
        session_type: SessionType,
        timeout: int = None
    ) -> None:
        """Aguarda o prompt do programa."""
        timeout = timeout or self._default_timeout
        patterns = self.prompts.get(session_type, [r'.*'])
        
        # Adiciona padrões genéricos
        patterns = patterns + [pexpect.TIMEOUT, pexpect.EOF]
        
        process.expect(patterns, timeout=timeout)
    
    def _clean_output(self, output: str, command: str = "") -> str:
        """Limpa o output removendo escape sequences e o comando ecoado."""
        # Remove ANSI escape sequences
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)
        
        # Remove o comando ecoado (primeira linha geralmente)
        if command and output.startswith(command):
            output = output[len(command):].lstrip('\r\n')
        
        # Remove linhas vazias extras
        lines = [l for l in output.split('\n') if l.strip()]
        return '\n'.join(lines)


# === Funções de conveniência ===

_executor: Optional[PTYExecutor] = None


def get_executor() -> PTYExecutor:
    """Retorna a instância global do executor."""
    global _executor
    if _executor is None:
        _executor = PTYExecutor()
    return _executor


def spawn_msfconsole(timeout: int = 60) -> int:
    """Inicia uma sessão msfconsole."""
    executor = get_executor()
    return executor.spawn_session(
        "msfconsole -q",
        session_type=SessionType.MSFCONSOLE,
        timeout=timeout,
        env={"TERM": "dumb"}
    )


def spawn_ftp(target: str, timeout: int = 30) -> int:
    """Inicia uma sessão FTP."""
    executor = get_executor()
    return executor.spawn_session(
        f"ftp {target}",
        session_type=SessionType.FTP,
        timeout=timeout
    )


def spawn_ssh(target: str, user: str = None, timeout: int = 30) -> int:
    """Inicia uma sessão SSH."""
    executor = get_executor()
    cmd = f"ssh {user}@{target}" if user else f"ssh {target}"
    return executor.spawn_session(
        cmd,
        session_type=SessionType.SSH,
        timeout=timeout
    )


def spawn_telnet(target: str, port: int = 23, timeout: int = 30) -> int:
    """Inicia uma sessão Telnet."""
    executor = get_executor()
    return executor.spawn_session(
        f"telnet {target} {port}",
        session_type=SessionType.TELNET,
        timeout=timeout
    )


def execute_in_session(session_id: int, command: str, timeout: int = 30) -> tuple[str, bool]:
    """Executa comando em uma sessão existente."""
    executor = get_executor()
    return executor.send_command(session_id, command, timeout=timeout)


def close_session(session_id: int) -> bool:
    """Fecha uma sessão."""
    executor = get_executor()
    return executor.close_session(session_id)


def list_sessions() -> list[dict]:
    """Lista sessões ativas."""
    executor = get_executor()
    return executor.list_sessions()


# === Exemplo de uso ===

if __name__ == "__main__":
    print("=== PTY Executor Demo ===\n")
    
    executor = PTYExecutor()
    
    # Exemplo 1: Bash simples
    print("[*] Criando sessão bash...")
    bash_id = executor.spawn_session("bash", session_type=SessionType.BASH)
    
    print("[*] Executando 'whoami'...")
    output, success = executor.send_command(bash_id, "whoami")
    print(f"    Output: {output}")
    print(f"    Success: {success}")
    
    print("[*] Executando 'pwd'...")
    output, success = executor.send_command(bash_id, "pwd")
    print(f"    Output: {output}")
    
    print("[*] Listando sessões:")
    for s in executor.list_sessions():
        print(f"    Session {s['id']}: {s['type']} - {'alive' if s['alive'] else 'dead'}")
    
    print("[*] Fechando sessão...")
    executor.close_session(bash_id)
    
    print("\n[+] Demo concluída!")
