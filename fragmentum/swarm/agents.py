"""
Agentes especializados para pentesting

Cada agente tem uma especialidade e trabalha em paralelo com os outros.
"""

import asyncio
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from .shared_memory import SharedMemory, Finding, FindingType, Severity


@dataclass
class AgentResult:
    """Resultado de execução de um agente"""
    agent_name: str
    success: bool
    findings: List[Finding]
    duration: float
    errors: List[str]


class BaseAgent(ABC):
    """Agente base para pentesting"""
    
    name: str = "base"
    description: str = "Base agent"
    
    def __init__(self, memory: SharedMemory):
        self.memory = memory
        self.findings: List[Finding] = []
        self.errors: List[str] = []
        self._running = False
        self._start_time: Optional[datetime] = None
    
    @abstractmethod
    async def run(self, target: str, **kwargs) -> AgentResult:
        """Executa o agente"""
        pass
    
    async def execute_tool(self, command: str, timeout: int = 180) -> tuple[str, bool]:
        """Executa uma ferramenta"""
        from fragmentum.tools.executor import execute_command
        return await execute_command(command, timeout)
    
    async def add_finding(self, finding: Finding) -> bool:
        """Adiciona descoberta à memória compartilhada"""
        self.findings.append(finding)
        return await self.memory.add_finding(finding)
    
    def log(self, message: str):
        """Log do agente"""
        print(f"[{self.name}] {message}")


class ReconAgent(BaseAgent):
    """Agente de reconhecimento - Descobre portas e serviços"""
    
    name = "recon"
    description = "Reconnaissance agent - port scanning and service detection"
    
    async def run(self, target: str, **kwargs) -> AgentResult:
        self._start_time = datetime.now()
        self._running = True
        self.log(f"Iniciando reconhecimento em {target}")
        
        try:
            # Scan rápido de portas
            self.log("Executando scan de portas...")
            output, success = await self.execute_tool(
                f"nmap -T4 -F --open {target}",
                timeout=120
            )
            
            if success:
                await self._parse_nmap_output(output, target)
            
            # Scan com detecção de versão nas portas encontradas
            ports = self.memory.get_ports(target)
            if ports:
                ports_str = ",".join(str(p) for p in sorted(ports))
                self.log(f"Detectando versões nas portas: {ports_str}")
                
                output, success = await self.execute_tool(
                    f"nmap -sV -sC -p {ports_str} {target}",
                    timeout=180
                )
                
                if success:
                    await self._parse_nmap_services(output, target)
            
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=True,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
            
        except Exception as e:
            self.errors.append(str(e))
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=False,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
        finally:
            self._running = False
    
    async def _parse_nmap_output(self, output: str, target: str):
        """Parse output do nmap para extrair portas"""
        port_pattern = r"(\d+)/tcp\s+open"
        for match in re.finditer(port_pattern, output):
            port = int(match.group(1))
            await self.add_finding(Finding(
                type=FindingType.PORT,
                value=port,
                source=self.name,
                target=target,
                severity=Severity.INFO,
                details={"protocol": "tcp"}
            ))
    
    async def _parse_nmap_services(self, output: str, target: str):
        """Parse output do nmap para extrair serviços"""
        service_pattern = r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)"
        for match in re.finditer(service_pattern, output):
            port = int(match.group(1))
            service = match.group(2)
            version = match.group(3).strip() if match.group(3) else ""
            
            await self.add_finding(Finding(
                type=FindingType.SERVICE,
                value=service,
                source=self.name,
                target=target,
                severity=Severity.INFO,
                details={"port": port, "version": version}
            ))


class WebAgent(BaseAgent):
    """Agente web - Testa vulnerabilidades web"""
    
    name = "web"
    description = "Web agent - web vulnerability scanning"
    
    async def run(self, target: str, **kwargs) -> AgentResult:
        self._start_time = datetime.now()
        self._running = True
        self.log(f"Iniciando análise web em {target}")
        
        try:
            # Verifica se tem serviço web
            services = self.memory.get_services(target)
            web_ports = [p for p, s in services.items() if 'http' in s.lower()]
            
            if not web_ports:
                # Tenta portas padrão
                web_ports = [80, 443, 8080, 8443]
            
            for port in web_ports:
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{target}:{port}"
                
                # WhatWeb - Identifica tecnologias
                self.log(f"Identificando tecnologias em {url}")
                output, success = await self.execute_tool(
                    f"whatweb {url}",
                    timeout=60
                )
                if success:
                    await self._parse_whatweb(output, target, port)
                
                # Gobuster - Diretórios
                self.log(f"Buscando diretórios em {url}")
                output, success = await self.execute_tool(
                    f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -t 20 -q",
                    timeout=180
                )
                if success:
                    await self._parse_gobuster(output, target, port)
                
                # Nikto - Vulnerabilidades
                self.log(f"Scan de vulnerabilidades em {url}")
                output, success = await self.execute_tool(
                    f"nikto -h {url} -Tuning 123bde -maxtime 120",
                    timeout=180
                )
                if success:
                    await self._parse_nikto(output, target, port)
            
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=True,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
            
        except Exception as e:
            self.errors.append(str(e))
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=False,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
        finally:
            self._running = False
    
    async def _parse_whatweb(self, output: str, target: str, port: int):
        """Parse output do whatweb"""
        # Extrai tecnologias
        tech_pattern = r"\[([^\]]+)\]"
        for match in re.finditer(tech_pattern, output):
            tech = match.group(1)
            if tech and not tech.startswith("200") and not tech.startswith("30"):
                await self.add_finding(Finding(
                    type=FindingType.TECHNOLOGY,
                    value=tech,
                    source=self.name,
                    target=target,
                    severity=Severity.INFO,
                    details={"port": port}
                ))
    
    async def _parse_gobuster(self, output: str, target: str, port: int):
        """Parse output do gobuster"""
        endpoint_pattern = r"(/\S+)\s+\(Status:\s*(\d+)\)"
        for match in re.finditer(endpoint_pattern, output):
            endpoint = match.group(1)
            status = match.group(2)
            await self.add_finding(Finding(
                type=FindingType.ENDPOINT,
                value=endpoint,
                source=self.name,
                target=target,
                severity=Severity.LOW,
                details={"port": port, "status": status}
            ))
    
    async def _parse_nikto(self, output: str, target: str, port: int):
        """Parse output do nikto"""
        vuln_pattern = r"\+ (OSVDB-\d+|CVE-\d+-\d+):\s*(.*)"
        for match in re.finditer(vuln_pattern, output):
            vuln_id = match.group(1)
            description = match.group(2)
            await self.add_finding(Finding(
                type=FindingType.VULNERABILITY,
                value=vuln_id,
                source=self.name,
                target=target,
                severity=Severity.MEDIUM,
                details={"port": port, "description": description}
            ))


class NetworkAgent(BaseAgent):
    """Agente de rede - Testa serviços de rede"""
    
    name = "network"
    description = "Network agent - network service testing"
    
    async def run(self, target: str, **kwargs) -> AgentResult:
        self._start_time = datetime.now()
        self._running = True
        self.log(f"Iniciando análise de rede em {target}")
        
        try:
            services = self.memory.get_services(target)
            
            # SMB
            if any('smb' in s.lower() or 'microsoft-ds' in s.lower() or 'netbios' in s.lower() 
                   for s in services.values()):
                await self._test_smb(target)
            
            # FTP
            if any('ftp' in s.lower() for s in services.values()):
                await self._test_ftp(target)
            
            # SSH
            if any('ssh' in s.lower() for s in services.values()):
                await self._test_ssh(target)
            
            # SNMP
            if 161 in self.memory.get_ports(target):
                await self._test_snmp(target)
            
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=True,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
            
        except Exception as e:
            self.errors.append(str(e))
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=False,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
        finally:
            self._running = False
    
    async def _test_smb(self, target: str):
        """Testa SMB"""
        self.log("Testando SMB...")
        
        # Enum4linux
        output, success = await self.execute_tool(
            f"enum4linux -a {target}",
            timeout=180
        )
        
        if success:
            # Extrai shares
            share_pattern = r"//\S+/(\S+)\s+Disk"
            for match in re.finditer(share_pattern, output):
                share = match.group(1)
                await self.add_finding(Finding(
                    type=FindingType.INFO,
                    value=f"SMB Share: {share}",
                    source=self.name,
                    target=target,
                    severity=Severity.LOW,
                    details={"type": "smb_share", "share": share}
                ))
            
            # Extrai usuários
            user_pattern = r"user:\[([^\]]+)\]"
            for match in re.finditer(user_pattern, output):
                user = match.group(1)
                await self.add_finding(Finding(
                    type=FindingType.USER,
                    value=user,
                    source=self.name,
                    target=target,
                    severity=Severity.INFO,
                    details={"source": "smb"}
                ))
    
    async def _test_ftp(self, target: str):
        """Testa FTP"""
        self.log("Testando FTP...")
        
        # Tenta login anônimo
        output, success = await self.execute_tool(
            f"echo -e 'anonymous\\nanonymous' | ftp -n {target}",
            timeout=30
        )
        
        if "230" in output:  # Login successful
            await self.add_finding(Finding(
                type=FindingType.VULNERABILITY,
                value="FTP Anonymous Login",
                source=self.name,
                target=target,
                severity=Severity.HIGH,
                details={"port": 21}
            ))
    
    async def _test_ssh(self, target: str):
        """Testa SSH"""
        self.log("Testando SSH...")
        
        # Verifica versão
        output, success = await self.execute_tool(
            f"nc -nv {target} 22 -w 3",
            timeout=10
        )
        
        if "SSH" in output:
            version = output.strip()
            await self.add_finding(Finding(
                type=FindingType.INFO,
                value=f"SSH Version: {version}",
                source=self.name,
                target=target,
                severity=Severity.INFO,
                details={"port": 22, "version": version}
            ))
    
    async def _test_snmp(self, target: str):
        """Testa SNMP"""
        self.log("Testando SNMP...")
        
        output, success = await self.execute_tool(
            f"snmpwalk -v2c -c public {target}",
            timeout=60
        )
        
        if success and "iso" in output.lower():
            await self.add_finding(Finding(
                type=FindingType.VULNERABILITY,
                value="SNMP Public Community String",
                source=self.name,
                target=target,
                severity=Severity.MEDIUM,
                details={"port": 161, "community": "public"}
            ))


class ExploitAgent(BaseAgent):
    """Agente de exploração - Tenta explorar vulnerabilidades"""
    
    name = "exploit"
    description = "Exploit agent - vulnerability exploitation"
    
    # Mapeamento de serviços para exploits conhecidos
    KNOWN_EXPLOITS = {
        "vsftpd 2.3.4": "vsftpd",
        "vsftpd": "vsftpd",
        "samba 3.0.20": "samba",
        "samba 3.0": "samba",
        "distccd": "distcc",
        "distcc": "distcc",
        "unrealirc": "unrealirc",
        "unreal": "unrealirc",
        "java-rmi": "java_rmi",
        "java rmi": "java_rmi",
        "tomcat": "tomcat",
        "postgres": "postgres",
        "postgresql": "postgres",
    }
    
    async def run(self, target: str, **kwargs) -> AgentResult:
        self._start_time = datetime.now()
        self._running = True
        self.log(f"Iniciando exploração em {target}")
        
        try:
            services = self.memory.get_services(target)
            
            self.log(f"Serviços encontrados: {services}")
            
            for port, service in services.items():
                service_lower = service.lower()
                
                # Verifica se tem exploit conhecido
                for pattern, exploit_key in self.KNOWN_EXPLOITS.items():
                    if pattern in service_lower:
                        self.log(f"Tentando exploit {exploit_key} na porta {port}")
                        await self._try_exploit(target, exploit_key, port)
                        break  # Só tenta um exploit por serviço
            
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=True,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
            
        except Exception as e:
            self.errors.append(str(e))
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=False,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
        finally:
            self._running = False
    
    async def _try_exploit(self, target: str, exploit_key: str, port: int):
        """Tenta executar um exploit"""
        from fragmentum.tools.executor import execute_with_pty
        
        output, success = await execute_with_pty(
            exploit_key, target, timeout=120, interactive=False
        )
        
        if success:
            await self.add_finding(Finding(
                type=FindingType.SHELL,
                value=f"Shell via {exploit_key}",
                source=self.name,
                target=target,
                severity=Severity.CRITICAL,
                details={"port": port, "exploit": exploit_key, "output": output[:500]}
            ))
    
    async def _search_exploit(self, vuln_id: str):
        """Busca exploits para uma vulnerabilidade"""
        output, success = await self.execute_tool(
            f"searchsploit {vuln_id}",
            timeout=30
        )
        
        if success and "Exploit" in output:
            self.log(f"Exploits encontrados para {vuln_id}")


class PasswordAgent(BaseAgent):
    """Agente de senhas - Tenta brute-force"""
    
    name = "password"
    description = "Password agent - credential brute-forcing"
    
    async def run(self, target: str, **kwargs) -> AgentResult:
        self._start_time = datetime.now()
        self._running = True
        self.log(f"Iniciando ataques de senha em {target}")
        
        try:
            services = self.memory.get_services(target)
            users = [f.value for f in self.memory.get_findings_by_type(FindingType.USER)]
            
            if not users:
                users = ["root", "admin", "administrator"]
            
            # SSH
            if any('ssh' in s.lower() for s in services.values()):
                await self._brute_ssh(target, users)
            
            # FTP
            if any('ftp' in s.lower() for s in services.values()):
                await self._brute_ftp(target, users)
            
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=True,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
            
        except Exception as e:
            self.errors.append(str(e))
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=False,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
        finally:
            self._running = False
    
    async def _brute_ssh(self, target: str, users: List[str]):
        """Brute-force SSH"""
        self.log("Brute-force SSH (wordlist pequena)...")
        
        for user in users[:3]:  # Limita a 3 usuários
            output, success = await self.execute_tool(
                f"hydra -l {user} -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 -f ssh://{target}",
                timeout=120
            )
            
            if "password:" in output.lower():
                # Extrai credencial
                cred_pattern = r"login:\s*(\S+)\s+password:\s*(\S+)"
                match = re.search(cred_pattern, output)
                if match:
                    await self.add_finding(Finding(
                        type=FindingType.CREDENTIAL,
                        value=f"{match.group(1)}:{match.group(2)}",
                        source=self.name,
                        target=target,
                        severity=Severity.CRITICAL,
                        details={"service": "ssh", "user": match.group(1), "password": match.group(2)}
                    ))
    
    async def _brute_ftp(self, target: str, users: List[str]):
        """Brute-force FTP"""
        self.log("Brute-force FTP (wordlist pequena)...")
        
        for user in users[:3]:
            output, success = await self.execute_tool(
                f"hydra -l {user} -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 -f ftp://{target}",
                timeout=120
            )
            
            if "password:" in output.lower():
                cred_pattern = r"login:\s*(\S+)\s+password:\s*(\S+)"
                match = re.search(cred_pattern, output)
                if match:
                    await self.add_finding(Finding(
                        type=FindingType.CREDENTIAL,
                        value=f"{match.group(1)}:{match.group(2)}",
                        source=self.name,
                        target=target,
                        severity=Severity.CRITICAL,
                        details={"service": "ftp", "user": match.group(1), "password": match.group(2)}
                    ))


class PostExploitAgent(BaseAgent):
    """Agente pós-exploração - Coleta informações após acesso"""
    
    name = "post_exploit"
    description = "Post-exploitation agent - information gathering after access"
    
    async def run(self, target: str, **kwargs) -> AgentResult:
        self._start_time = datetime.now()
        self._running = True
        self.log(f"Iniciando pós-exploração em {target}")
        
        try:
            # Verifica se temos shell ou credenciais
            shells = self.memory.get_shells()
            credentials = self.memory.get_credentials()
            
            if not shells and not credentials:
                self.log("Sem acesso ao alvo ainda. Aguardando...")
                duration = (datetime.now() - self._start_time).total_seconds()
                return AgentResult(
                    agent_name=self.name,
                    success=True,
                    findings=[],
                    duration=duration,
                    errors=[]
                )
            
            # Se temos credenciais SSH, coleta info
            for cred in credentials:
                if cred.details.get("service") == "ssh":
                    user = cred.details.get("user")
                    password = cred.details.get("password")
                    await self._collect_info_ssh(target, user, password)
            
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=True,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
            
        except Exception as e:
            self.errors.append(str(e))
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=False,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
        finally:
            self._running = False
    
    async def _collect_info_ssh(self, target: str, user: str, password: str):
        """Coleta informações via SSH"""
        self.log(f"Coletando informações via SSH como {user}")
        
        commands = [
            ("whoami", "current_user"),
            ("id", "user_id"),
            ("uname -a", "system_info"),
            ("cat /etc/passwd", "users"),
            ("cat /etc/shadow 2>/dev/null", "shadow"),
            ("sudo -l 2>/dev/null", "sudo_privs"),
        ]
        
        for cmd, info_type in commands:
            output, success = await self.execute_tool(
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {user}@{target} '{cmd}'",
                timeout=30
            )
            
            if success and output:
                await self.add_finding(Finding(
                    type=FindingType.INFO,
                    value=f"{info_type}: {output[:200]}",
                    source=self.name,
                    target=target,
                    severity=Severity.INFO,
                    details={"type": info_type, "full_output": output}
                ))


class OSINTAgent(BaseAgent):
    """Agente OSINT - Coleta informações públicas"""
    
    name = "osint"
    description = "OSINT agent - public information gathering"
    
    async def run(self, target: str, **kwargs) -> AgentResult:
        self._start_time = datetime.now()
        self._running = True
        self.log(f"Iniciando OSINT em {target}")
        
        try:
            # Verifica se é domínio ou IP
            is_domain = not re.match(r"^\d+\.\d+\.\d+\.\d+$", target)
            
            if is_domain:
                # Subdomínios
                await self._find_subdomains(target)
                
                # WHOIS
                await self._whois(target)
            
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=True,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
            
        except Exception as e:
            self.errors.append(str(e))
            duration = (datetime.now() - self._start_time).total_seconds()
            return AgentResult(
                agent_name=self.name,
                success=False,
                findings=self.findings,
                duration=duration,
                errors=self.errors
            )
        finally:
            self._running = False
    
    async def _find_subdomains(self, domain: str):
        """Encontra subdomínios"""
        self.log(f"Buscando subdomínios de {domain}")
        
        output, success = await self.execute_tool(
            f"subfinder -d {domain} -silent",
            timeout=120
        )
        
        if success:
            for line in output.strip().split("\n"):
                subdomain = line.strip()
                if subdomain:
                    await self.add_finding(Finding(
                        type=FindingType.SUBDOMAIN,
                        value=subdomain,
                        source=self.name,
                        target=domain,
                        severity=Severity.INFO,
                        details={}
                    ))
    
    async def _whois(self, domain: str):
        """Consulta WHOIS"""
        self.log(f"Consultando WHOIS de {domain}")
        
        output, success = await self.execute_tool(
            f"whois {domain}",
            timeout=30
        )
        
        if success:
            await self.add_finding(Finding(
                type=FindingType.INFO,
                value=f"WHOIS data for {domain}",
                source=self.name,
                target=domain,
                severity=Severity.INFO,
                details={"whois": output[:1000]}
            ))
