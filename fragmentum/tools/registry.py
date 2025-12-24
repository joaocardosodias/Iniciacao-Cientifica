"""
Registry de ferramentas de segurança
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import subprocess
import asyncio


class ToolCategory(Enum):
    """Categorias de ferramentas"""
    RECON = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    WEB = "web"
    EXPLOIT = "exploit"
    PASSWORD = "password"
    WIRELESS = "wireless"
    FORENSICS = "forensics"
    OSINT = "osint"
    CLOUD = "cloud"
    BINARY = "binary"
    NETWORK = "network"
    SOCIAL = "social_engineering"


@dataclass
class Tool:
    """Definição de uma ferramenta"""
    name: str
    command: str
    category: ToolCategory
    description: str = ""
    timeout: int = 180
    requires_root: bool = False
    
    # Opções padrão
    default_options: Dict[str, str] = field(default_factory=dict)
    
    # Parser de output customizado
    output_parser: Optional[Callable] = None
    
    def build_command(self, target: str = None, options: Dict[str, Any] = None) -> str:
        """Constrói comando completo"""
        cmd = self.command
        opts = {**self.default_options, **(options or {})}
        
        # Substitui placeholders
        if target:
            cmd = cmd.replace("{target}", target)
            cmd = cmd.replace("{TARGET}", target)
        
        for key, value in opts.items():
            cmd = cmd.replace(f"{{{key}}}", str(value))
        
        return cmd
    
    async def execute(
        self, 
        target: str = None, 
        options: Dict[str, Any] = None,
        timeout: int = None
    ) -> tuple[str, bool]:
        """Executa a ferramenta"""
        cmd = self.build_command(target, options)
        timeout = timeout or self.timeout
        
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode() + stderr.decode()
            success = proc.returncode == 0
            
            # Ajusta sucesso para ferramentas específicas
            output_lower = output.lower()
            if self.name == "nmap" and "nmap scan report" in output_lower:
                success = True
            elif self.name == "hydra" and "valid password" in output_lower:
                success = True
            elif self.name == "nikto" and "server:" in output_lower:
                success = True
            
            return output.strip(), success
            
        except asyncio.TimeoutError:
            return f"TIMEOUT after {timeout}s", False
        except Exception as e:
            return f"ERROR: {e}", False


class ToolRegistry:
    """Registry central de ferramentas"""
    
    def __init__(self):
        self._tools: Dict[str, Tool] = {}
        self._load_default_tools()
    
    def _load_default_tools(self):
        """Carrega ferramentas padrão - UMA versão de cada ferramenta"""
        
        # === SCANNING ===
        self.register(Tool(
            name="nmap",
            command="nmap {options} {target}",
            category=ToolCategory.SCANNING,
            description="Network port scanner with service detection",
            timeout=300,
            default_options={"options": "-sV -sC"}
        ))
        
        self.register(Tool(
            name="masscan",
            command="masscan -p{ports} --rate={rate} {target}",
            category=ToolCategory.SCANNING,
            description="Fast port scanner for large networks",
            timeout=300,
            requires_root=True,
            default_options={"ports": "1-65535", "rate": "1000"}
        ))
        
        self.register(Tool(
            name="rustscan",
            command="rustscan -a {target} -- -sV -sC",
            category=ToolCategory.SCANNING,
            description="Fast Rust-based port scanner",
            timeout=180
        ))
        
        # === ENUMERATION ===
        self.register(Tool(
            name="enum4linux",
            command="enum4linux -a {target}",
            category=ToolCategory.ENUMERATION,
            description="SMB/Samba enumeration tool",
            timeout=300
        ))
        
        self.register(Tool(
            name="smbmap",
            command="smbmap -H {target} -u {user} -p {password}",
            category=ToolCategory.ENUMERATION,
            description="SMB share mapper and enumerator",
            timeout=120,
            default_options={"user": "", "password": ""}
        ))
        
        self.register(Tool(
            name="smbclient",
            command="smbclient -L //{target} -N",
            category=ToolCategory.ENUMERATION,
            description="SMB client for share listing",
            timeout=60
        ))
        
        self.register(Tool(
            name="ldapsearch",
            command="ldapsearch -x -H ldap://{target} -b '' -s base",
            category=ToolCategory.ENUMERATION,
            description="LDAP enumeration tool",
            timeout=60
        ))
        
        self.register(Tool(
            name="snmpwalk",
            command="snmpwalk -v2c -c {community} {target}",
            category=ToolCategory.ENUMERATION,
            description="SNMP enumeration tool",
            timeout=180,
            default_options={"community": "public"}
        ))
        
        self.register(Tool(
            name="nbtscan",
            command="nbtscan {target}",
            category=ToolCategory.ENUMERATION,
            description="NetBIOS scanner",
            timeout=60
        ))
        
        self.register(Tool(
            name="showmount",
            command="showmount -e {target}",
            category=ToolCategory.ENUMERATION,
            description="NFS share enumeration",
            timeout=30
        ))
        
        self.register(Tool(
            name="rpcclient",
            command="rpcclient -U '' -N {target} -c '{command}'",
            category=ToolCategory.ENUMERATION,
            description="RPC enumeration tool",
            timeout=60,
            default_options={"command": "enumdomusers"}
        ))
        
        self.register(Tool(
            name="dnsrecon",
            command="dnsrecon -d {target}",
            category=ToolCategory.ENUMERATION,
            description="DNS reconnaissance tool",
            timeout=120
        ))
        
        # === WEB ===
        self.register(Tool(
            name="gobuster",
            command="gobuster dir -u {target} -w {wordlist} -t {threads}",
            category=ToolCategory.WEB,
            description="Directory and file brute-forcer",
            timeout=300,
            default_options={"wordlist": "/usr/share/wordlists/dirb/common.txt", "threads": "50"}
        ))
        
        self.register(Tool(
            name="ffuf",
            command="ffuf -u {target}/FUZZ -w {wordlist} -mc 200,301,302,403",
            category=ToolCategory.WEB,
            description="Fast web fuzzer",
            timeout=300,
            default_options={"wordlist": "/usr/share/wordlists/dirb/common.txt"}
        ))
        
        self.register(Tool(
            name="nikto",
            command="nikto -h {target}",
            category=ToolCategory.WEB,
            description="Web server vulnerability scanner",
            timeout=600
        ))
        
        self.register(Tool(
            name="wpscan",
            command="wpscan --url {target} --enumerate {enumerate}",
            category=ToolCategory.WEB,
            description="WordPress security scanner",
            timeout=300,
            default_options={"enumerate": "vp,vt,u"}
        ))
        
        self.register(Tool(
            name="sqlmap",
            command="sqlmap -u {target} --batch --level={level} --risk={risk}",
            category=ToolCategory.WEB,
            description="SQL injection scanner and exploiter",
            timeout=600,
            default_options={"level": "3", "risk": "2"}
        ))
        
        self.register(Tool(
            name="whatweb",
            command="whatweb {target}",
            category=ToolCategory.WEB,
            description="Web technology identifier",
            timeout=60
        ))
        
        self.register(Tool(
            name="wafw00f",
            command="wafw00f {target}",
            category=ToolCategory.WEB,
            description="Web Application Firewall detector",
            timeout=60
        ))
        
        self.register(Tool(
            name="xsstrike",
            command="xsstrike -u {target}",
            category=ToolCategory.WEB,
            description="XSS vulnerability scanner",
            timeout=180
        ))
        
        self.register(Tool(
            name="commix",
            command="commix -u {target} --batch",
            category=ToolCategory.WEB,
            description="Command injection scanner",
            timeout=300
        ))
        
        self.register(Tool(
            name="nuclei",
            command="nuclei -u {target} -t {templates}",
            category=ToolCategory.WEB,
            description="Template-based vulnerability scanner",
            timeout=300,
            default_options={"templates": "cves/"}
        ))
        
        # === PASSWORD ===
        self.register(Tool(
            name="hydra",
            command="hydra -l {user} -P {wordlist} {service}://{target}",
            category=ToolCategory.PASSWORD,
            description="Network login brute-forcer (ssh, ftp, http, smb, etc)",
            timeout=900,
            default_options={"user": "root", "wordlist": "/usr/share/wordlists/rockyou.txt", "service": "ssh"}
        ))
        
        self.register(Tool(
            name="medusa",
            command="medusa -h {target} -u {user} -P {wordlist} -M {module}",
            category=ToolCategory.PASSWORD,
            description="Parallel password cracker",
            timeout=900,
            default_options={"user": "root", "wordlist": "/usr/share/wordlists/rockyou.txt", "module": "ssh"}
        ))
        
        self.register(Tool(
            name="john",
            command="john --wordlist={wordlist} {hashfile}",
            category=ToolCategory.PASSWORD,
            description="Password hash cracker",
            timeout=1800,
            default_options={"wordlist": "/usr/share/wordlists/rockyou.txt", "hashfile": "hashes.txt"}
        ))
        
        self.register(Tool(
            name="hashcat",
            command="hashcat -m {mode} {hashfile} {wordlist}",
            category=ToolCategory.PASSWORD,
            description="GPU-accelerated password cracker",
            timeout=1800,
            default_options={"mode": "0", "wordlist": "/usr/share/wordlists/rockyou.txt", "hashfile": "hashes.txt"}
        ))
        
        self.register(Tool(
            name="crackmapexec",
            command="crackmapexec {protocol} {target} -u {user} -p {password}",
            category=ToolCategory.PASSWORD,
            description="Network password spraying tool",
            timeout=300,
            default_options={"protocol": "smb", "user": "administrator", "password": ""}
        ))
        
        # === OSINT ===
        self.register(Tool(
            name="theharvester",
            command="theHarvester -d {target} -b {source}",
            category=ToolCategory.OSINT,
            description="Email and subdomain harvester",
            timeout=300,
            default_options={"source": "all"}
        ))
        
        self.register(Tool(
            name="subfinder",
            command="subfinder -d {target}",
            category=ToolCategory.OSINT,
            description="Subdomain discovery tool",
            timeout=180
        ))
        
        self.register(Tool(
            name="amass",
            command="amass enum -d {target}",
            category=ToolCategory.OSINT,
            description="Attack surface mapper",
            timeout=600
        ))
        
        self.register(Tool(
            name="whois",
            command="whois {target}",
            category=ToolCategory.OSINT,
            description="Domain/IP WHOIS lookup",
            timeout=30
        ))
        
        self.register(Tool(
            name="dnsenum",
            command="dnsenum {target}",
            category=ToolCategory.OSINT,
            description="DNS enumeration tool",
            timeout=180
        ))
        
        self.register(Tool(
            name="sherlock",
            command="sherlock {username}",
            category=ToolCategory.OSINT,
            description="Username search across social networks",
            timeout=120,
            default_options={"username": ""}
        ))
        
        # === EXPLOIT ===
        self.register(Tool(
            name="searchsploit",
            command="searchsploit {query}",
            category=ToolCategory.EXPLOIT,
            description="Exploit database search",
            timeout=30,
            default_options={"query": ""}
        ))
        
        self.register(Tool(
            name="msfvenom",
            command="msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {format} -o {output}",
            category=ToolCategory.EXPLOIT,
            description="Payload generator for reverse shells",
            timeout=30,
            default_options={"payload": "linux/x64/shell_reverse_tcp", "lhost": "0.0.0.0", "lport": "4444", "format": "elf", "output": "shell"}
        ))
        
        self.register(Tool(
            name="linpeas",
            command="curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
            category=ToolCategory.EXPLOIT,
            description="Linux privilege escalation scanner",
            timeout=300
        ))
        
        # === NETWORK ===
        self.register(Tool(
            name="netcat",
            command="nc -nv {target} {port}",
            category=ToolCategory.NETWORK,
            description="Network utility for connections",
            timeout=30,
            default_options={"port": "80"}
        ))
        
        self.register(Tool(
            name="tcpdump",
            command="tcpdump -i {interface} host {target} -c {count}",
            category=ToolCategory.NETWORK,
            description="Packet capture tool",
            timeout=60,
            requires_root=True,
            default_options={"interface": "any", "count": "100"}
        ))
        
        self.register(Tool(
            name="traceroute",
            command="traceroute {target}",
            category=ToolCategory.NETWORK,
            description="Network path tracer",
            timeout=60
        ))
        
        self.register(Tool(
            name="netdiscover",
            command="netdiscover -r {range} -P",
            category=ToolCategory.NETWORK,
            description="Network host discovery",
            timeout=60,
            requires_root=True,
            default_options={"range": "192.168.1.0/24"}
        ))
        
        # === ACTIVE DIRECTORY ===
        self.register(Tool(
            name="impacket_secretsdump",
            command="impacket-secretsdump {domain}/{user}:{password}@{target}",
            category=ToolCategory.EXPLOIT,
            description="Dump secrets from Windows/AD",
            timeout=300,
            default_options={"domain": "", "user": "", "password": ""}
        ))
        
        self.register(Tool(
            name="impacket_psexec",
            command="impacket-psexec {domain}/{user}:{password}@{target}",
            category=ToolCategory.EXPLOIT,
            description="Remote command execution via PSExec",
            timeout=60,
            default_options={"domain": "", "user": "", "password": ""}
        ))
        
        self.register(Tool(
            name="evil_winrm",
            command="evil-winrm -i {target} -u {user} -p {password}",
            category=ToolCategory.EXPLOIT,
            description="WinRM shell for Windows",
            timeout=60,
            default_options={"user": "", "password": ""}
        ))
        
        self.register(Tool(
            name="bloodhound",
            command="bloodhound-python -d {domain} -u {user} -p {password} -ns {target} -c all",
            category=ToolCategory.ENUMERATION,
            description="Active Directory relationship mapper",
            timeout=300,
            default_options={"domain": "", "user": "", "password": ""}
        ))
        
        self.register(Tool(
            name="kerbrute",
            command="kerbrute userenum -d {domain} --dc {target} {wordlist}",
            category=ToolCategory.ENUMERATION,
            description="Kerberos user enumeration",
            timeout=300,
            default_options={"domain": "", "wordlist": "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt"}
        ))
        
        # === CLOUD ===
        self.register(Tool(
            name="aws_enum",
            command="aws {service} {action}",
            category=ToolCategory.CLOUD,
            description="AWS CLI for cloud enumeration",
            timeout=60,
            default_options={"service": "s3", "action": "ls"}
        ))
        
        self.register(Tool(
            name="trivy",
            command="trivy image {target}",
            category=ToolCategory.CLOUD,
            description="Container vulnerability scanner",
            timeout=300
        ))
        
        self.register(Tool(
            name="kube_hunter",
            command="kube-hunter --remote {target}",
            category=ToolCategory.CLOUD,
            description="Kubernetes security scanner",
            timeout=180
        ))
        
        # === BINARY ===
        self.register(Tool(
            name="checksec",
            command="checksec --file={target}",
            category=ToolCategory.BINARY,
            description="Binary security checker",
            timeout=30
        ))
        
        self.register(Tool(
            name="strings",
            command="strings {target}",
            category=ToolCategory.BINARY,
            description="Extract strings from binary",
            timeout=60
        ))
        
        self.register(Tool(
            name="binwalk",
            command="binwalk {target}",
            category=ToolCategory.BINARY,
            description="Firmware analysis tool",
            timeout=120
        ))
        
        self.register(Tool(
            name="exiftool",
            command="exiftool {target}",
            category=ToolCategory.BINARY,
            description="Metadata extractor",
            timeout=30
        ))
        
        # === MISC ===
        self.register(Tool(
            name="execute_command",
            command="{command}",
            category=ToolCategory.NETWORK,
            description="Execute arbitrary shell command",
            timeout=180,
            default_options={"command": "whoami"}
        ))
    
    def register(self, tool: Tool):
        """Registra uma ferramenta"""
        self._tools[tool.name] = tool
    
    def get(self, name: str) -> Optional[Tool]:
        """Obtém ferramenta por nome"""
        return self._tools.get(name)
    
    def list_all(self) -> List[Tool]:
        """Lista todas as ferramentas"""
        return list(self._tools.values())
    
    def list_by_category(self, category: ToolCategory) -> List[Tool]:
        """Lista ferramentas por categoria"""
        return [t for t in self._tools.values() if t.category == category]
    
    def search(self, query: str) -> List[Tool]:
        """Busca ferramentas por nome ou descrição"""
        query = query.lower()
        return [
            t for t in self._tools.values()
            if query in t.name.lower() or query in t.description.lower()
        ]


# Singleton
_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Obtém o registry singleton"""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


def reset_tool_registry() -> None:
    """Reseta o registry (para testes)"""
    global _registry
    _registry = None
