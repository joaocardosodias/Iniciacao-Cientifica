"""
Módulo de Output Profissional com Cores ANSI.
"""


class Colors:
    """Códigos de cores ANSI para terminal."""
    # Reset
    RESET = "\033[0m"
    
    # Cores básicas
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Cores brilhantes
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Estilos
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    
    # Backgrounds
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


class Logger:
    """Logger profissional com cores."""
    
    @staticmethod
    def banner():
        """Exibe banner do sistema com ASCII art."""
        ascii_art = r"""
███████╗██████╗  █████╗  ██████╗ ███╗   ███╗███████╗███╗   ██╗████████╗██╗   ██╗███╗   ███╗
██╔════╝██╔══██╗██╔══██╗██╔════╝ ████╗ ████║██╔════╝████╗  ██║╚══██╔══╝██║   ██║████╗ ████║
█████╗  ██████╔╝███████║██║  ███╗██╔████╔██║█████╗  ██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔══╝  ██╔══██╗██╔══██║██║   ██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
"""
        print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}{ascii_art}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 80}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}  Red Team Autonomous Agent - Guardrail Evasion Research{Colors.RESET}")
        print(f"{Colors.DIM}  IC Project - Context Fragmentation Analysis{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 80}{Colors.RESET}\n")
    
    @staticmethod
    def config(provider: str, model: str, target: str, stealth: str = "low"):
        """Exibe configuração atual."""
        stealth_colors = {
            "low": Colors.RED,
            "medium": Colors.YELLOW,
            "high": Colors.GREEN
        }
        stealth_labels = {
            "low": "AGGRESSIVE",
            "medium": "BALANCED",
            "high": "STEALTH/LOLBins"
        }
        sc = stealth_colors.get(stealth, Colors.WHITE)
        sl = stealth_labels.get(stealth, stealth.upper())
        print(f"{Colors.DIM}[CONFIG]{Colors.RESET} Provider: {Colors.CYAN}{provider}{Colors.RESET} | Model: {Colors.CYAN}{model}{Colors.RESET} | Target: {Colors.YELLOW}{target}{Colors.RESET}")
        print(f"{Colors.DIM}[OPSEC]{Colors.RESET}  Stealth: {sc}{sl}{Colors.RESET}")
    
    @staticmethod
    def mode(mode: str):
        """Exibe modo de execução."""
        color = Colors.MAGENTA if mode == "agentic" else Colors.BLUE
        print(f"\n{Colors.BOLD}{color}{'=' * 70}")
        print(f"  EXECUTION MODE: {mode.upper()}")
        print(f"{'=' * 70}{Colors.RESET}\n")
    
    @staticmethod
    def phase(phase_num: int, total: int, name: str):
        """Exibe fase atual."""
        print(f"{Colors.BRIGHT_BLUE}[PHASE {phase_num}/{total}]{Colors.RESET} {Colors.BOLD}{name}{Colors.RESET}")
    
    @staticmethod
    def step(step_num: int, description: str):
        """Exibe passo atual."""
        print(f"\n{Colors.YELLOW}--- STEP {step_num} ---{Colors.RESET}")
        print(f"{Colors.DIM}Description:{Colors.RESET} {description}")
    
    @staticmethod
    def sanitizer(original: str, sanitized: str):
        """Exibe resultado do sanitizador."""
        print(f"{Colors.DIM}[INPUT]{Colors.RESET}  {original[:80]}{'...' if len(original) > 80 else ''}")
        print(f"{Colors.GREEN}[OUTPUT]{Colors.RESET} {sanitized[:80]}{'...' if len(sanitized) > 80 else ''}")
    
    @staticmethod
    def planner(decision: str):
        """Exibe decisão do planejador."""
        print(f"{Colors.CYAN}[PLANNER]{Colors.RESET} {decision}")
    
    @staticmethod
    def command(cmd: str, timeout: int):
        """Exibe comando a ser executado."""
        print(f"{Colors.MAGENTA}[COMMAND]{Colors.RESET} {Colors.BOLD}{cmd}{Colors.RESET} {Colors.DIM}(timeout: {timeout}s){Colors.RESET}")
    
    @staticmethod
    def exec_start(cmd: str):
        """Indica início de execução."""
        print(f"{Colors.DIM}[EXEC]{Colors.RESET} Running: {cmd}")
    
    @staticmethod
    def exec_output(output: str, success: bool):
        """Exibe saída da execução."""
        if success:
            status = f"{Colors.GREEN}[OK]{Colors.RESET}"
        else:
            status = f"{Colors.RED}[FAIL]{Colors.RESET}"
        
        # Limita output
        short = output[:400] + "..." if len(output) > 400 else output
        print(f"{status} Output:")
        for line in short.split("\n")[:10]:
            print(f"    {Colors.DIM}{line}{Colors.RESET}")
    
    @staticmethod
    def success(message: str):
        """Mensagem de sucesso."""
        print(f"\n{Colors.BRIGHT_GREEN}[SUCCESS]{Colors.RESET} {message}")
    
    @staticmethod
    def error(message: str):
        """Mensagem de erro."""
        print(f"{Colors.BRIGHT_RED}[ERROR]{Colors.RESET} {message}")
    
    @staticmethod
    def warning(message: str):
        """Mensagem de aviso."""
        print(f"{Colors.BRIGHT_YELLOW}[WARN]{Colors.RESET} {message}")
    
    @staticmethod
    def info(message: str):
        """Mensagem informativa."""
        print(f"{Colors.DIM}[INFO]{Colors.RESET} {message}")
    
    @staticmethod
    def refused():
        """Indica que o modelo recusou."""
        print(f"{Colors.BG_RED}{Colors.WHITE}[GUARDRAIL TRIGGERED]{Colors.RESET} Model refused the request")
    
    @staticmethod
    def loop_detected(failures: int):
        """Indica detecção de loop."""
        print(f"\n{Colors.BRIGHT_YELLOW}[LOOP DETECTED]{Colors.RESET} {failures} consecutive failures. Aborting execution.")
    
    @staticmethod
    def completed():
        """Indica conclusão do objetivo."""
        print(f"\n{Colors.BRIGHT_GREEN}[COMPLETED]{Colors.RESET} Agent determined objective was achieved")
    
    @staticmethod
    def timeout():
        """Indica timeout."""
        print(f"\n{Colors.YELLOW}[TIMEOUT]{Colors.RESET} Maximum iterations reached")
    
    @staticmethod
    def result(result_type: str):
        """Exibe resultado final."""
        colors = {
            "success": Colors.BRIGHT_GREEN,
            "refused": Colors.BRIGHT_RED,
            "timeout": Colors.YELLOW,
            "logic_error": Colors.BRIGHT_YELLOW,
            "hallucination": Colors.MAGENTA,
            "error": Colors.RED
        }
        color = colors.get(result_type, Colors.WHITE)
        print(f"\n{Colors.BOLD}[RESULT]{Colors.RESET} {color}{result_type.upper()}{Colors.RESET}")
    
    @staticmethod
    def separator():
        """Linha separadora."""
        print(f"{Colors.DIM}{'-' * 70}{Colors.RESET}")
    
    @staticmethod
    def end():
        """Finalização."""
        print(f"\n{Colors.CYAN}{'=' * 70}")
        print("  END OF OPERATION")
        print(f"{'=' * 70}{Colors.RESET}\n")
    
    @staticmethod
    def final_report(findings: 'FindingsCollector', target: str, scenario_id: str = None):
        """Exibe relatório final com findings."""
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_CYAN}{'=' * 70}")
        print("  FINAL REPORT - OPERATION SUMMARY")
        print(f"{'=' * 70}{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}Target:{Colors.RESET} {Colors.YELLOW}{target}{Colors.RESET}")
        if scenario_id and scenario_id != "manual":
            print(f"{Colors.BOLD}Scenario:{Colors.RESET} {scenario_id}")
        print(f"{Colors.BOLD}Total Steps:{Colors.RESET} {findings.total_steps}")
        print(f"{Colors.BOLD}Commands Executed:{Colors.RESET} {len(findings.commands)}")
        
        # Open Ports
        if findings.open_ports:
            print(f"\n{Colors.BRIGHT_GREEN}[OPEN PORTS]{Colors.RESET}")
            for port, service in sorted(findings.open_ports.items()):
                print(f"  {Colors.GREEN}*{Colors.RESET} {port}/tcp - {service}")
        
        # Services
        if findings.services:
            print(f"\n{Colors.BRIGHT_BLUE}[SERVICES DETECTED]{Colors.RESET}")
            for service, version in findings.services.items():
                print(f"  {Colors.BLUE}*{Colors.RESET} {service}: {version}")
        
        # Vulnerabilities
        if findings.vulnerabilities:
            print(f"\n{Colors.BRIGHT_RED}[VULNERABILITIES]{Colors.RESET}")
            for vuln in findings.vulnerabilities:
                print(f"  {Colors.RED}!{Colors.RESET} {vuln}")
        
        # Credentials
        if findings.credentials:
            print(f"\n{Colors.BRIGHT_MAGENTA}[CREDENTIALS FOUND]{Colors.RESET}")
            for cred in findings.credentials:
                print(f"  {Colors.MAGENTA}*{Colors.RESET} {cred}")
        
        # Key Findings
        if findings.key_findings:
            print(f"\n{Colors.BRIGHT_YELLOW}[KEY FINDINGS]{Colors.RESET}")
            for finding in findings.key_findings:
                print(f"  {Colors.YELLOW}>{Colors.RESET} {finding}")
        
        # Brain Intelligence Summary (if available)
        try:
            from intelligence import get_brain
            brain = get_brain(target)
            if brain.knowledge.users_found:
                print(f"\n{Colors.BRIGHT_CYAN}[USERS DISCOVERED]{Colors.RESET}")
                for user in list(brain.knowledge.users_found)[:10]:
                    print(f"  {Colors.CYAN}@{Colors.RESET} {user}")
            if brain.knowledge.credentials_valid:
                print(f"\n{Colors.BRIGHT_MAGENTA}[VALID CREDENTIALS]{Colors.RESET}")
                for svc, user, passwd in brain.knowledge.credentials_valid[:5]:
                    print(f"  {Colors.MAGENTA}*{Colors.RESET} {user}:{passwd} ({svc})")
            if brain.insights:
                print(f"\n{Colors.BRIGHT_WHITE}[INTELLIGENCE INSIGHTS]{Colors.RESET}")
                for insight in brain.insights[-5:]:  # Last 5 insights
                    print(f"  {Colors.WHITE}>{Colors.RESET} {insight}")
        except:
            pass  # Brain not available
        
        print(f"\n{Colors.DIM}{'─' * 70}{Colors.RESET}")


class FindingsCollector:
    """Coleta findings durante a execução para relatório final."""
    
    def __init__(self):
        self.open_ports = {}  # port: service
        self.services = {}    # service: version
        self.vulnerabilities = []
        self.credentials = []
        self.key_findings = []
        self.commands = []
        self.total_steps = 0
    
    def parse_output(self, cmd: str, output: str):
        """Extrai findings do output de comandos."""
        import re
        output_lower = output.lower()
        
        self.commands.append(cmd)
        
        # Parse nmap output for ports
        port_matches = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', output)
        for port, service in port_matches:
            self.open_ports[port] = service
        
        # Parse service versions
        version_matches = re.findall(r'(\d+)/tcp\s+open\s+(\S+)\s+(.+?)(?:\n|$)', output)
        for port, service, version in version_matches:
            version = version.strip()[:50]
            if version and service not in self.services:
                self.services[service] = version
        
        # Detect vulnerabilities
        vuln_patterns = [
            (r'vsftpd 2\.3\.4', 'vsftpd 2.3.4 Backdoor (CVE-2011-2523)'),
            (r'OpenSSH 4\.7p1', 'OpenSSH 4.7p1 - Multiple vulnerabilities'),
            (r'Apache/2\.2\.8', 'Apache 2.2.8 - Multiple vulnerabilities'),
            (r'PHP/5\.2\.4', 'PHP 5.2.4 - Multiple vulnerabilities'),
            (r'Samba 3\.0\.20', 'Samba 3.0.20 - Username map script RCE'),
            (r'MySQL 5\.0\.51', 'MySQL 5.0.51 - Multiple vulnerabilities'),
            (r'PostgreSQL 8\.3', 'PostgreSQL 8.3 - Multiple vulnerabilities'),
            (r'distccd', 'DistCC - Remote Code Execution'),
            (r'UnrealIRCd', 'UnrealIRCd - Backdoor'),
            (r'EXPLOIT', 'Exploit available (see nmap output)'),
        ]
        for pattern, vuln_name in vuln_patterns:
            if re.search(pattern, output, re.IGNORECASE) and vuln_name not in self.vulnerabilities:
                self.vulnerabilities.append(vuln_name)
        
        # Detect credentials
        cred_patterns = [
            r'login:\s*(\S+)\s+password:\s*(\S+)',
            r'\[(\d+)\]\[(\w+)\]\s+host:.+login:\s*(\S+)\s+password:\s*(\S+)',
            r'valid password found:\s*(\S+)',
        ]
        for pattern in cred_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    cred = ':'.join(match)
                else:
                    cred = match
                if cred not in self.credentials:
                    self.credentials.append(cred)
        
        # Key findings based on output
        if 'host is up' in output_lower:
            if 'Host is up' not in [f[:10] for f in self.key_findings]:
                self.key_findings.append(f"Host is up and responding")
        
        if 'backdoor' in output_lower:
            self.key_findings.append("Backdoor detected!")
        
        if 'root' in output_lower and ('access' in output_lower or 'shell' in output_lower):
            self.key_findings.append("Potential root access identified")


# Instância global
log = Logger()
findings = FindingsCollector()
