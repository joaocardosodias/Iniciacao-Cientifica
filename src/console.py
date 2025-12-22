"""
FRAGMENTUM Console - Interface Interativa estilo Metasploit
"""

import cmd
import sys
import os
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()


# Cores ANSI - Paleta Azul Escuro
class C:
    RESET = "\033[0m"
    BLUE = "\033[34m"
    BLUE_DARK = "\033[38;5;17m"
    BLUE_NAVY = "\033[38;5;18m"
    BLUE_MED = "\033[38;5;20m"
    BLUE_LIGHT = "\033[38;5;39m"
    CYAN = "\033[38;5;45m"
    WHITE = "\033[97m"
    GRAY = "\033[38;5;245m"
    GREEN = "\033[38;5;42m"
    RED = "\033[38;5;196m"
    YELLOW = "\033[38;5;220m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


class FragmentumConsole(cmd.Cmd):
    """Console interativo do FRAGMENTUM."""
    
    intro = ""
    
    config = {
        "target": None,
        "scenario": None,
        "intent": None,
        "provider": os.getenv("LLM_PROVIDER", "gemini"),
        "model": None,
        "stealth": "low",
        "mode": "agentic",
    }
    
    PROVIDER_MODELS = {
        "gemini": ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo", "o1-preview", "o1-mini"],
        "anthropic": ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
        "groq": ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "mixtral-8x7b-32768"],
        "cerebras": ["llama3.1-8b", "llama3.1-70b"],
        "deepseek": ["deepseek-chat", "deepseek-coder"],
        "mistral": ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest"],
        "cohere": ["command-r-plus", "command-r", "command"],
        "together": ["meta-llama/Llama-3-70b-chat-hf", "mistralai/Mixtral-8x7B-Instruct-v0.1"],
        "fireworks": ["accounts/fireworks/models/llama-v3-70b-instruct"],
        "ollama": ["llama3:70b", "llama3:8b", "mistral", "codellama", "deepseek-coder"],
    }
    
    STEALTH_INFO = {
        "low": ("AGGRESSIVE", "All tools available"),
        "medium": ("BALANCED", "Common tools with basic evasion"),
        "high": ("STEALTH", "LOLBins only"),
    }
    
    MODE_INFO = {
        "agentic": "Hierarchical 3-stage pipeline (autonomous)",
        "interactive": "Hierarchical 3-stage with user confirmation",
        "monolithic": "Direct single prompt to LLM",
        "both": "Run both modes for comparison",
    }
    
    def __init__(self):
        super().__init__()
        self._update_prompt()
        self._show_banner()
    
    def _update_prompt(self):
        scenario = self.config["scenario"]
        if scenario:
            self.prompt = f"{C.BLUE_LIGHT}{C.BOLD}fragmentum{C.RESET}({C.CYAN}{scenario}{C.RESET}) > "
        else:
            self.prompt = f"{C.BLUE_LIGHT}{C.BOLD}fragmentum{C.RESET} > "
    
    def _show_banner(self):
        banner = f"""
{C.BLUE_LIGHT}{C.BOLD}
███████╗██████╗  █████╗  ██████╗ ███╗   ███╗███████╗███╗   ██╗████████╗██╗   ██╗███╗   ███╗
██╔════╝██╔══██╗██╔══██╗██╔════╝ ████╗ ████║██╔════╝████╗  ██║╚══██╔══╝██║   ██║████╗ ████║
█████╗  ██████╔╝███████║██║  ███╗██╔████╔██║█████╗  ██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔══╝  ██╔══██╗██╔══██║██║   ██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
{C.RESET}
{C.GRAY}       [ Red Team Autonomous Agent - Guardrail Evasion Research ]{C.RESET}

{C.CYAN}       Type 'help' for available commands, 'scenarios' to list attack scenarios{C.RESET}
"""
        print(banner)
    
    def do_set(self, arg):
        """Define configurações. Uso: set <opção> <valor>"""
        args = arg.split()
        if len(args) < 2:
            print(f"{C.RED}[!]{C.RESET} Uso: set <opção> <valor>")
            return
        
        option = args[0].lower()
        value = " ".join(args[1:])
        
        if option == "target":
            self.config["target"] = value
            print(f"{C.GREEN}[+]{C.RESET} target => {value}")
        elif option == "intent":
            if self.config["scenario"]:
                print(f"{C.YELLOW}[*]{C.RESET} Limpando scenario")
                self.config["scenario"] = None
            self.config["intent"] = value
            print(f"{C.GREEN}[+]{C.RESET} intent => {value}")
        elif option == "scenario":
            try:
                from scenarios import get_scenario
                scenario = get_scenario(value.upper())
                if self.config["intent"]:
                    print(f"{C.YELLOW}[*]{C.RESET} Limpando intent")
                    self.config["intent"] = None
                self.config["scenario"] = value.upper()
                print(f"{C.GREEN}[+]{C.RESET} scenario => {value.upper()}")
            except ValueError:
                print(f"{C.RED}[!]{C.RESET} Cenário não encontrado: {value}")
                return
        elif option == "provider":
            self.config["provider"] = value.lower()
            print(f"{C.GREEN}[+]{C.RESET} provider => {value.lower()}")
        elif option == "model":
            self.config["model"] = value
            print(f"{C.GREEN}[+]{C.RESET} model => {value}")
        elif option == "stealth":
            if value.lower() in ["low", "medium", "high"]:
                self.config["stealth"] = value.lower()
                print(f"{C.GREEN}[+]{C.RESET} stealth => {value.lower()}")
            else:
                print(f"{C.RED}[!]{C.RESET} Stealth inválido. Use: low, medium, high")
        elif option == "mode":
            if value.lower() in ["agentic", "interactive", "monolithic", "both"]:
                self.config["mode"] = value.lower()
                print(f"{C.GREEN}[+]{C.RESET} mode => {value.lower()}")
            else:
                print(f"{C.RED}[!]{C.RESET} Mode inválido. Use: agentic, interactive, monolithic, both")
        else:
            print(f"{C.RED}[!]{C.RESET} Opção desconhecida: {option}")
            return
        
        self._update_prompt()
    
    def complete_set(self, text, line, begidx, endidx):
        options = ["target", "scenario", "intent", "provider", "model", "stealth", "mode"]
        args = line.split()
        if len(args) <= 2:
            return [o for o in options if o.startswith(text.lower())]
        return []
    
    def do_options(self, arg):
        """Mostra configurações atuais."""
        print(f"\n{C.BOLD}Module options:{C.RESET}\n")
        print(f"   {'Name':<12} {'Current Setting':<30} {'Required':<10}")
        print(f"   {'-'*12} {'-'*30} {'-'*10}")
        
        target = self.config["target"] or ""
        scenario = self.config["scenario"] or ""
        intent = self.config["intent"] or ""
        intent_display = (intent[:27] + "...") if len(intent) > 30 else intent
        
        print(f"   {'target':<12} {target:<30} {'yes':<10}")
        print(f"   {'scenario':<12} {scenario:<30} {'no':<10}")
        print(f"   {'intent':<12} {intent_display:<30} {'no':<10}")
        print(f"   {'provider':<12} {self.config['provider']:<30} {'no':<10}")
        print(f"   {'model':<12} {(self.config['model'] or 'default'):<30} {'no':<10}")
        print(f"   {'stealth':<12} {self.config['stealth']:<30} {'no':<10}")
        print(f"   {'mode':<12} {self.config['mode']:<30} {'no':<10}")
        print()
    
    def do_scenarios(self, arg):
        """Lista todos os cenários disponíveis."""
        from scenarios import SCENARIOS
        
        print(f"\n{C.BOLD}Available Scenarios:{C.RESET}\n")
        
        current_tactic = None
        for s in SCENARIOS:
            if s.tactic != current_tactic:
                current_tactic = s.tactic
                print(f"\n   {C.YELLOW}[{s.tactic.name}]{C.RESET}")
                print(f"   {'-' * 50}")
            print(f"   {C.CYAN}{s.id:<12}{C.RESET} {s.name}")
        
        print(f"\n{C.DIM}   Total: {len(SCENARIOS)} scenarios{C.RESET}\n")
    
    def do_use(self, arg):
        """Seleciona um cenário. Uso: use <scenario_id>"""
        if not arg:
            print(f"{C.RED}[!]{C.RESET} Uso: use <scenario_id>")
            return
        self.do_set(f"scenario {arg}")
    
    def complete_use(self, text, line, begidx, endidx):
        from scenarios import SCENARIOS
        scenarios = [s.id for s in SCENARIOS]
        return [s for s in scenarios if s.lower().startswith(text.lower())]
    
    def do_run(self, arg):
        """Executa o ataque com as configurações atuais."""
        self.do_exploit(arg)
    
    def do_exploit(self, arg):
        """Executa o ataque com as configurações atuais."""
        if not self.config["target"]:
            print(f"{C.RED}[!]{C.RESET} Target não definido. Use 'set target <IP>'")
            return
        
        import main as fragmentum_main
        
        fragmentum_main.CURRENT_PROVIDER = self.config["provider"]
        fragmentum_main.CURRENT_MODEL = self.config["model"]
        fragmentum_main.CURRENT_TARGET = self.config["target"]
        fragmentum_main.CURRENT_STEALTH = self.config["stealth"]
        
        intent = None
        scenario_id = self.config["scenario"] or "manual"
        
        if self.config["intent"]:
            intent = self.config["intent"]
            print(f"\n{C.GREEN}[*]{C.RESET} Using custom intent: {intent}\n")
        elif self.config["scenario"]:
            from scenarios import get_scenario
            scenario = get_scenario(self.config["scenario"])
            intent = scenario.objective
            print(f"\n{C.GREEN}[*]{C.RESET} Loaded scenario: {scenario.name}")
            print(f"{C.GREEN}[*]{C.RESET} Objective: {intent}\n")
        else:
            intent = input(f"\n{C.CYAN}>> Enter objective:{C.RESET} ")
        
        if not intent:
            print(f"{C.RED}[!]{C.RESET} Objetivo não pode ser vazio")
            return
        
        from metrics import MetricsCollector
        from llm_setup import DEFAULT_PROVIDER, DEFAULT_MODELS
        
        collector = MetricsCollector()
        provider = self.config["provider"] or DEFAULT_PROVIDER
        model = self.config["model"] or DEFAULT_MODELS.get(provider)
        
        print(f"[CONFIG] Provider: {provider} | Model: {model} | Target: {self.config['target']}")
        
        modes = ["monolithic", "agentic"] if self.config["mode"] == "both" else [self.config["mode"]]
        
        for mode in modes:
            print(f"\n{'=' * 70}")
            print(f"  EXECUTION MODE: {mode.upper()}")
            print(f"{'=' * 70}\n")
            
            run = collector.new_run(mode=mode, model=f"{provider}/{model}",
                                   scenario_id=scenario_id, original_intent=intent)
            
            if mode == "monolithic":
                result = fragmentum_main.run_monolithic(intent, self.config["target"], run)
            elif mode == "interactive":
                result = fragmentum_main.run_interactive(intent, self.config["target"], run)
            else:
                result = fragmentum_main.run_agentic(intent, self.config["target"], run)
            
            run.finish(result)
            
            if run.execution_log:
                for step in reversed(run.execution_log):
                    output = step.get('output', '')
                    cmd = step.get('command', '')
                    if cmd and output and 'forced completion' not in output.lower():
                        print(f"\n[LAST OUTPUT]\n{output}")
                        break
            
            print(f"\n[RESULT] {result.value.upper()}")
        
        print(f"\n{'-' * 70}")
        collector.print_summary()
        
        print(f"\n{'=' * 70}")
        print("  END OF OPERATION")
        print(f"{'=' * 70}\n")
    
    def do_check(self, arg):
        """Verifica se o target está acessível."""
        if not self.config["target"]:
            print(f"{C.RED}[!]{C.RESET} Target não definido")
            return
        
        print(f"{C.YELLOW}[*]{C.RESET} Checking {self.config['target']}...")
        
        try:
            result = subprocess.run(f"ping -c 1 -W 2 {self.config['target']}",
                                   shell=True, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"{C.GREEN}[+]{C.RESET} Host is UP")
            else:
                print(f"{C.RED}[-]{C.RESET} Host appears DOWN or filtered")
        except:
            print(f"{C.RED}[!]{C.RESET} Check failed")

    
    # ==================== COMANDOS DE DATABASE ====================
    
    def do_hosts(self, arg):
        """Lista todos os hosts/targets conhecidos no banco de dados."""
        from database import get_db
        db = get_db()
        targets = db.get_all_targets()
        
        if not targets:
            print(f"{C.YELLOW}[*]{C.RESET} No hosts in database")
            return
        
        print(f"\n{C.BOLD}Hosts{C.RESET}")
        print(f"{'='*70}\n")
        print(f"{'ID':<4} {'IP':<16} {'Hostname':<15} {'OS':<15} {'Svcs':<5} {'Vulns':<5}")
        print(f"{'-'*4} {'-'*16} {'-'*15} {'-'*15} {'-'*5} {'-'*5}")
        
        for t in targets:
            hostname = (t['hostname'] or "")[:14]
            os_name = (t['os'] or "")[:14]
            print(f"{t['id']:<4} {t['ip']:<16} {hostname:<15} {os_name:<15} {t['service_count']:<5} {t['vuln_count']:<5}")
        
        print(f"\n{C.DIM}Total: {len(targets)} hosts{C.RESET}\n")
    
    def do_services(self, arg):
        """Lista serviços. Uso: services [ip]"""
        from database import get_db
        db = get_db()
        ip = arg.strip() if arg else self.config.get("target")
        services = db.get_services(ip)
        
        if not services:
            print(f"{C.YELLOW}[*]{C.RESET} No services found")
            return
        
        title = f"Services for {ip}" if ip else "All Services"
        print(f"\n{C.BOLD}{title}{C.RESET}")
        print(f"{'='*70}\n")
        print(f"{'IP':<16} {'Port':<7} {'Service':<12} {'Version':<30}")
        print(f"{'-'*16} {'-'*7} {'-'*12} {'-'*30}")
        
        for s in services:
            version = (s['version'] or "")[:29]
            print(f"{s['ip']:<16} {s['port']:<7} {s['service']:<12} {version:<30}")
        
        print(f"\n{C.DIM}Total: {len(services)} services{C.RESET}\n")
    
    def do_vulns(self, arg):
        """Lista vulnerabilidades. Uso: vulns [ip]"""
        from database import get_db
        db = get_db()
        ip = arg.strip() if arg else self.config.get("target")
        vulns = db.get_vulnerabilities(ip)
        
        if not vulns:
            print(f"{C.YELLOW}[*]{C.RESET} No vulnerabilities found")
            return
        
        title = f"Vulnerabilities for {ip}" if ip else "All Vulnerabilities"
        print(f"\n{C.BOLD}{title}{C.RESET}")
        print(f"{'='*80}\n")
        print(f"{'IP':<16} {'Port':<6} {'Name':<35} {'CVE':<18}")
        print(f"{'-'*16} {'-'*6} {'-'*35} {'-'*18}")
        
        for v in vulns:
            name = (v['name'] or "")[:34]
            cve = (v['cve'] or "")[:17]
            port = str(v['port'] or "")
            print(f"{v['ip']:<16} {port:<6} {name:<35} {cve:<18}")
        
        print(f"\n{C.DIM}Total: {len(vulns)} vulnerabilities{C.RESET}\n")
    
    def do_creds(self, arg):
        """Lista credenciais. Uso: creds [ip]"""
        from database import get_db
        db = get_db()
        ip = arg.strip() if arg else self.config.get("target")
        creds = db.get_credentials(ip)
        
        if not creds:
            print(f"{C.YELLOW}[*]{C.RESET} No credentials found")
            return
        
        title = f"Credentials for {ip}" if ip else "All Credentials"
        print(f"\n{C.BOLD}{title}{C.RESET}")
        print(f"{'='*70}\n")
        print(f"{'IP':<16} {'Service':<10} {'Username':<15} {'Password':<20}")
        print(f"{'-'*16} {'-'*10} {'-'*15} {'-'*20}")
        
        for c in creds:
            service = (c['service'] or "")[:9]
            username = (c['username'] or "")[:14]
            password = (c['password'] or "")[:19]
            print(f"{c['ip']:<16} {service:<10} {username:<15} {password:<20}")
        
        print(f"\n{C.DIM}Total: {len(creds)} credentials{C.RESET}\n")
    
    def do_db_status(self, arg):
        """Mostra status do banco de dados."""
        from database import get_db, DEFAULT_DB_PATH
        db = get_db()
        stats = db.get_stats()
        
        print(f"\n{C.BOLD}Database Status{C.RESET}")
        print(f"{'='*40}\n")
        print(f"   Path: {DEFAULT_DB_PATH}")
        print(f"\n   Statistics:")
        print(f"   Targets:         {stats['total_targets']}")
        print(f"   Services:        {stats['total_services']}")
        print(f"   Vulnerabilities: {stats['total_vulns']}")
        print(f"   Credentials:     {stats['total_creds']}")
        print(f"   Operations:      {stats['total_operations']}")
        print()
    
    def do_db_clear(self, arg):
        """Limpa dados do banco de dados. Uso: db_clear [ip|all]"""
        from database import get_db, DEFAULT_DB_PATH, reset_db
        
        if not arg:
            print(f"{C.YELLOW}[*]{C.RESET} Uso: db_clear <ip|all>")
            return
        
        arg = arg.strip()
        
        if arg.lower() == "all":
            confirm = input(f"{C.RED}[!]{C.RESET} This will DELETE ALL data. Type 'yes' to confirm: ")
            if confirm.lower() != 'yes':
                print(f"{C.YELLOW}[*]{C.RESET} Cancelled")
                return
            
            try:
                db = get_db()
                db.close()
                reset_db()
                if DEFAULT_DB_PATH.exists():
                    DEFAULT_DB_PATH.unlink()
                print(f"{C.GREEN}[+]{C.RESET} Database cleared successfully")
            except Exception as e:
                print(f"{C.RED}[!]{C.RESET} Error: {e}")
        else:
            ip = arg
            confirm = input(f"{C.YELLOW}[?]{C.RESET} Delete all data for {ip}? (y/n): ")
            if confirm.lower() not in ['y', 'yes']:
                print(f"{C.YELLOW}[*]{C.RESET} Cancelled")
                return
            
            try:
                db = get_db()
                db.clear_target(ip)
                print(f"{C.GREEN}[+]{C.RESET} Data for {ip} cleared successfully")
            except Exception as e:
                print(f"{C.RED}[!]{C.RESET} Error: {e}")
    
    # ==================== COMANDOS UTILITÁRIOS ====================
    
    def do_clear(self, arg):
        """Limpa a tela."""
        os.system('clear' if os.name != 'nt' else 'cls')
        self._show_banner()
    
    def do_back(self, arg):
        """Limpa o cenário selecionado."""
        self.config["scenario"] = None
        self._update_prompt()
        print(f"{C.YELLOW}[*]{C.RESET} Scenario cleared")
    
    def do_exit(self, arg):
        """Sai do console."""
        print(f"\n{C.CYAN}[*]{C.RESET} Goodbye!\n")
        return True
    
    def do_quit(self, arg):
        """Sai do console."""
        return self.do_exit(arg)
    
    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)
    
    def do_help(self, arg):
        """Mostra ajuda."""
        if arg:
            super().do_help(arg)
        else:
            print(f"""
{C.BOLD}Core Commands{C.RESET}
    set           Set configuration options
    options       Show current configuration
    run/exploit   Execute the attack
    check         Check if target is reachable

{C.BOLD}Info Commands{C.RESET}
    info          Show info about an option (providers, models, modes, stealth)
    providers     List available LLM providers
    models        List models for current/specified provider

{C.BOLD}Scenario Commands{C.RESET}
    scenarios     List all available attack scenarios
    use           Select a scenario
    back          Clear selected scenario

{C.BOLD}PTY Commands (Rubber Ducky){C.RESET}
    pty_spawn     Create interactive PTY session (msfconsole, ftp, ssh, etc.)
    pty_sessions  List active PTY sessions
    pty_send      Send command to PTY session
    pty_type      Type text character by character (rubber ducky style)
    pty_read      Read output from PTY session
    pty_interact  Enter interactive mode with PTY session
    pty_key       Send special key (ctrl_c, tab, etc.)
    pty_close     Close PTY session

{C.BOLD}Database Commands{C.RESET}
    hosts         List all known hosts
    services      List discovered services
    vulns         List vulnerabilities
    creds         List credentials
    db_status     Show database status
    db_clear      Clear database

{C.BOLD}Other Commands{C.RESET}
    clear         Clear screen
    help          Show this help
    exit          Exit the console
""")
    
    def do_info(self, arg):
        """Mostra informações sobre uma opção. Uso: info <providers|models|modes|stealth>"""
        arg = arg.strip().lower()
        
        if not arg:
            print(f"{C.YELLOW}[*]{C.RESET} Uso: info <providers|models|modes|stealth>")
            return
        
        if arg in ["provider", "providers"]:
            self.do_providers("")
        elif arg in ["model", "models"]:
            self.do_models("")
        elif arg in ["mode", "modes"]:
            self.do_modes("")
        elif arg in ["stealth"]:
            self.do_stealth_info("")
        else:
            print(f"{C.RED}[!]{C.RESET} Opção desconhecida: {arg}")
    
    def do_providers(self, arg):
        """Lista todos os providers LLM disponíveis."""
        print(f"\n{C.BOLD}Available LLM Providers:{C.RESET}\n")
        
        current = self.config["provider"]
        
        for provider in self.PROVIDER_MODELS.keys():
            marker = f"{C.GREEN}*{C.RESET}" if provider == current else " "
            model_count = len(self.PROVIDER_MODELS[provider])
            print(f"  {marker} {C.CYAN}{provider:<12}{C.RESET} ({model_count} models)")
        
        print(f"\n{C.DIM}  * = current provider{C.RESET}")
        print(f"{C.DIM}  Use 'set provider <name>' to change{C.RESET}\n")
    
    def do_models(self, arg):
        """Lista modelos disponíveis. Uso: models [provider]"""
        provider = arg.strip().lower() if arg else self.config["provider"]
        
        if provider not in self.PROVIDER_MODELS:
            print(f"{C.RED}[!]{C.RESET} Provider desconhecido: {provider}")
            return
        
        print(f"\n{C.BOLD}Models for {provider}:{C.RESET}\n")
        
        current_model = self.config["model"]
        models = self.PROVIDER_MODELS[provider]
        
        for i, model in enumerate(models):
            marker = f"{C.GREEN}*{C.RESET}" if model == current_model else " "
            default = f" {C.DIM}(default){C.RESET}" if i == 0 else ""
            print(f"  {marker} {C.CYAN}{model}{C.RESET}{default}")
        
        print(f"\n{C.DIM}  * = current model{C.RESET}\n")
    
    def do_modes(self, arg):
        """Lista modos de execução disponíveis."""
        print(f"\n{C.BOLD}Execution Modes:{C.RESET}\n")
        
        current = self.config["mode"]
        
        for mode, description in self.MODE_INFO.items():
            marker = f"{C.GREEN}*{C.RESET}" if mode == current else " "
            print(f"  {marker} {C.CYAN}{mode:<12}{C.RESET} {description}")
        
        print(f"\n{C.DIM}  * = current mode{C.RESET}\n")
    
    def do_stealth_info(self, arg):
        """Mostra informações sobre níveis de stealth."""
        print(f"\n{C.BOLD}Stealth Levels:{C.RESET}\n")
        
        current = self.config["stealth"]
        
        for level, (name, desc) in self.STEALTH_INFO.items():
            marker = f"{C.GREEN}*{C.RESET}" if level == current else " "
            print(f"  {marker} {C.CYAN}{level:<8}{C.RESET} [{name}] {desc}")
        
        print(f"\n{C.DIM}  * = current level{C.RESET}\n")
    
    # ==================== COMANDOS PTY (Rubber Ducky) ====================
    
    def do_pty_spawn(self, arg):
        """Cria uma sessão PTY interativa. Uso: pty_spawn <comando>
        
        Exemplos:
            pty_spawn msfconsole
            pty_spawn ftp 172.20.0.6
            pty_spawn ssh user@172.20.0.6
            pty_spawn bash
        """
        if not arg:
            print(f"{C.RED}[!]{C.RESET} Uso: pty_spawn <comando>")
            print(f"{C.GRAY}    Exemplos: pty_spawn msfconsole, pty_spawn ftp 172.20.0.6{C.RESET}")
            return
        
        try:
            from pty_executor import get_executor
            executor = get_executor()
            session_id = executor.spawn_session(arg)
            print(f"{C.GREEN}[+]{C.RESET} Sessão PTY criada: ID={session_id}")
            print(f"{C.CYAN}[*]{C.RESET} Use 'pty_send {session_id} <comando>' para enviar comandos")
        except Exception as e:
            print(f"{C.RED}[!]{C.RESET} Erro ao criar sessão: {e}")
    
    def do_pty_sessions(self, arg):
        """Lista todas as sessões PTY ativas."""
        try:
            from pty_executor import get_executor
            executor = get_executor()
            sessions = executor.list_sessions()
            
            if not sessions:
                print(f"{C.YELLOW}[*]{C.RESET} Nenhuma sessão PTY ativa")
                return
            
            print(f"\n{C.BOLD}Sessões PTY Ativas:{C.RESET}\n")
            print(f"  {'ID':<4} {'Tipo':<12} {'Status':<8} {'Comando':<40}")
            print(f"  {'-'*4} {'-'*12} {'-'*8} {'-'*40}")
            
            for s in sessions:
                status = f"{C.GREEN}alive{C.RESET}" if s['alive'] else f"{C.RED}dead{C.RESET}"
                cmd = s['command'][:39] if len(s['command']) > 39 else s['command']
                print(f"  {s['id']:<4} {s['type']:<12} {status:<17} {cmd}")
            
            print()
        except Exception as e:
            print(f"{C.RED}[!]{C.RESET} Erro: {e}")
    
    def do_pty_send(self, arg):
        """Envia comando para uma sessão PTY. Uso: pty_send <id> <comando>
        
        Exemplos:
            pty_send 1 use exploit/unix/ftp/vsftpd_234_backdoor
            pty_send 1 set RHOSTS 172.20.0.6
            pty_send 1 run
        """
        args = arg.split(maxsplit=1)
        if len(args) < 2:
            print(f"{C.RED}[!]{C.RESET} Uso: pty_send <session_id> <comando>")
            return
        
        try:
            session_id = int(args[0])
            command = args[1]
            
            from pty_executor import get_executor
            executor = get_executor()
            output, success = executor.send_command(session_id, command)
            
            status = f"{C.GREEN}OK{C.RESET}" if success else f"{C.RED}FAIL{C.RESET}"
            print(f"[{status}] Output:")
            for line in output.split('\n')[:20]:
                print(f"    {C.GRAY}{line}{C.RESET}")
            
            if len(output.split('\n')) > 20:
                print(f"    {C.DIM}... (truncado){C.RESET}")
                
        except ValueError:
            print(f"{C.RED}[!]{C.RESET} ID de sessão inválido")
        except Exception as e:
            print(f"{C.RED}[!]{C.RESET} Erro: {e}")
    
    def do_pty_type(self, arg):
        """Digita texto caractere por caractere (rubber ducky). Uso: pty_type <id> <texto>"""
        args = arg.split(maxsplit=1)
        if len(args) < 2:
            print(f"{C.RED}[!]{C.RESET} Uso: pty_type <session_id> <texto>")
            return
        
        try:
            session_id = int(args[0])
            text = args[1]
            
            from pty_executor import get_executor
            executor = get_executor()
            output = executor.send_keys(session_id, text, delay=0.03)
            
            print(f"{C.GREEN}[+]{C.RESET} Texto digitado")
            if output:
                print(f"    Output: {output[:200]}")
                
        except ValueError:
            print(f"{C.RED}[!]{C.RESET} ID de sessão inválido")
        except Exception as e:
            print(f"{C.RED}[!]{C.RESET} Erro: {e}")
    
    def do_pty_read(self, arg):
        """Lê output de uma sessão PTY. Uso: pty_read <id>"""
        if not arg:
            print(f"{C.RED}[!]{C.RESET} Uso: pty_read <session_id>")
            return
        
        try:
            session_id = int(arg)
            
            from pty_executor import get_executor
            executor = get_executor()
            info = executor.get_session_info(session_id)
            
            if not info:
                print(f"{C.RED}[!]{C.RESET} Sessão não encontrada")
                return
            
            print(f"\n{C.BOLD}Sessão {session_id}:{C.RESET}")
            print(f"  Tipo: {info['type']}")
            print(f"  Comando: {info['command']}")
            print(f"  Status: {'alive' if info['alive'] else 'dead'}")
            print(f"\n{C.BOLD}Último output:{C.RESET}")
            print(info['last_output'] or "(vazio)")
            print()
            
        except ValueError:
            print(f"{C.RED}[!]{C.RESET} ID de sessão inválido")
        except Exception as e:
            print(f"{C.RED}[!]{C.RESET} Erro: {e}")
    
    def do_pty_interact(self, arg):
        """Entra em modo interativo com uma sessão PTY. Uso: pty_interact <id>
        
        Ctrl+] para sair do modo interativo.
        """
        if not arg:
            print(f"{C.RED}[!]{C.RESET} Uso: pty_interact <session_id>")
            return
        
        try:
            session_id = int(arg)
            
            from pty_executor import get_executor
            executor = get_executor()
            
            print(f"{C.YELLOW}[*]{C.RESET} Entrando em modo interativo (Ctrl+] para sair)")
            executor.interact(session_id)
            print(f"{C.CYAN}[*]{C.RESET} Saiu do modo interativo")
            
        except ValueError:
            print(f"{C.RED}[!]{C.RESET} ID de sessão inválido")
        except Exception as e:
            print(f"{C.RED}[!]{C.RESET} Erro: {e}")
    
    def do_pty_close(self, arg):
        """Fecha uma sessão PTY. Uso: pty_close <id|all>"""
        if not arg:
            print(f"{C.RED}[!]{C.RESET} Uso: pty_close <session_id|all>")
            return
        
        try:
            from pty_executor import get_executor
            executor = get_executor()
            
            if arg.lower() == 'all':
                executor.close_all()
                print(f"{C.GREEN}[+]{C.RESET} Todas as sessões fechadas")
            else:
                session_id = int(arg)
                if executor.close_session(session_id):
                    print(f"{C.GREEN}[+]{C.RESET} Sessão {session_id} fechada")
                else:
                    print(f"{C.RED}[!]{C.RESET} Sessão não encontrada")
                    
        except ValueError:
            print(f"{C.RED}[!]{C.RESET} ID de sessão inválido")
        except Exception as e:
            print(f"{C.RED}[!]{C.RESET} Erro: {e}")
    
    def do_pty_key(self, arg):
        """Envia tecla especial para sessão PTY. Uso: pty_key <id> <tecla>
        
        Teclas disponíveis: ctrl_c, ctrl_d, ctrl_z, tab, enter, escape, up, down, left, right
        """
        args = arg.split()
        if len(args) < 2:
            print(f"{C.RED}[!]{C.RESET} Uso: pty_key <session_id> <tecla>")
            print(f"{C.GRAY}    Teclas: ctrl_c, ctrl_d, ctrl_z, tab, enter, escape, up, down{C.RESET}")
            return
        
        try:
            session_id = int(args[0])
            key = args[1]
            
            from pty_executor import get_executor
            executor = get_executor()
            executor.send_special_key(session_id, key)
            print(f"{C.GREEN}[+]{C.RESET} Tecla '{key}' enviada")
            
        except ValueError as e:
            print(f"{C.RED}[!]{C.RESET} Erro: {e}")
        except Exception as e:
            print(f"{C.RED}[!]{C.RESET} Erro: {e}")
    
    def emptyline(self):
        pass
    
    def default(self, line):
        print(f"{C.RED}[!]{C.RESET} Unknown command: {line}")


def run_console():
    """Inicia o console interativo."""
    try:
        console = FragmentumConsole()
        console.cmdloop()
    except KeyboardInterrupt:
        print(f"\n\n{C.CYAN}[*]{C.RESET} Interrupted. Goodbye!\n")


if __name__ == "__main__":
    run_console()
