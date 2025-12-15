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
        """Exibe banner do sistema."""
        print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}")
        print("=" * 70)
        print("    RED TEAM AUTONOMOUS AGENT - Guardrail Evasion Research")
        print("    IC Project - Context Fragmentation Analysis")
        print("=" * 70)
        print(f"{Colors.RESET}")
    
    @staticmethod
    def config(provider: str, model: str, target: str):
        """Exibe configuração atual."""
        print(f"{Colors.DIM}[CONFIG]{Colors.RESET} Provider: {Colors.CYAN}{provider}{Colors.RESET} | Model: {Colors.CYAN}{model}{Colors.RESET} | Target: {Colors.YELLOW}{target}{Colors.RESET}")
    
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


# Instância global
log = Logger()
