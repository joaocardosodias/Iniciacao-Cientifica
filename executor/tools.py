


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_nmap",
            "description": (
                "Executa uma varredura de rede com Nmap no alvo especificado. "
                "Use para descobrir hosts, portas abertas e serviços."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP ou hostname do alvo (ex: 10.0.100.2)",
                    },
                    "ports": {
                        "type": "string",
                        "description": (
                            "Portas a escanear. Ex: '22,80,443' ou '1-1000' "
                            "ou '-' para todas. Default: top 1000 portas."
                        ),
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "service", "full", "udp"],
                        "description": (
                            "Tipo de scan: "
                            "quick (-sS top 100), "
                            "service (-sS -sV), "
                            "full (-sS -sV -sC -p-), "
                            "udp (-sU --top-ports 50)"
                        ),
                    },
                    "scripts": {
                        "type": "string",
                        "description": (
                            "Scripts NSE opcionais separados por vírgula. "
                            "Ex: 'ssh-brute,smb-enum-users'"
                        ),
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ssh",
            "description": (
                "Conecta via SSH ao alvo e executa um comando remoto."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP ou hostname do alvo",
                    },
                    "username": {
                        "type": "string",
                        "description": "Usuário para autenticação SSH",
                    },
                    "password": {
                        "type": "string",
                        "description": "Senha para autenticação SSH",
                    },
                    "command": {
                        "type": "string",
                        "description": "Comando a executar no host remoto",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Porta SSH (default: 22)",
                    },
                },
                "required": ["target", "username", "password", "command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_hydra",
            "description": (
                "Executa teste de autenticação (brute force) com Hydra "
                "contra um serviço no alvo."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP ou hostname do alvo",
                    },
                    "service": {
                        "type": "string",
                        "enum": ["ssh", "ftp", "telnet", "smb", "mysql", "postgresql", "http-get", "http-post-form"],
                        "description": "Serviço alvo para teste de autenticação",
                    },
                    "username": {
                        "type": "string",
                        "description": "Usuário único para testar (use OU este OU user_list)",
                    },
                    "user_list": {
                        "type": "string",
                        "description": "Caminho para arquivo com lista de usuários",
                    },
                    "password": {
                        "type": "string",
                        "description": "Senha única para testar (use OU esta OU pass_list)",
                    },
                    "pass_list": {
                        "type": "string",
                        "description": "Caminho para arquivo com lista de senhas",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Porta do serviço (usa default se omitido)",
                    },
                },
                "required": ["target", "service"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_enum4linux",
            "description": (
                "Executa enumeração SMB/NetBIOS contra o alvo usando enum4linux. "
                "Enumera shares, usuários, grupos e políticas."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP ou hostname do alvo",
                    },
                    "options": {
                        "type": "string",
                        "enum": ["all", "users", "shares", "groups", "policies"],
                        "description": (
                            "O que enumerar: "
                            "all (-a), users (-U), shares (-S), "
                            "groups (-G), policies (-P)"
                        ),
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": (
                "Executa um comando shell genérico. Use apenas quando "
                "nenhuma das outras ferramentas específicas se aplica."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Comando shell completo a executar",
                    },
                },
                "required": ["command"],
            },
        },
    },
]




def build_nmap_command(target: str, ports: str = None, scan_type: str = "quick", scripts: str = None) -> list[str]:

    cmd = ["nmap"]

    scan_flags = {
        "quick": ["-sS", "--top-ports", "100"],
        "service": ["-sS", "-sV"],
        "full": ["-sS", "-sV", "-sC", "-p-"],
        "udp": ["-sU", "--top-ports", "50"],
    }
    cmd.extend(scan_flags.get(scan_type, ["-sS"]))

    if ports:
        cmd.extend(["-p", ports])

    if scripts:
        cmd.extend(["--script", scripts])

    cmd.append(target)
    return cmd


def build_ssh_command(target: str, username: str, password: str, command: str, port: int = 22) -> list[str]:

    return [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
        f"{username}@{target}",
        command,
    ]


def build_hydra_command(
    target: str,
    service: str,
    username: str = None,
    user_list: str = None,
    password: str = None,
    pass_list: str = None,
    port: int = None,
) -> list[str]:

    cmd = ["hydra"]

    if username:
        cmd.extend(["-l", username])
    elif user_list:
        cmd.extend(["-L", user_list])
    else:
        cmd.extend(["-l", "admin"])

    if password:
        cmd.extend(["-p", password])
    elif pass_list:
        cmd.extend(["-P", pass_list])
    else:
        cmd.extend(["-P", "/usr/share/wordlists/rockyou.txt"])

    if port:
        cmd.extend(["-s", str(port)])

    cmd.extend([target, service])
    return cmd


def build_enum4linux_command(target: str, options: str = "all") -> list[str]:

    option_flags = {
        "all": "-a",
        "users": "-U",
        "shares": "-S",
        "groups": "-G",
        "policies": "-P",
    }
    flag = option_flags.get(options, "-a")
    return ["enum4linux", flag, target]


def build_shell_command(command: str) -> list[str]:

    return ["bash", "-c", command]



TOOL_BUILDERS = {
    "run_nmap": build_nmap_command,
    "run_ssh": build_ssh_command,
    "run_hydra": build_hydra_command,
    "run_enum4linux": build_enum4linux_command,
    "run_shell": build_shell_command,
}
