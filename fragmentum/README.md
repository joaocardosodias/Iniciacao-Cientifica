# FRAGMENTUM 2.0

**AI-Powered Penetration Testing Framework via MCP**

O FRAGMENTUM é um framework de pentesting que funciona como extensão para IAs via MCP (Model Context Protocol). Compatível com Kiro, Claude Desktop, Cursor e qualquer IDE com suporte a MCP.

## Como Funciona

```
┌─────────────────────────────────────────────────────────┐
│                    VOCÊ (no Kiro)                       │
│                                                         │
│  "Escaneia o alvo 172.20.0.6"                          │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                    CLAUDE (IA)                          │
│                                                         │
│  Entende → Chama ferramenta MCP → Retorna resultado    │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              FRAGMENTUM MCP SERVER                      │
│                                                         │
│  nmap_scan(target="172.20.0.6")                        │
│  → Executa: nmap -sV -sC 172.20.0.6                    │
│  → Retorna resultado para a IA                         │
└─────────────────────────────────────────────────────────┘
```

## Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/fragmentum.git
cd fragmentum

# Crie ambiente virtual
python -m venv venv
source venv/bin/activate

# Instale dependências
pip install -r requirements-new.txt
```

## Configuração no Kiro

Adicione ao arquivo `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "fragmentum": {
      "command": "/caminho/para/venv/bin/python",
      "args": ["-m", "fragmentum.mcp.server"],
      "cwd": "/caminho/para/fragmentum"
    }
  }
}
```

Reinicie o Kiro e pronto!

## Ferramentas Disponíveis

| Ferramenta | Descrição |
|------------|-----------|
| `nmap_scan` | Scan de portas e serviços |
| `masscan` | Scan rápido de portas |
| `enum4linux` | Enumeração SMB/Samba |
| `smbmap` | Mapeamento de shares SMB |
| `gobuster` | Brute-force de diretórios web |
| `nikto` | Scanner de vulnerabilidades web |
| `sqlmap` | Detecção de SQL injection |
| `hydra` | Brute-force de credenciais |
| `searchsploit` | Busca de exploits |
| `msf_exploit` | Execução de exploits Metasploit |
| `subfinder` | Descoberta de subdomínios |
| `theharvester` | Coleta de emails/subdomínios |
| `execute_command` | Execução de comandos shell |

## Exemplos de Uso

No chat do Kiro/Claude, você pode pedir:

- "Escaneia o alvo 192.168.1.1"
- "Busca exploits para vsftpd 2.3.4"
- "Enumera os shares SMB do 172.20.0.6"
- "Executa o exploit samba no alvo"
- "Faz brute-force SSH no alvo com usuário root"

## CLI (Debug)

```bash
# Mostra ajuda
python -m fragmentum.cli

# Lista ferramentas
python -m fragmentum.cli --tools

# Inicia servidor MCP (debug)
python -m fragmentum.cli --mcp

# Versão
python -m fragmentum.cli --version
```

## Arquitetura

```
fragmentum/
├── __init__.py          # Módulo principal
├── cli.py               # Interface de linha de comando
├── core/                # Engine e configurações
│   ├── engine.py
│   ├── config.py
│   └── session.py
├── mcp/                 # Servidor MCP
│   ├── __init__.py
│   └── server.py        # 14 ferramentas expostas
└── tools/               # Ferramentas de segurança
    ├── registry.py      # 29 ferramentas registradas
    └── executor.py      # Executor inteligente (PTY/subprocess)
```

## Vantagens sobre HexStrike AI

| Feature | FRAGMENTUM | HexStrike |
|---------|------------|-----------|
| Shell Real | ✅ PTY interativo | ❌ Só output |
| Exploits | ✅ Metasploit integrado | ❌ Limitado |
| Ferramentas | 29+ | 150+ |
| Arquitetura | MCP nativo | MCP adaptado |

## Licença

MIT License
