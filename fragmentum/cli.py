#!/usr/bin/env python3
"""
FRAGMENTUM CLI - Interface de linha de comando

O FRAGMENTUM funciona 100% via MCP (Model Context Protocol).
Use com Kiro, Claude Desktop, Cursor, ou qualquer IDE com suporte a MCP.
"""

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="FRAGMENTUM - AI-Powered Penetration Testing Framework (MCP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
FRAGMENTUM funciona via MCP (Model Context Protocol).

Para usar:
  1. Configure o MCP no seu IDE (Kiro, Claude, Cursor)
  2. Adicione o servidor FRAGMENTUM no mcp.json
  3. Peça para a IA executar ferramentas de pentesting

Exemplos de uso no chat da IA:
  "Escaneia o alvo 192.168.1.1"
  "Busca exploits para vsftpd 2.3.4"
  "Enumera os shares SMB do alvo"
  "Executa o exploit samba no 172.20.0.6"

Comandos disponíveis:
  fragmentum --mcp       Inicia MCP server (para debug)
  fragmentum --tools     Lista ferramentas disponíveis
  fragmentum --version   Mostra versão
        """
    )
    
    parser.add_argument("--mcp", action="store_true", help="Inicia MCP server")
    parser.add_argument("--tools", action="store_true", help="Lista ferramentas")
    parser.add_argument("--version", "-v", action="store_true", help="Mostra versão")
    
    args = parser.parse_args()
    
    if args.version:
        from fragmentum import __version__
        print(f"FRAGMENTUM v{__version__}")
        return
    
    if args.tools:
        from fragmentum.mcp import HAS_MCP
        if HAS_MCP:
            from fragmentum.mcp import FragmentumMCPServer
            server = FragmentumMCPServer()
            print("\nFERRAMENTAS MCP DISPONÍVEIS:")
            print("=" * 50)
            for name, tool in server.tools.items():
                print(f"\n  {name}")
                print(f"    {tool.description}")
        else:
            from fragmentum import get_tool_registry
            registry = get_tool_registry()
            print("\nFERRAMENTAS DISPONÍVEIS:")
            print("=" * 50)
            for tool in registry.list_all():
                print(f"\n  {tool.name} [{tool.category.value}]")
                print(f"    {tool.description}")
        return
    
    if args.mcp:
        from fragmentum.mcp import HAS_MCP
        if not HAS_MCP:
            print("Erro: MCP não instalado")
            print("Execute: pip install mcp")
            sys.exit(1)
        
        print("Iniciando FRAGMENTUM MCP Server...")
        print("O servidor está rodando. Conecte via Kiro/Claude/Cursor.")
        from fragmentum.mcp.server import main as mcp_main
        mcp_main()
        return
    
    # Sem argumentos - mostra ajuda
    print("""
╔═══════════════════════════════════════════════════════════════╗
║           FRAGMENTUM - AI-Powered Pentesting (MCP)            ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  O FRAGMENTUM funciona via MCP (Model Context Protocol).      ║
║  Use com Kiro, Claude Desktop, Cursor ou similar.             ║
║                                                               ║
║  COMO CONFIGURAR:                                             ║
║                                                               ║
║  1. Copie para .kiro/settings/mcp.json:                       ║
║                                                               ║
║     {                                                         ║
║       "mcpServers": {                                         ║
║         "fragmentum": {                                       ║
║           "command": "python",                                ║
║           "args": ["-m", "fragmentum.mcp.server"]             ║
║         }                                                     ║
║       }                                                       ║
║     }                                                         ║
║                                                               ║
║  2. Reinicie o Kiro                                           ║
║                                                               ║
║  3. Peça no chat:                                             ║
║     "Escaneia o alvo 172.20.0.6"                              ║
║     "Busca exploits para samba 3.0.20"                        ║
║                                                               ║
╠═══════════════════════════════════════════════════════════════╣
║  fragmentum --tools    Lista ferramentas                      ║
║  fragmentum --mcp      Inicia servidor (debug)                ║
║  fragmentum --version  Mostra versão                          ║
╚═══════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
