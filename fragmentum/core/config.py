"""
Configuração centralizada do FRAGMENTUM
"""

import os
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from pathlib import Path


@dataclass
class LLMConfig:
    """Configuração de LLM"""
    provider: str = "gemini"
    model: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096


@dataclass
class ToolConfig:
    """Configuração de uma ferramenta"""
    name: str
    command: str
    category: str
    timeout: int = 180
    requires_root: bool = False
    description: str = ""


@dataclass
class Config:
    """Configuração global do FRAGMENTUM"""
    
    # Diretórios
    base_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)
    data_dir: Path = field(default_factory=lambda: Path.home() / ".fragmentum")
    
    # LLM
    llm: LLMConfig = field(default_factory=LLMConfig)
    
    # Execução
    max_loops: int = 10
    default_timeout: int = 180
    stealth_level: str = "low"  # low, medium, high
    
    # Rede
    target: Optional[str] = None
    
    # MCP Server
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8888
    
    # Web UI
    web_host: str = "127.0.0.1"
    web_port: int = 3000
    
    # Database
    db_path: Optional[Path] = None
    
    # Propriedades de conveniência
    @property
    def provider(self) -> str:
        """Retorna provider LLM"""
        return self.llm.provider
    
    @property
    def model(self) -> Optional[str]:
        """Retorna modelo LLM"""
        return self.llm.model
    
    def __post_init__(self):
        # Cria diretórios se não existirem
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        if self.db_path is None:
            self.db_path = self.data_dir / "fragmentum.db"
        
        # Carrega variáveis de ambiente
        self._load_env()
    
    def _load_env(self):
        """Carrega configurações de variáveis de ambiente"""
        if provider := os.getenv("LLM_PROVIDER"):
            self.llm.provider = provider
        if model := os.getenv("LLM_MODEL"):
            self.llm.model = model
        if target := os.getenv("TARGET"):
            self.target = target
    
    @classmethod
    def from_file(cls, path: Path) -> "Config":
        """Carrega configuração de arquivo YAML/JSON"""
        import json
        
        if path.suffix == ".json":
            with open(path) as f:
                data = json.load(f)
            return cls(**data)
        
        # TODO: Suporte YAML
        return cls()
    
    def to_dict(self) -> Dict:
        """Converte para dicionário"""
        return {
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.model,
                "temperature": self.llm.temperature,
            },
            "max_loops": self.max_loops,
            "stealth_level": self.stealth_level,
            "target": self.target,
            "mcp_port": self.mcp_port,
            "web_port": self.web_port,
        }


# Instância global
_config: Optional[Config] = None


def get_config() -> Config:
    """Retorna configuração global"""
    global _config
    if _config is None:
        _config = Config()
    return _config


def set_config(config: Config):
    """Define configuração global"""
    global _config
    _config = config
