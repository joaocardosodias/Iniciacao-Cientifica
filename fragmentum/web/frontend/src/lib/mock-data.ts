import { Tool, Target, Session, Finding } from "@/types";

export const mockTools: Tool[] = [
  {
    name: "nmap_scan",
    description: "Executa scan de portas e serviços com nmap",
    category: "scanning",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "IP ou hostname do alvo" },
        ports: { type: "string", description: "Portas", default: "1-1000" },
        options: { type: "string", description: "Opções extras", default: "-sV -sC" }
      },
      required: ["target"]
    }
  },
  {
    name: "gobuster",
    description: "Brute-force de diretórios web",
    category: "web",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "URL do alvo" },
        wordlist: { type: "string", description: "Wordlist", default: "/usr/share/wordlists/dirb/common.txt" },
        threads: { type: "integer", description: "Threads", default: 50 }
      },
      required: ["target"]
    }
  },
  {
    name: "hydra",
    description: "Brute-force de credenciais",
    category: "password",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "IP do alvo" },
        service: { type: "string", description: "Serviço (ssh, ftp, etc)" },
        user: { type: "string", description: "Usuário" },
        wordlist: { type: "string", description: "Wordlist", default: "/usr/share/wordlists/rockyou.txt" }
      },
      required: ["target", "service", "user"]
    }
  },
  {
    name: "nikto",
    description: "Scanner de vulnerabilidades web",
    category: "web",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "URL do alvo" },
        ssl: { type: "boolean", description: "Usar SSL", default: false }
      },
      required: ["target"]
    }
  },
  {
    name: "sqlmap",
    description: "Detecção e exploração de SQL Injection",
    category: "exploit",
    parameters: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL com parâmetro vulnerável" },
        data: { type: "string", description: "POST data" },
        level: { type: "integer", description: "Nível de testes (1-5)", default: 1 }
      },
      required: ["url"]
    }
  },
  {
    name: "theHarvester",
    description: "OSINT - coleta de emails e subdomínios",
    category: "osint",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Domínio alvo" },
        source: { type: "string", description: "Fonte de dados", default: "all" }
      },
      required: ["domain"]
    }
  },
  {
    name: "enum4linux",
    description: "Enumeração de sistemas Windows/Samba",
    category: "enumeration",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "IP do alvo" },
        all: { type: "boolean", description: "Executar todas as opções", default: true }
      },
      required: ["target"]
    }
  },
  {
    name: "masscan",
    description: "Scanner de portas ultra-rápido",
    category: "scanning",
    parameters: {
      type: "object",
      properties: {
        target: { type: "string", description: "IP ou range CIDR" },
        ports: { type: "string", description: "Portas", default: "0-65535" },
        rate: { type: "integer", description: "Pacotes por segundo", default: 10000 }
      },
      required: ["target"]
    }
  }
];

export const mockTargets: Target[] = [
  { id: "1", value: "192.168.1.100", type: "ip", created_at: "2024-01-15T10:30:00Z", session_count: 3 },
  { id: "2", value: "10.0.0.0/24", type: "cidr", created_at: "2024-01-14T08:00:00Z", session_count: 1 },
  { id: "3", value: "example.com", type: "domain", created_at: "2024-01-13T14:20:00Z", session_count: 5 },
  { id: "4", value: "192.168.1.50", type: "ip", created_at: "2024-01-12T09:15:00Z", session_count: 2 },
];

export const mockFindings: Finding[] = [
  {
    id: "f1",
    type: "vulnerability",
    value: "CVE-2024-1234",
    severity: "critical",
    source: "nmap_scan",
    target: "192.168.1.100",
    timestamp: "2024-01-15T10:35:00Z",
    details: { description: "Remote Code Execution in Apache Struts", cvss: 9.8 }
  },
  {
    id: "f2",
    type: "port",
    value: { port: 22, service: "ssh", version: "OpenSSH 7.4" },
    severity: "info",
    source: "nmap_scan",
    target: "192.168.1.100",
    timestamp: "2024-01-15T10:32:00Z",
    details: {}
  },
  {
    id: "f3",
    type: "credential",
    value: { username: "admin", password: "admin123" },
    severity: "critical",
    source: "hydra",
    target: "192.168.1.50",
    timestamp: "2024-01-15T11:00:00Z",
    details: { service: "ssh" }
  },
  {
    id: "f4",
    type: "vulnerability",
    value: "SQL Injection",
    severity: "high",
    source: "sqlmap",
    target: "example.com",
    timestamp: "2024-01-15T09:45:00Z",
    details: { parameter: "id", url: "https://example.com/users?id=1" }
  },
  {
    id: "f5",
    type: "endpoint",
    value: "/admin/login",
    severity: "medium",
    source: "gobuster",
    target: "example.com",
    timestamp: "2024-01-15T09:30:00Z",
    details: { status: 200 }
  },
  {
    id: "f6",
    type: "service",
    value: { port: 3306, service: "mysql", version: "5.7.32" },
    severity: "low",
    source: "nmap_scan",
    target: "192.168.1.100",
    timestamp: "2024-01-15T10:33:00Z",
    details: {}
  }
];

export const mockSessions: Session[] = [
  {
    id: "sess-001",
    target_id: "1",
    target_value: "192.168.1.100",
    status: "running",
    started_at: "2024-01-15T10:30:00Z",
    findings: mockFindings.filter(f => f.target === "192.168.1.100"),
    agents: ["ReconAgent", "NetworkAgent", "ExploitAgent"]
  },
  {
    id: "sess-002",
    target_id: "3",
    target_value: "example.com",
    status: "completed",
    started_at: "2024-01-14T14:00:00Z",
    ended_at: "2024-01-14T15:30:00Z",
    findings: mockFindings.filter(f => f.target === "example.com"),
    agents: ["WebAgent", "OSINTAgent"]
  },
  {
    id: "sess-003",
    target_id: "4",
    target_value: "192.168.1.50",
    status: "completed",
    started_at: "2024-01-13T09:00:00Z",
    ended_at: "2024-01-13T10:00:00Z",
    findings: mockFindings.filter(f => f.target === "192.168.1.50"),
    agents: ["PasswordAgent"]
  }
];

export const mockStats = {
  totalTargets: mockTargets.length,
  activeSessions: mockSessions.filter(s => s.status === "running").length,
  totalFindings: mockFindings.length,
  criticalFindings: mockFindings.filter(f => f.severity === "critical").length
};
