export interface Tool {
  name: string;
  description: string;
  category: string;
  command?: string;  // Command template for preview
  parameters: {
    type: "object";
    properties: Record<string, {
      type: "string" | "number" | "integer" | "boolean";
      description: string;
      default?: any;
    }>;
    required: string[];
  };
}

export interface ToolVariant {
  id: string;
  label: string;
  description: string;
  tool: Tool;
}

export interface ToolGroup {
  id: string;
  name: string;
  description: string;
  category: string;
  isGroup: true;
  variants: ToolVariant[];
  defaultVariant: string;
}

export interface StandaloneTool {
  id: string;
  name: string;
  description: string;
  category: string;
  isGroup: false;
  tool: Tool;
}

export type ToolItem = ToolGroup | StandaloneTool;

export interface Target {
  id: string;
  value: string;
  type: "ip" | "domain" | "cidr";
  created_at: string;
  session_count: number;
}

export interface Session {
  id: string;
  target_id: string;
  target_value: string;
  status: "running" | "completed" | "error";
  started_at: string;
  ended_at?: string;
  findings: Finding[];
  agents?: string[];
}

export interface Finding {
  id: string;
  type: "port" | "service" | "vulnerability" | "credential" | "shell" | "info" | "endpoint" | "technology" | "user" | "subdomain";
  value: any;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  target: string;
  timestamp: string;
  details: Record<string, any>;
}

export interface Job {
  job_id: string;
  tool: string;
  status: "pending" | "running" | "completed" | "error";
  output: string;
  findings: Finding[];
  started_at: string;
  completed_at?: string;
}

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export type ToolCategory = 
  | "scanning" 
  | "enumeration" 
  | "web" 
  | "exploit" 
  | "password" 
  | "osint" 
  | "network" 
  | "cloud" 
  | "binary" 
  | "forensics";

// Shell Manager Types

export type ShellType = "reverse" | "bind";

export type ShellStatus = "connected" | "disconnected" | "idle";

export type ListenerStatus = "active" | "stopped";

export interface ShellConnection {
  id: string;
  target_ip: string;
  target_port: number;
  local_port: number;
  shell_type: ShellType;
  status: ShellStatus;
  is_pty: boolean;
  created_at: string;
  last_activity: string;
  source: string;
}

export interface Listener {
  id: string;
  port: number;
  protocol: "tcp" | "udp";
  status: ListenerStatus;
  connection_count: number;
  created_at: string;
}

export interface HistoryEntry {
  id: string;
  shell_id: string;
  command: string;
  output: string;
  timestamp: string;
}

export interface ShellHistory {
  shell_id: string;
  entries: HistoryEntry[];
}
