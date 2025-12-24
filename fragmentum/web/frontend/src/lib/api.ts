import { Tool, Target, Session, Job, Finding, ToolItem, ShellConnection, Listener, HistoryEntry } from "@/types";

const API_BASE = "http://localhost:8000";
const API_KEY = "fragmentum-dev-token-2024"; // Development token

const headers = {
  "Content-Type": "application/json",
  "X-API-Key": API_KEY,
};

export const api = {
  // Tools
  async getTools(): Promise<ToolItem[]> {
    const res = await fetch(`${API_BASE}/api/tools?grouped=true`, { headers });
    if (!res.ok) throw new Error("Failed to fetch tools");
    const data = await res.json();
    return data.tools || [];
  },

  async getTool(name: string): Promise<Tool> {
    const res = await fetch(`${API_BASE}/api/tools/${name}`, { headers });
    if (!res.ok) throw new Error("Failed to fetch tool");
    return res.json();
  },

  async executeTool(tool: string, parameters: Record<string, any>, customCommand?: string): Promise<{ job_id: string; status: string }> {
    const res = await fetch(`${API_BASE}/api/execute`, {
      method: "POST",
      headers,
      body: JSON.stringify({ 
        tool, 
        parameters,
        custom_command: customCommand || null
      }),
    });
    if (!res.ok) throw new Error("Failed to execute tool");
    return res.json();
  },

  async getJobStatus(jobId: string): Promise<Job> {
    const res = await fetch(`${API_BASE}/api/execute/${jobId}`, { headers });
    if (!res.ok) throw new Error("Failed to fetch job status");
    return res.json();
  },

  // Targets
  async getTargets(): Promise<Target[]> {
    const res = await fetch(`${API_BASE}/api/targets`, { headers });
    if (!res.ok) throw new Error("Failed to fetch targets");
    return res.json();
  },

  async addTarget(value: string, type: "ip" | "domain" | "cidr"): Promise<Target> {
    const res = await fetch(`${API_BASE}/api/targets`, {
      method: "POST",
      headers,
      body: JSON.stringify({ value, type }),
    });
    if (!res.ok) throw new Error("Failed to add target");
    return res.json();
  },

  async deleteTarget(id: string): Promise<void> {
    const res = await fetch(`${API_BASE}/api/targets/${id}`, {
      method: "DELETE",
      headers,
    });
    if (!res.ok) throw new Error("Failed to delete target");
  },

  // Sessions
  async getSessions(): Promise<Session[]> {
    const res = await fetch(`${API_BASE}/api/sessions`, { headers });
    if (!res.ok) throw new Error("Failed to fetch sessions");
    return res.json();
  },

  async getSession(id: string): Promise<Session> {
    const res = await fetch(`${API_BASE}/api/sessions/${id}`, { headers });
    if (!res.ok) throw new Error("Failed to fetch session");
    return res.json();
  },

  async exportSession(id: string): Promise<Blob> {
    const res = await fetch(`${API_BASE}/api/sessions/${id}/export`, {
      method: "POST",
      headers,
    });
    if (!res.ok) throw new Error("Failed to export session");
    return res.blob();
  },

  // Swarm
  async startSwarmAttack(target: string, options: {
    enable_exploitation?: boolean;
    enable_password_attacks?: boolean;
    aggressive_mode?: boolean;
  }): Promise<{ session_id: string }> {
    const res = await fetch(`${API_BASE}/api/swarm/attack`, {
      method: "POST",
      headers,
      body: JSON.stringify({ target, ...options }),
    });
    if (!res.ok) throw new Error("Failed to start swarm attack");
    return res.json();
  },

  async getSwarmStatus(sessionId: string): Promise<Session> {
    const res = await fetch(`${API_BASE}/api/swarm/${sessionId}`, { headers });
    if (!res.ok) throw new Error("Failed to fetch swarm status");
    return res.json();
  },

  // Shell
  async executeShell(command: string, timeout: number = 180): Promise<{ job_id: string; status: string }> {
    const res = await fetch(`${API_BASE}/api/shell/execute`, {
      method: "POST",
      headers,
      body: JSON.stringify({ command, timeout }),
    });
    if (!res.ok) throw new Error("Failed to execute shell command");
    return res.json();
  },

  // Shell Manager
  async getShells(): Promise<ShellConnection[]> {
    const res = await fetch(`${API_BASE}/api/shells`, { headers });
    if (!res.ok) throw new Error("Failed to fetch shells");
    return res.json();
  },

  async getShell(id: string): Promise<ShellConnection> {
    const res = await fetch(`${API_BASE}/api/shells/${id}`, { headers });
    if (!res.ok) throw new Error("Failed to fetch shell");
    return res.json();
  },

  async upgradeShell(id: string): Promise<{ success: boolean; is_pty: boolean }> {
    const res = await fetch(`${API_BASE}/api/shells/${id}/upgrade`, {
      method: "POST",
      headers,
    });
    if (!res.ok) throw new Error("Failed to upgrade shell");
    return res.json();
  },

  async closeShell(id: string): Promise<void> {
    const res = await fetch(`${API_BASE}/api/shells/${id}`, {
      method: "DELETE",
      headers,
    });
    if (!res.ok) throw new Error("Failed to close shell");
  },

  async getShellHistory(id: string): Promise<HistoryEntry[]> {
    const res = await fetch(`${API_BASE}/api/shells/${id}/history`, { headers });
    if (!res.ok) throw new Error("Failed to fetch shell history");
    return res.json();
  },

  async exportShellHistory(id: string): Promise<Blob> {
    const res = await fetch(`${API_BASE}/api/shells/${id}/history/export`, { headers });
    if (!res.ok) throw new Error("Failed to export shell history");
    return res.blob();
  },

  // Listeners
  async getListeners(): Promise<Listener[]> {
    const res = await fetch(`${API_BASE}/api/shells/listeners`, { headers });
    if (!res.ok) throw new Error("Failed to fetch listeners");
    return res.json();
  },

  async createListener(port: number, protocol: "tcp" | "udp" = "tcp"): Promise<Listener> {
    const res = await fetch(`${API_BASE}/api/shells/listeners`, {
      method: "POST",
      headers,
      body: JSON.stringify({ port, protocol }),
    });
    if (!res.ok) throw new Error("Failed to create listener");
    return res.json();
  },

  async stopListener(id: string): Promise<void> {
    const res = await fetch(`${API_BASE}/api/shells/listeners/${id}`, {
      method: "DELETE",
      headers,
    });
    if (!res.ok) throw new Error("Failed to stop listener");
  },
};

// WebSocket connections
export const createJobStream = (jobId: string, onMessage: (data: string) => void) => {
  const ws = new WebSocket(`ws://localhost:8000/ws/stream/${jobId}`);
  
  ws.onmessage = (event) => {
    onMessage(event.data);
  };

  ws.onerror = (error) => {
    console.error("WebSocket error:", error);
  };

  return ws;
};

export const createNotificationsStream = (onNotification: (finding: Finding) => void) => {
  const ws = new WebSocket(`ws://localhost:8000/ws/notifications`);

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onNotification(data);
    } catch (e) {
      console.error("Failed to parse notification:", e);
    }
  };

  ws.onerror = (error) => {
    console.error("WebSocket error:", error);
  };

  return ws;
};
