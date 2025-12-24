import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Tool, Target, Session, Job, ToolItem } from "@/types";

// Tools
export function useTools() {
  return useQuery<ToolItem[]>({
    queryKey: ["tools"],
    queryFn: async () => {
      try {
        const response = await api.getTools();
        return response;
      } catch (error) {
        console.error("Failed to fetch tools:", error);
        return [];
      }
    },
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}

export function useTool(name: string) {
  return useQuery({
    queryKey: ["tool", name],
    queryFn: () => api.getTool(name),
    enabled: !!name,
  });
}

// Targets
export function useTargets() {
  return useQuery({
    queryKey: ["targets"],
    queryFn: async () => {
      try {
        return await api.getTargets();
      } catch (error) {
        console.error("Failed to fetch targets:", error);
        return [];
      }
    },
  });
}

export function useAddTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ value, type }: { value: string; type: "ip" | "domain" | "cidr" }) =>
      api.addTarget(value, type),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
  });
}

export function useDeleteTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteTarget(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
  });
}

// Sessions
export function useSessions() {
  return useQuery({
    queryKey: ["sessions"],
    queryFn: async () => {
      try {
        return await api.getSessions();
      } catch (error) {
        console.error("Failed to fetch sessions:", error);
        return [];
      }
    },
    refetchInterval: 5000, // Refetch every 5 seconds for active sessions
  });
}

export function useSession(id: string) {
  return useQuery({
    queryKey: ["session", id],
    queryFn: () => api.getSession(id),
    enabled: !!id,
    refetchInterval: 3000,
  });
}

// Tool Execution
export function useExecuteTool() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tool, parameters, customCommand }: { tool: string; parameters: Record<string, any>; customCommand?: string }) =>
      api.executeTool(tool, parameters, customCommand),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
}

export function useJobStatus(jobId: string | null) {
  return useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.getJobStatus(jobId!),
    enabled: !!jobId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (data?.status === "completed" || data?.status === "error") {
        return false;
      }
      return 1000; // Poll every second while running
    },
  });
}

// Swarm
export function useStartSwarm() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ target, options }: { 
      target: string; 
      options: {
        enable_exploitation?: boolean;
        enable_password_attacks?: boolean;
        aggressive_mode?: boolean;
      }
    }) => api.startSwarmAttack(target, options),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
}

export function useSwarmStatus(sessionId: string | null) {
  return useQuery({
    queryKey: ["swarm", sessionId],
    queryFn: () => api.getSwarmStatus(sessionId!),
    enabled: !!sessionId,
    refetchInterval: 2000,
  });
}

// Shell Execution
export function useExecuteShell() {
  return useMutation({
    mutationFn: ({ command, timeout }: { command: string; timeout?: number }) =>
      api.executeShell(command, timeout),
  });
}

// Stats (computed from other data)
export function useStats() {
  const { data: targets } = useTargets();
  const { data: sessions } = useSessions();

  const allFindings = sessions?.flatMap(s => s.findings || []) || [];

  return {
    totalTargets: targets?.length || 0,
    activeSessions: sessions?.filter(s => s.status === "running").length || 0,
    totalFindings: allFindings.length,
    criticalFindings: allFindings.filter(f => f.severity === "critical").length,
  };
}

// Recent findings
export function useRecentFindings(limit = 20) {
  const { data: sessions } = useSessions();
  
  const allFindings = sessions?.flatMap(s => s.findings || []) || [];
  
  return allFindings
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit);
}
