import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { ShellConnection, Listener, HistoryEntry } from "@/types";

// Shells
export function useShells() {
  return useQuery<ShellConnection[]>({
    queryKey: ["shells"],
    queryFn: async () => {
      try {
        return await api.getShells();
      } catch (error) {
        console.error("Failed to fetch shells:", error);
        return [];
      }
    },
    refetchInterval: 5000,
  });
}

export function useShell(id: string | null) {
  return useQuery<ShellConnection>({
    queryKey: ["shell", id],
    queryFn: () => api.getShell(id!),
    enabled: !!id,
    refetchInterval: 3000,
  });
}

export function useUpgradeShell() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.upgradeShell(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["shells"] });
    },
  });
}

export function useCloseShell() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.closeShell(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["shells"] });
    },
  });
}

// Shell History
export function useShellHistory(shellId: string | null) {
  return useQuery<HistoryEntry[]>({
    queryKey: ["shellHistory", shellId],
    queryFn: () => api.getShellHistory(shellId!),
    enabled: !!shellId,
  });
}

export function useExportShellHistory() {
  return useMutation({
    mutationFn: async (shellId: string) => {
      const blob = await api.exportShellHistory(shellId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `shell-${shellId}-history.txt`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    },
  });
}

// Listeners
export function useListeners() {
  return useQuery<Listener[]>({
    queryKey: ["listeners"],
    queryFn: async () => {
      try {
        return await api.getListeners();
      } catch (error) {
        console.error("Failed to fetch listeners:", error);
        return [];
      }
    },
    refetchInterval: 5000,
  });
}

export function useCreateListener() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ port, protocol }: { port: number; protocol: "tcp" | "udp" }) =>
      api.createListener(port, protocol),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["listeners"] });
    },
  });
}

export function useStopListener() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.stopListener(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["listeners"] });
    },
  });
}
