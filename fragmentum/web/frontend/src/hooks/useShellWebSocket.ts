import { useState, useEffect, useCallback, useRef } from "react";

interface ShellWebSocketMessage {
  type: "connected" | "output" | "error" | "disconnected";
  data?: string;
  message?: string;
}

interface UseShellWebSocketOptions {
  onOutput?: (data: string) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: string) => void;
}

export function useShellWebSocket(
  shellId: string | null,
  options: UseShellWebSocketOptions = {}
) {
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const maxReconnectAttempts = 5;

  const { onOutput, onConnect, onDisconnect, onError } = options;

  const connect = useCallback(() => {
    if (!shellId) return;

    // Check reconnect limit
    if (reconnectAttemptsRef.current >= maxReconnectAttempts) {
      console.log(`[ShellWS] Max reconnect attempts reached for shell: ${shellId}`);
      setError("Connection failed after multiple attempts");
      return;
    }

    try {
      const ws = new WebSocket(`ws://localhost:8000/ws/shell/${shellId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        setError(null);
        reconnectAttemptsRef.current = 0; // Reset on successful connection
        console.log(`[ShellWS] Connected to shell: ${shellId}`);
        onConnect?.();
      };

      ws.onclose = (event) => {
        setIsConnected(false);
        console.log(`[ShellWS] Disconnected from shell: ${shellId}, code: ${event.code}`);
        onDisconnect?.();

        // Don't reconnect if closed normally or shell not found
        if (event.code === 4004 || event.code === 4003 || event.code === 1000) {
          setError(event.reason || "Shell not available");
          return;
        }

        // Attempt reconnection after 3 seconds
        reconnectAttemptsRef.current++;
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectTimeoutRef.current = setTimeout(() => {
            if (shellId) {
              console.log(`[ShellWS] Attempting reconnection (${reconnectAttemptsRef.current}/${maxReconnectAttempts})...`);
              connect();
            }
          }, 3000);
        }
      };

      ws.onerror = () => {
        setIsConnected(false);
        const errorMsg = "WebSocket connection error";
        setError(errorMsg);
        onError?.(errorMsg);
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);

          switch (message.type) {
            case "connected":
              console.log(`[ShellWS] Shell connection confirmed`);
              break;

            case "output":
              // Backend sends: {"type": "output", "data": {"output": "..."}}
              const output = message.data?.output || message.data;
              if (output) {
                onOutput?.(output);
              }
              break;

            case "error":
              const errorMsg = message.data?.error || message.message || "Unknown error";
              setError(errorMsg);
              onError?.(errorMsg);
              break;

            case "status":
              // Handle status updates
              if (message.data?.status === "disconnected") {
                setIsConnected(false);
                onDisconnect?.();
              }
              break;

            case "disconnected":
              setIsConnected(false);
              onDisconnect?.();
              break;
          }
        } catch {
          // If not JSON, treat as raw output
          onOutput?.(event.data);
        }
      };
    } catch (e) {
      console.error("[ShellWS] Connection error:", e);
      setError("Failed to connect to shell");
    }
  }, [shellId, onOutput, onConnect, onDisconnect, onError]);

  // Connect when shellId changes
  useEffect(() => {
    if (shellId) {
      connect();
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
    };
  }, [shellId, connect]);

  // Send input to shell
  const sendInput = useCallback((data: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "input", data }));
    }
  }, []);

  // Send special key (Ctrl+C, Tab, arrows, etc.)
  const sendSpecialKey = useCallback((key: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "special", key }));
    }
  }, []);

  // Send terminal resize event
  const sendResize = useCallback((cols: number, rows: number) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "resize", cols, rows }));
    }
  }, []);

  // Disconnect manually
  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsConnected(false);
  }, []);

  return {
    isConnected,
    error,
    sendInput,
    sendSpecialKey,
    sendResize,
    disconnect,
  };
}
