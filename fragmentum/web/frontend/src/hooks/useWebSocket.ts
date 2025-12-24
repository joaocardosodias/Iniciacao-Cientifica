import { useState, useEffect, useCallback } from "react";
import { Finding } from "@/types";
import { toast } from "@/hooks/use-toast";

export const useWebSocket = () => {
  const [isConnected, setIsConnected] = useState(false);
  const [notifications, setNotifications] = useState<Finding[]>([]);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;

    const connect = () => {
      try {
        ws = new WebSocket("ws://localhost:8000/ws/notifications");

        ws.onopen = () => {
          setIsConnected(true);
          console.log("[WS] Connected to notifications");
        };

        ws.onclose = () => {
          setIsConnected(false);
          console.log("[WS] Disconnected, reconnecting in 5s...");
          reconnectTimeout = setTimeout(connect, 5000);
        };

        ws.onerror = () => {
          setIsConnected(false);
        };

        ws.onmessage = (event) => {
          try {
            const finding: Finding = JSON.parse(event.data);
            setNotifications(prev => [finding, ...prev].slice(0, 50));
            
            if (finding.severity === "critical" || finding.severity === "high") {
              toast({
                title: `${finding.severity.toUpperCase()} Finding`,
                description: `${finding.type}: ${typeof finding.value === "string" ? finding.value : JSON.stringify(finding.value)}`,
                variant: finding.severity === "critical" ? "destructive" : "default",
              });
            }
          } catch (e) {
            console.error("[WS] Failed to parse message:", e);
          }
        };
      } catch (e) {
        console.error("[WS] Connection error:", e);
        reconnectTimeout = setTimeout(connect, 5000);
      }
    };

    connect();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  return { isConnected, notifications };
};

interface JobStreamMessage {
  type: "connected" | "output" | "finding" | "status" | "error";
  data: {
    output?: string;
    append?: boolean;
    status?: string;
    message?: string;
    [key: string]: any;
  };
  timestamp: string;
  job_id: string;
}

export const useJobStream = (jobId: string | null) => {
  const [output, setOutput] = useState<string[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);

  const clearOutput = useCallback(() => {
    setOutput([]);
    setFindings([]);
  }, []);

  useEffect(() => {
    if (!jobId) return;

    setOutput([]);
    setFindings([]);
    setIsStreaming(true);

    const ws = new WebSocket(`ws://localhost:8000/ws/stream/${jobId}`);

    ws.onopen = () => {
      console.log(`[WS] Connected to job stream: ${jobId}`);
    };

    ws.onmessage = (event) => {
      try {
        const message: JobStreamMessage = JSON.parse(event.data);
        
        switch (message.type) {
          case "connected":
            // Connection confirmed, no output needed
            break;
            
          case "output":
            if (message.data.output) {
              // Remove trailing newline and add as new line
              const text = message.data.output.replace(/\n$/, "");
              if (text) {
                setOutput(prev => [...prev, text]);
              }
            }
            break;
            
          case "finding":
            if (message.data) {
              setFindings(prev => [...prev, message.data as unknown as Finding]);
              // Show toast for important findings
              const finding = message.data;
              if (finding.severity === "critical" || finding.severity === "high") {
                toast({
                  title: `${String(finding.severity).toUpperCase()} Finding`,
                  description: `${finding.type}: ${typeof finding.value === "string" ? finding.value : JSON.stringify(finding.value)}`,
                  variant: finding.severity === "critical" ? "destructive" : "default",
                });
              }
            }
            break;
            
          case "status":
            if (message.data.status === "completed" || message.data.status === "error") {
              setIsStreaming(false);
            }
            break;
            
          case "error":
            setOutput(prev => [...prev, `[ERROR] ${message.data.message || "Unknown error"}`]);
            setIsStreaming(false);
            break;
        }
      } catch (e) {
        // If not JSON, add raw text (fallback)
        console.error("[WS] Failed to parse message:", e);
        setOutput(prev => [...prev, event.data]);
      }
    };

    ws.onclose = () => {
      setIsStreaming(false);
      console.log(`[WS] Job stream closed: ${jobId}`);
    };

    ws.onerror = () => {
      setIsStreaming(false);
    };

    return () => {
      ws.close();
    };
  }, [jobId]);

  return { output, isStreaming, clearOutput, findings };
};
