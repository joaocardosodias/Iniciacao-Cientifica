/**
 * Chat Stream Hook
 * 
 * Provides WebSocket connection for real-time chat streaming.
 * Handles SSE/WebSocket events for real-time updates and parses different event types.
 * 
 * Requirements:
 * - 1.3: Display real-time output in chat interface
 * - 4.2: Stream output lines to chat interface
 */

import { useState, useEffect, useCallback, useRef } from "react";
import type { Message, ToolExecutionState, Finding } from "@/components/AIChatPanel";

const WS_BASE = "ws://localhost:8000";

// Event types from backend WebSocket
export interface ChatWSEvent {
  type: 
    | "text" 
    | "tool_start" 
    | "tool_output" 
    | "tool_complete" 
    | "tool_error" 
    | "finding" 
    | "confirmation_required" 
    | "error" 
    | "done"
    | "session_created"
    | "pong";
  content?: string;
  tool_name?: string;
  execution_id?: string;
  output?: string;
  finding?: Finding;
  message?: string;
  summary?: string;
  timestamp?: string;
  session_id?: string;
}

// Client message types
export interface ChatWSClientMessage {
  type: "message" | "confirm" | "cancel" | "ping";
  content?: string;
  execution_id?: string;
  confirmed?: boolean;
}

export type ConnectionStatus = "connecting" | "connected" | "disconnected" | "error";

interface UseChatStreamOptions {
  sessionId: string | null;
  onMessage?: (event: ChatWSEvent) => void;
  onSessionCreated?: (sessionId: string) => void;
  autoReconnect?: boolean;
  reconnectInterval?: number;
}

interface UseChatStreamReturn {
  status: ConnectionStatus;
  sendMessage: (content: string) => void;
  confirmExecution: (executionId: string, confirmed: boolean) => void;
  disconnect: () => void;
  reconnect: () => void;
}

/**
 * Generate unique ID for messages
 */
function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * WebSocket-based chat stream hook
 * 
 * Provides bidirectional real-time communication for chat.
 * Automatically handles reconnection and message parsing.
 * 
 * Requirements: 1.3, 4.2
 */
export function useChatStream({
  sessionId,
  onMessage,
  onSessionCreated,
  autoReconnect = true,
  reconnectInterval = 5000,
}: UseChatStreamOptions): UseChatStreamReturn {
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  /**
   * Clear all timers
   */
  const clearTimers = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
  }, []);

  /**
   * Connect to WebSocket
   */
  const connect = useCallback(() => {
    if (!sessionId) return;
    
    // Close existing connection
    if (wsRef.current) {
      wsRef.current.close();
    }

    clearTimers();
    setStatus("connecting");

    try {
      const ws = new WebSocket(`${WS_BASE}/api/chat/ws/${sessionId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus("connected");
        console.log("[ChatWS] Connected to session:", sessionId);

        // Start ping interval to keep connection alive
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "ping" }));
          }
        }, 30000);
      };

      ws.onclose = (event) => {
        setStatus("disconnected");
        console.log("[ChatWS] Disconnected:", event.code, event.reason);
        clearTimers();

        // Auto-reconnect if enabled and not a clean close
        if (autoReconnect && event.code !== 1000) {
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log("[ChatWS] Attempting reconnect...");
            connect();
          }, reconnectInterval);
        }
      };

      ws.onerror = (error) => {
        setStatus("error");
        console.error("[ChatWS] Error:", error);
      };

      ws.onmessage = (event) => {
        try {
          const data: ChatWSEvent = JSON.parse(event.data);
          
          // Handle session creation
          if (data.type === "session_created" && data.session_id) {
            onSessionCreated?.(data.session_id);
          }
          
          // Forward all events to callback
          onMessage?.(data);
        } catch (e) {
          console.error("[ChatWS] Failed to parse message:", e);
        }
      };
    } catch (e) {
      setStatus("error");
      console.error("[ChatWS] Connection error:", e);
    }
  }, [sessionId, autoReconnect, reconnectInterval, onMessage, onSessionCreated, clearTimers]);

  /**
   * Disconnect from WebSocket
   */
  const disconnect = useCallback(() => {
    clearTimers();
    if (wsRef.current) {
      wsRef.current.close(1000, "User disconnected");
      wsRef.current = null;
    }
    setStatus("disconnected");
  }, [clearTimers]);

  /**
   * Reconnect to WebSocket
   */
  const reconnect = useCallback(() => {
    disconnect();
    connect();
  }, [disconnect, connect]);

  /**
   * Send a chat message
   */
  const sendMessage = useCallback((content: string) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      console.error("[ChatWS] Cannot send message: not connected");
      return;
    }

    const message: ChatWSClientMessage = {
      type: "message",
      content,
    };

    wsRef.current.send(JSON.stringify(message));
  }, []);

  /**
   * Confirm or cancel a pending execution
   */
  const confirmExecution = useCallback((executionId: string, confirmed: boolean) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      console.error("[ChatWS] Cannot confirm: not connected");
      return;
    }

    const message: ChatWSClientMessage = {
      type: "confirm",
      execution_id: executionId,
      confirmed,
    };

    wsRef.current.send(JSON.stringify(message));
  }, []);

  // Connect when sessionId changes
  useEffect(() => {
    if (sessionId) {
      connect();
    } else {
      disconnect();
    }

    return () => {
      disconnect();
    };
  }, [sessionId]); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    status,
    sendMessage,
    confirmExecution,
    disconnect,
    reconnect,
  };
}

/**
 * Hook for managing chat messages with WebSocket streaming
 * 
 * Combines WebSocket connection with message state management.
 * Provides a complete solution for real-time chat.
 */
export function useChatStreamWithMessages(sessionId: string | null) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const currentToolExecutionRef = useRef<ToolExecutionState | null>(null);
  const assistantContentRef = useRef<string>("");
  const assistantMessageIdRef = useRef<string>("");

  /**
   * Handle incoming WebSocket events
   */
  const handleMessage = useCallback((event: ChatWSEvent) => {
    switch (event.type) {
      case "text":
        if (event.content) {
          assistantContentRef.current += event.content;
          
          setMessages((prev) => {
            const existing = prev.find((m) => m.id === assistantMessageIdRef.current);
            if (existing) {
              return prev.map((m) =>
                m.id === assistantMessageIdRef.current
                  ? { ...m, content: assistantContentRef.current }
                  : m
              );
            } else {
              assistantMessageIdRef.current = generateId();
              return [
                ...prev,
                {
                  id: assistantMessageIdRef.current,
                  role: "assistant" as const,
                  content: assistantContentRef.current,
                  timestamp: event.timestamp || new Date().toISOString(),
                },
              ];
            }
          });
        }
        break;

      case "tool_start":
        currentToolExecutionRef.current = {
          id: event.execution_id || generateId(),
          toolName: event.tool_name || "unknown",
          status: "running",
          output: [],
          startedAt: event.timestamp || new Date().toISOString(),
        };
        setMessages((prev) => [
          ...prev,
          {
            id: currentToolExecutionRef.current!.id,
            role: "tool",
            content: "",
            timestamp: event.timestamp || new Date().toISOString(),
            toolExecution: { ...currentToolExecutionRef.current! },
          },
        ]);
        break;

      case "tool_output":
        if (currentToolExecutionRef.current && event.output) {
          currentToolExecutionRef.current.output.push(event.output);
          setMessages((prev) =>
            prev.map((m) =>
              m.id === currentToolExecutionRef.current?.id
                ? {
                    ...m,
                    toolExecution: {
                      ...currentToolExecutionRef.current!,
                      output: [...currentToolExecutionRef.current!.output],
                    },
                  }
                : m
            )
          );
        }
        break;

      case "tool_complete":
        if (currentToolExecutionRef.current) {
          currentToolExecutionRef.current.status = "completed";
          currentToolExecutionRef.current.completedAt = event.timestamp || new Date().toISOString();
          setMessages((prev) =>
            prev.map((m) =>
              m.id === currentToolExecutionRef.current?.id
                ? {
                    ...m,
                    toolExecution: { ...currentToolExecutionRef.current! },
                  }
                : m
            )
          );
          
          // Add summary as assistant message
          if (event.summary) {
            assistantMessageIdRef.current = generateId();
            assistantContentRef.current = event.summary;
            setMessages((prev) => [
              ...prev,
              {
                id: assistantMessageIdRef.current,
                role: "assistant",
                content: event.summary!,
                timestamp: event.timestamp || new Date().toISOString(),
              },
            ]);
          }
          currentToolExecutionRef.current = null;
        }
        break;

      case "tool_error":
        if (currentToolExecutionRef.current) {
          currentToolExecutionRef.current.status = "error";
          currentToolExecutionRef.current.error = event.message;
          currentToolExecutionRef.current.completedAt = event.timestamp || new Date().toISOString();
          setMessages((prev) =>
            prev.map((m) =>
              m.id === currentToolExecutionRef.current?.id
                ? {
                    ...m,
                    toolExecution: { ...currentToolExecutionRef.current! },
                  }
                : m
            )
          );
          currentToolExecutionRef.current = null;
        }
        break;

      case "finding":
        if (event.finding) {
          setMessages((prev) => {
            const lastIdx = prev.length - 1;
            if (lastIdx >= 0) {
              const last = prev[lastIdx];
              return [
                ...prev.slice(0, lastIdx),
                {
                  ...last,
                  findings: [...(last.findings || []), event.finding!],
                },
              ];
            }
            return prev;
          });
        }
        break;

      case "confirmation_required":
        if (currentToolExecutionRef.current) {
          currentToolExecutionRef.current.status = "pending";
          currentToolExecutionRef.current.requiresConfirmation = true;
          currentToolExecutionRef.current.confirmationMessage = event.message;
          setMessages((prev) =>
            prev.map((m) =>
              m.id === currentToolExecutionRef.current?.id
                ? {
                    ...m,
                    toolExecution: { ...currentToolExecutionRef.current! },
                  }
                : m
            )
          );
        }
        break;

      case "error":
        setMessages((prev) => [
          ...prev,
          {
            id: generateId(),
            role: "system",
            content: event.message || "An error occurred",
            timestamp: event.timestamp || new Date().toISOString(),
          },
        ]);
        setIsLoading(false);
        break;

      case "done":
        setIsLoading(false);
        // Reset refs for next message
        assistantContentRef.current = "";
        assistantMessageIdRef.current = "";
        break;
    }
  }, []);

  const { status, sendMessage: wsSendMessage, confirmExecution, disconnect, reconnect } = useChatStream({
    sessionId,
    onMessage: handleMessage,
  });

  /**
   * Send a user message
   */
  const sendMessage = useCallback((content: string) => {
    if (!content.trim()) return;

    // Add user message immediately
    const userMessage: Message = {
      id: generateId(),
      role: "user",
      content: content.trim(),
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMessage]);
    setIsLoading(true);

    // Reset refs for new response
    assistantContentRef.current = "";
    assistantMessageIdRef.current = "";

    // Send via WebSocket
    wsSendMessage(content.trim());
  }, [wsSendMessage]);

  /**
   * Clear all messages
   */
  const clearMessages = useCallback(() => {
    setMessages([]);
    assistantContentRef.current = "";
    assistantMessageIdRef.current = "";
    currentToolExecutionRef.current = null;
  }, []);

  return {
    messages,
    isLoading,
    status,
    sendMessage,
    confirmExecution,
    clearMessages,
    disconnect,
    reconnect,
  };
}

/**
 * SSE-based chat stream hook (alternative to WebSocket)
 * 
 * Uses Server-Sent Events for one-way streaming from server.
 * Useful when WebSocket is not available or for simpler use cases.
 */
export function useSSEChatStream() {
  const [isStreaming, setIsStreaming] = useState(false);
  const abortControllerRef = useRef<AbortController | null>(null);

  /**
   * Start streaming a chat response
   */
  const startStream = useCallback(async (
    content: string,
    sessionId: string | null,
    onEvent: (event: ChatWSEvent) => void,
  ): Promise<string | null> => {
    // Cancel any existing stream
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();

    setIsStreaming(true);
    let newSessionId: string | null = null;

    try {
      const response = await fetch("http://localhost:8000/api/chat/message", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": "fragmentum-dev-token-2024",
        },
        body: JSON.stringify({
          content,
          session_id: sessionId,
        }),
        signal: abortControllerRef.current.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      // Get session ID from response header
      newSessionId = response.headers.get("X-Session-Id");

      // Process SSE stream
      const reader = response.body?.getReader();
      if (!reader) throw new Error("No response body");

      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const event: ChatWSEvent = JSON.parse(line.slice(6));
              onEvent(event);
            } catch (e) {
              console.error("Failed to parse SSE event:", e);
            }
          }
        }
      }
    } catch (error) {
      if ((error as Error).name !== "AbortError") {
        onEvent({
          type: "error",
          message: (error as Error).message,
        });
      }
    } finally {
      setIsStreaming(false);
      abortControllerRef.current = null;
    }

    return newSessionId;
  }, []);

  /**
   * Cancel the current stream
   */
  const cancelStream = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setIsStreaming(false);
    }
  }, []);

  return {
    isStreaming,
    startStream,
    cancelStream,
  };
}
