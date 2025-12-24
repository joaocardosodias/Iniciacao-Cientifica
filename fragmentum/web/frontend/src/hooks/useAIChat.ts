/**
 * AI Chat Hook
 * 
 * Provides state management and API interactions for the AI chat feature.
 * Handles message sending with streaming, session management, and configuration.
 * 
 * Requirements:
 * - 1.1: Interpret user intent and respond appropriately
 * - 5.2: Restore previous conversation history
 */

import { useState, useCallback, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { Message, ToolExecutionState, Finding } from "@/components/AIChatPanel";

const API_BASE = "http://localhost:8000";
const API_KEY = "fragmentum-dev-token-2024";

const headers = {
  "Content-Type": "application/json",
  "X-API-Key": API_KEY,
};

// Types for chat API
export interface ChatSession {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  messages: ChatMessage[];
  metadata: Record<string, unknown>;
}

export interface ChatSessionSummary {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  message_count: number;
  last_message_preview?: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  timestamp: string;
  tool_calls?: ToolCall[];
  tool_execution?: ToolExecution;
}

export interface ToolCall {
  id: string;
  name: string;
  parameters: Record<string, unknown>;
}

export interface ToolExecution {
  tool_name: string;
  parameters: Record<string, unknown>;
  status: "pending" | "running" | "completed" | "error";
  output: string[];
  findings: Finding[];
  started_at: string;
  completed_at?: string;
  error?: string;
  summary?: string;
}

export interface ChatConfig {
  provider: "claude" | "openai" | "ollama";
  model: string;
  ollama_url?: string;
  temperature: number;
  max_tokens: number;
}

export interface ChatConfigUpdate {
  provider?: "claude" | "openai" | "ollama";
  model?: string;
  api_key?: string;
  ollama_url?: string;
  temperature?: number;
  max_tokens?: number;
}

export interface ConfigStatus {
  configured: boolean;
  provider: string;
  model: string;
  has_api_key: boolean;
  message?: string;
}

// SSE Event types from backend
export interface ChatStreamEvent {
  type: "text" | "tool_start" | "tool_output" | "tool_complete" | "tool_error" | "finding" | "confirmation_required" | "error" | "done";
  content?: string;
  tool_name?: string;
  execution_id?: string;
  output?: string;
  finding?: Finding;
  message?: string;
  summary?: string;
  timestamp?: string;
}

// Chat API functions
const chatApi = {
  async getSessions(limit = 50, offset = 0): Promise<{ sessions: ChatSessionSummary[]; total: number }> {
    const res = await fetch(`${API_BASE}/api/chat/sessions?limit=${limit}&offset=${offset}`, { headers });
    if (!res.ok) throw new Error("Failed to fetch sessions");
    return res.json();
  },

  async getSession(sessionId: string): Promise<ChatSession> {
    const res = await fetch(`${API_BASE}/api/chat/sessions/${sessionId}`, { headers });
    if (!res.ok) throw new Error("Failed to fetch session");
    return res.json();
  },

  async createSession(title?: string): Promise<ChatSession> {
    const url = title 
      ? `${API_BASE}/api/chat/sessions?title=${encodeURIComponent(title)}`
      : `${API_BASE}/api/chat/sessions`;
    const res = await fetch(url, { method: "POST", headers });
    if (!res.ok) throw new Error("Failed to create session");
    return res.json();
  },

  async deleteSession(sessionId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/api/chat/sessions/${sessionId}`, { 
      method: "DELETE", 
      headers 
    });
    if (!res.ok) throw new Error("Failed to delete session");
  },

  async getConfig(): Promise<ChatConfig> {
    const res = await fetch(`${API_BASE}/api/chat/config`, { headers });
    if (!res.ok) throw new Error("Failed to fetch config");
    return res.json();
  },

  async updateConfig(config: ChatConfigUpdate): Promise<ChatConfig> {
    const res = await fetch(`${API_BASE}/api/chat/config`, {
      method: "PUT",
      headers,
      body: JSON.stringify(config),
    });
    if (!res.ok) throw new Error("Failed to update config");
    return res.json();
  },

  async getConfigStatus(): Promise<ConfigStatus> {
    const res = await fetch(`${API_BASE}/api/chat/config/status`, { headers });
    if (!res.ok) throw new Error("Failed to fetch config status");
    return res.json();
  },

  async confirmExecution(executionId: string, confirmed: boolean): Promise<Response> {
    return fetch(`${API_BASE}/api/chat/confirm/${executionId}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ confirmed }),
    });
  },
};

// Generate unique ID for messages
function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Convert backend message to frontend format
function convertMessage(msg: ChatMessage): Message {
  const message: Message = {
    id: msg.id,
    role: msg.role,
    content: msg.content,
    timestamp: msg.timestamp,
  };

  if (msg.tool_execution) {
    message.toolExecution = {
      id: msg.id,
      toolName: msg.tool_execution.tool_name,
      status: msg.tool_execution.status,
      output: msg.tool_execution.output,
      startedAt: msg.tool_execution.started_at,
      completedAt: msg.tool_execution.completed_at,
      error: msg.tool_execution.error,
    };
    message.findings = msg.tool_execution.findings;
  }

  return message;
}

/**
 * Main AI Chat hook
 * 
 * Provides complete chat functionality including:
 * - Message state management
 * - Streaming message sending
 * - Session management
 * - Configuration
 */
export function useAIChat() {
  const queryClient = useQueryClient();
  
  // Local state
  const [messages, setMessages] = useState<Message[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isPanelOpen, setIsPanelOpen] = useState(false);
  
  // Refs for streaming
  const abortControllerRef = useRef<AbortController | null>(null);
  const currentToolExecutionRef = useRef<ToolExecutionState | null>(null);

  // Reset unread count when panel opens
  useEffect(() => {
    if (isPanelOpen) {
      setUnreadCount(0);
    }
  }, [isPanelOpen]);

  // Load session on mount or session change
  useEffect(() => {
    if (currentSessionId) {
      chatApi.getSession(currentSessionId)
        .then((session) => {
          setMessages(session.messages.map(convertMessage));
        })
        .catch((err) => {
          console.error("Failed to load session:", err);
        });
    }
  }, [currentSessionId]);

  /**
   * Send a message and handle streaming response
   * Requirements: 1.1, 1.3, 4.2
   */
  const sendMessage = useCallback(async (content: string) => {
    if (!content.trim() || isLoading) return;

    // Cancel any existing request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();

    // Add user message immediately
    const userMessage: Message = {
      id: generateId(),
      role: "user",
      content: content.trim(),
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMessage]);
    setIsLoading(true);

    // Prepare assistant message placeholder
    let assistantMessageId = generateId();
    let assistantContent = "";

    try {
      const response = await fetch(`${API_BASE}/api/chat/message`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          content: content.trim(),
          session_id: currentSessionId,
        }),
        signal: abortControllerRef.current.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      // Get session ID from response header
      const sessionId = response.headers.get("X-Session-Id");
      if (sessionId && sessionId !== currentSessionId) {
        setCurrentSessionId(sessionId);
      }

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
              const event: ChatStreamEvent = JSON.parse(line.slice(6));
              
              switch (event.type) {
                case "text":
                  if (event.content) {
                    assistantContent += event.content;
                    setMessages((prev) => {
                      const existing = prev.find((m) => m.id === assistantMessageId);
                      if (existing) {
                        return prev.map((m) =>
                          m.id === assistantMessageId
                            ? { ...m, content: assistantContent }
                            : m
                        );
                      } else {
                        return [
                          ...prev,
                          {
                            id: assistantMessageId,
                            role: "assistant" as const,
                            content: assistantContent,
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
                    
                    // Add summary as assistant message if provided
                    if (event.summary) {
                      assistantMessageId = generateId();
                      assistantContent = event.summary;
                      setMessages((prev) => [
                        ...prev,
                        {
                          id: assistantMessageId,
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
                    // Add finding to current tool execution or last assistant message
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
                  break;

                case "done":
                  // Increment unread if panel is closed
                  if (!isPanelOpen) {
                    setUnreadCount((prev) => prev + 1);
                  }
                  break;
              }
            } catch (e) {
              console.error("Failed to parse SSE event:", e);
            }
          }
        }
      }
    } catch (error) {
      if ((error as Error).name === "AbortError") {
        return; // Request was cancelled
      }
      console.error("Chat error:", error);
      setMessages((prev) => [
        ...prev,
        {
          id: generateId(),
          role: "system",
          content: `Error: ${(error as Error).message}`,
          timestamp: new Date().toISOString(),
        },
      ]);
    } finally {
      setIsLoading(false);
      abortControllerRef.current = null;
    }
  }, [currentSessionId, isLoading, isPanelOpen]);

  /**
   * Confirm or cancel a pending tool execution
   * Requirements: 8.1, 7.4
   */
  const confirmExecution = useCallback(async (executionId: string, confirmed: boolean) => {
    try {
      const response = await chatApi.confirmExecution(executionId, confirmed);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      // Process SSE stream for confirmation response
      const reader = response.body?.getReader();
      if (!reader) return;

      const decoder = new TextDecoder();
      let buffer = "";

      // Update the tool execution status
      setMessages((prev) =>
        prev.map((m) =>
          m.toolExecution?.id === executionId
            ? {
                ...m,
                toolExecution: {
                  ...m.toolExecution,
                  status: confirmed ? "running" : "error",
                  requiresConfirmation: false,
                  error: confirmed ? undefined : "Cancelled by user",
                },
              }
            : m
        )
      );

      if (!confirmed) return;

      // Set current tool execution ref for streaming updates
      const existingMsg = messages.find((m) => m.toolExecution?.id === executionId);
      if (existingMsg?.toolExecution) {
        currentToolExecutionRef.current = { ...existingMsg.toolExecution, status: "running" };
      }

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const event: ChatStreamEvent = JSON.parse(line.slice(6));
              
              switch (event.type) {
                case "tool_output":
                  if (event.output) {
                    setMessages((prev) =>
                      prev.map((m) =>
                        m.toolExecution?.id === executionId
                          ? {
                              ...m,
                              toolExecution: {
                                ...m.toolExecution!,
                                output: [...m.toolExecution!.output, event.output!],
                              },
                            }
                          : m
                      )
                    );
                  }
                  break;

                case "tool_complete":
                  setMessages((prev) =>
                    prev.map((m) =>
                      m.toolExecution?.id === executionId
                        ? {
                            ...m,
                            toolExecution: {
                              ...m.toolExecution!,
                              status: "completed",
                              completedAt: event.timestamp || new Date().toISOString(),
                            },
                          }
                        : m
                    )
                  );
                  
                  if (event.summary) {
                    setMessages((prev) => [
                      ...prev,
                      {
                        id: generateId(),
                        role: "assistant",
                        content: event.summary!,
                        timestamp: event.timestamp || new Date().toISOString(),
                      },
                    ]);
                  }
                  break;

                case "tool_error":
                  setMessages((prev) =>
                    prev.map((m) =>
                      m.toolExecution?.id === executionId
                        ? {
                            ...m,
                            toolExecution: {
                              ...m.toolExecution!,
                              status: "error",
                              error: event.message,
                              completedAt: event.timestamp || new Date().toISOString(),
                            },
                          }
                        : m
                    )
                  );
                  break;
              }
            } catch (e) {
              console.error("Failed to parse confirmation SSE event:", e);
            }
          }
        }
      }
    } catch (error) {
      console.error("Confirmation error:", error);
      setMessages((prev) =>
        prev.map((m) =>
          m.toolExecution?.id === executionId
            ? {
                ...m,
                toolExecution: {
                  ...m.toolExecution!,
                  status: "error",
                  error: (error as Error).message,
                },
              }
            : m
        )
      );
    }
  }, [messages]);

  /**
   * Clear current session and start fresh
   * Requirements: 5.4
   */
  const clearSession = useCallback(async () => {
    if (currentSessionId) {
      try {
        await chatApi.deleteSession(currentSessionId);
      } catch (e) {
        console.error("Failed to delete session:", e);
      }
    }
    setMessages([]);
    setCurrentSessionId(null);
    queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
  }, [currentSessionId, queryClient]);

  /**
   * Load a specific session
   * Requirements: 5.2
   */
  const loadSession = useCallback(async (sessionId: string) => {
    try {
      const session = await chatApi.getSession(sessionId);
      setMessages(session.messages.map(convertMessage));
      setCurrentSessionId(sessionId);
    } catch (error) {
      console.error("Failed to load session:", error);
    }
  }, []);

  /**
   * Cancel ongoing request
   */
  const cancelRequest = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setIsLoading(false);
    }
  }, []);

  return {
    // State
    messages,
    isLoading,
    currentSessionId,
    unreadCount,
    isPanelOpen,
    
    // Actions
    sendMessage,
    confirmExecution,
    clearSession,
    loadSession,
    cancelRequest,
    setIsPanelOpen,
    setUnreadCount,
  };
}

// Query hooks for sessions and config

export function useChatSessions(limit = 50, offset = 0) {
  return useQuery({
    queryKey: ["chatSessions", limit, offset],
    queryFn: () => chatApi.getSessions(limit, offset),
    staleTime: 30 * 1000, // 30 seconds
  });
}

export function useChatSession(sessionId: string | null) {
  return useQuery({
    queryKey: ["chatSession", sessionId],
    queryFn: () => chatApi.getSession(sessionId!),
    enabled: !!sessionId,
  });
}

export function useChatConfig() {
  return useQuery({
    queryKey: ["chatConfig"],
    queryFn: chatApi.getConfig,
    staleTime: 60 * 1000, // 1 minute
  });
}

export function useChatConfigStatus() {
  return useQuery({
    queryKey: ["chatConfigStatus"],
    queryFn: chatApi.getConfigStatus,
    staleTime: 30 * 1000, // 30 seconds
  });
}

export function useUpdateChatConfig() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: chatApi.updateConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["chatConfig"] });
      queryClient.invalidateQueries({ queryKey: ["chatConfigStatus"] });
    },
  });
}

export function useCreateChatSession() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (title?: string) => chatApi.createSession(title),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
    },
  });
}

export function useDeleteChatSession() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: chatApi.deleteSession,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
    },
  });
}
