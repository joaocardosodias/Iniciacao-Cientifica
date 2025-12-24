/**
 * Chat Context Provider
 * 
 * Provides global state management for the AI chat feature.
 * Shares session state, unread count, and panel visibility across components.
 * 
 * Requirements:
 * - 5.2: Restore previous conversation history
 * - 6.4: Show notification badges for new AI responses
 */

import { createContext, useContext, ReactNode, useCallback, useState, useEffect } from "react";
import { useAIChat } from "@/hooks/useAIChat";
import type { Message } from "@/components/AIChatPanel";

interface ChatContextValue {
  // State
  messages: Message[];
  isLoading: boolean;
  currentSessionId: string | null;
  unreadCount: number;
  isPanelOpen: boolean;
  isConfigOpen: boolean;
  
  // Actions
  sendMessage: (message: string) => Promise<void>;
  confirmExecution: (executionId: string, confirmed: boolean) => Promise<void>;
  clearSession: () => Promise<void>;
  loadSession: (sessionId: string) => Promise<void>;
  cancelRequest: () => void;
  openPanel: () => void;
  closePanel: () => void;
  togglePanel: () => void;
  openConfig: () => void;
  closeConfig: () => void;
  resetUnreadCount: () => void;
}

const ChatContext = createContext<ChatContextValue | null>(null);

interface ChatProviderProps {
  children: ReactNode;
}

export function ChatProvider({ children }: ChatProviderProps) {
  const {
    messages,
    isLoading,
    currentSessionId,
    unreadCount,
    isPanelOpen,
    sendMessage,
    confirmExecution,
    clearSession,
    loadSession,
    cancelRequest,
    setIsPanelOpen,
    setUnreadCount,
  } = useAIChat();

  const [isConfigOpen, setIsConfigOpen] = useState(false);

  // Panel controls
  const openPanel = useCallback(() => {
    setIsPanelOpen(true);
  }, [setIsPanelOpen]);

  const closePanel = useCallback(() => {
    setIsPanelOpen(false);
  }, [setIsPanelOpen]);

  const togglePanel = useCallback(() => {
    setIsPanelOpen((prev) => !prev);
  }, [setIsPanelOpen]);

  // Config modal controls
  const openConfig = useCallback(() => {
    setIsConfigOpen(true);
  }, []);

  const closeConfig = useCallback(() => {
    setIsConfigOpen(false);
  }, []);

  // Reset unread count
  const resetUnreadCount = useCallback(() => {
    setUnreadCount(0);
  }, [setUnreadCount]);

  // Reset unread count when panel opens
  useEffect(() => {
    if (isPanelOpen) {
      resetUnreadCount();
    }
  }, [isPanelOpen, resetUnreadCount]);

  const value: ChatContextValue = {
    // State
    messages,
    isLoading,
    currentSessionId,
    unreadCount,
    isPanelOpen,
    isConfigOpen,
    
    // Actions
    sendMessage,
    confirmExecution,
    clearSession,
    loadSession,
    cancelRequest,
    openPanel,
    closePanel,
    togglePanel,
    openConfig,
    closeConfig,
    resetUnreadCount,
  };

  return (
    <ChatContext.Provider value={value}>
      {children}
    </ChatContext.Provider>
  );
}

/**
 * Hook to access chat context
 * Must be used within a ChatProvider
 */
export function useChatContext(): ChatContextValue {
  const context = useContext(ChatContext);
  
  if (!context) {
    throw new Error("useChatContext must be used within a ChatProvider");
  }
  
  return context;
}

/**
 * Hook to access only the unread count (for components that only need badge info)
 */
export function useChatUnreadCount(): number {
  const { unreadCount } = useChatContext();
  return unreadCount;
}

/**
 * Hook to access panel state and controls
 */
export function useChatPanel() {
  const { isPanelOpen, openPanel, closePanel, togglePanel } = useChatContext();
  return { isPanelOpen, openPanel, closePanel, togglePanel };
}
