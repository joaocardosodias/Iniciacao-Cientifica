/**
 * Chat Keyboard Shortcuts Hook
 * 
 * Provides keyboard shortcut handling for the AI chat panel.
 * 
 * Requirements:
 * - 6.5: Keyboard shortcuts (Enter to send, Shift+Enter for newline, Escape to close)
 */

import { useEffect, useCallback, RefObject } from "react";

export interface ChatKeyboardShortcutsOptions {
  /** Callback when Enter is pressed (without Shift) - send message */
  onSend?: () => void;
  /** Callback when Escape is pressed - close panel */
  onClose?: () => void;
  /** Callback when Ctrl/Cmd+K is pressed - clear chat */
  onClear?: () => void;
  /** Callback when Ctrl/Cmd+N is pressed - new session */
  onNewSession?: () => void;
  /** Callback when Ctrl/Cmd+/ is pressed - toggle settings */
  onToggleSettings?: () => void;
  /** Whether the chat panel is open */
  isOpen?: boolean;
  /** Whether a message is currently being sent */
  isLoading?: boolean;
  /** Reference to the input element for focus management */
  inputRef?: RefObject<HTMLTextAreaElement>;
}

/**
 * Hook for handling keyboard shortcuts in the chat panel
 * 
 * Shortcuts:
 * - Enter: Send message (when input is focused)
 * - Shift+Enter: New line in input
 * - Escape: Close chat panel
 * - Ctrl/Cmd+K: Clear chat history
 * - Ctrl/Cmd+N: Start new session
 * - Ctrl/Cmd+/: Toggle settings
 * 
 * Requirements: 6.5
 */
export function useChatKeyboardShortcuts({
  onSend,
  onClose,
  onClear,
  onNewSession,
  onToggleSettings,
  isOpen = true,
  isLoading = false,
  inputRef,
}: ChatKeyboardShortcutsOptions) {
  /**
   * Handle keyboard events for the textarea input
   * Returns true if the event was handled
   */
  const handleInputKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>): boolean => {
      // Enter without Shift - send message
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        if (!isLoading && onSend) {
          onSend();
        }
        return true;
      }

      // Escape - close panel
      if (e.key === "Escape") {
        e.preventDefault();
        if (onClose) {
          onClose();
        }
        return true;
      }

      // Shift+Enter is handled by default (new line)
      return false;
    },
    [onSend, onClose, isLoading]
  );

  /**
   * Global keyboard shortcuts (work when panel is open)
   */
  useEffect(() => {
    if (!isOpen) return;

    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      const isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0;
      const modKey = isMac ? e.metaKey : e.ctrlKey;

      // Escape - close panel (global)
      if (e.key === "Escape") {
        e.preventDefault();
        onClose?.();
        return;
      }

      // Ctrl/Cmd+K - clear chat
      if (modKey && e.key === "k") {
        e.preventDefault();
        onClear?.();
        return;
      }

      // Ctrl/Cmd+N - new session
      if (modKey && e.key === "n") {
        e.preventDefault();
        onNewSession?.();
        return;
      }

      // Ctrl/Cmd+/ - toggle settings
      if (modKey && e.key === "/") {
        e.preventDefault();
        onToggleSettings?.();
        return;
      }

      // Focus input on any alphanumeric key if not already focused
      if (
        inputRef?.current &&
        document.activeElement !== inputRef.current &&
        !modKey &&
        !e.altKey &&
        e.key.length === 1 &&
        /[a-zA-Z0-9]/.test(e.key)
      ) {
        inputRef.current.focus();
      }
    };

    window.addEventListener("keydown", handleGlobalKeyDown);
    return () => window.removeEventListener("keydown", handleGlobalKeyDown);
  }, [isOpen, onClose, onClear, onNewSession, onToggleSettings, inputRef]);

  return {
    handleInputKeyDown,
  };
}

/**
 * Hook for global chat toggle shortcut
 * 
 * Provides a keyboard shortcut to toggle the chat panel from anywhere.
 * Default: Ctrl/Cmd+Shift+C
 */
export function useChatToggleShortcut(
  onToggle: () => void,
  shortcut: string = "c"
) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0;
      const modKey = isMac ? e.metaKey : e.ctrlKey;

      if (modKey && e.shiftKey && e.key.toLowerCase() === shortcut) {
        e.preventDefault();
        onToggle();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onToggle, shortcut]);
}

/**
 * Keyboard shortcut descriptions for help/documentation
 */
export const CHAT_SHORTCUTS = [
  { keys: ["Enter"], description: "Send message" },
  { keys: ["Shift", "Enter"], description: "New line" },
  { keys: ["Escape"], description: "Close panel" },
  { keys: ["Ctrl/⌘", "K"], description: "Clear chat" },
  { keys: ["Ctrl/⌘", "N"], description: "New session" },
  { keys: ["Ctrl/⌘", "/"], description: "Settings" },
  { keys: ["Ctrl/⌘", "Shift", "C"], description: "Toggle chat (global)" },
] as const;
