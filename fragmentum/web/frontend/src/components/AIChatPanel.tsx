import { useState, useRef, useEffect, useCallback } from "react";
import { cn } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { 
  X, 
  Send, 
  Bot, 
  Minimize2, 
  Maximize2,
  GripVertical,
  Settings
} from "lucide-react";
import { ChatMessage, ChatMessageProps } from "./ChatMessage";
import { ToolExecutionCard } from "./ToolExecutionCard";
import { useChatKeyboardShortcuts } from "@/hooks/useChatKeyboardShortcuts";

export interface Message {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  timestamp: string;
  toolExecution?: ToolExecutionState;
  findings?: Finding[];
}

export interface ToolExecutionState {
  id: string;
  toolName: string;
  status: "pending" | "running" | "completed" | "error";
  output: string[];
  startedAt: string;
  completedAt?: string;
  error?: string;
  requiresConfirmation?: boolean;
  confirmationMessage?: string;
}

export interface Finding {
  id: string;
  type: string;
  value: any;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  target: string;
  timestamp: string;
  details: Record<string, any>;
}

interface AIChatPanelProps {
  isOpen: boolean;
  onClose: () => void;
  onToggle: () => void;
  messages: Message[];
  onSendMessage: (message: string) => void;
  onConfirmExecution?: (executionId: string, confirmed: boolean) => void;
  isLoading?: boolean;
  onOpenSettings?: () => void;
}

const MIN_WIDTH = 320;
const MAX_WIDTH = 800;
const DEFAULT_WIDTH = 420;

export function AIChatPanel({
  isOpen,
  onClose,
  onToggle,
  messages,
  onSendMessage,
  onConfirmExecution,
  isLoading = false,
  onOpenSettings,
}: AIChatPanelProps) {
  const [inputValue, setInputValue] = useState("");
  const [width, setWidth] = useState(DEFAULT_WIDTH);
  const [isMinimized, setIsMinimized] = useState(false);
  const [isResizing, setIsResizing] = useState(false);
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);


  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (scrollRef.current && !isMinimized) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isMinimized]);

  // Focus input when panel opens
  useEffect(() => {
    if (isOpen && !isMinimized && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen, isMinimized]);

  // Handle send message - declared first so it can be used in hooks
  const handleSend = useCallback(() => {
    const trimmed = inputValue.trim();
    if (trimmed && !isLoading) {
      onSendMessage(trimmed);
      setInputValue("");
    }
  }, [inputValue, isLoading, onSendMessage]);

  // Handle resize
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
  }, []);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing) return;
      
      const newWidth = window.innerWidth - e.clientX;
      setWidth(Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, newWidth)));
    };

    const handleMouseUp = () => {
      setIsResizing(false);
    };

    if (isResizing) {
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
    }

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isResizing]);

  // Handle keyboard shortcuts using the dedicated hook
  const { handleInputKeyDown } = useChatKeyboardShortcuts({
    onSend: handleSend,
    onClose,
    onClear: () => {
      // Could be connected to clearSession if needed
    },
    onToggleSettings: onOpenSettings,
    isOpen,
    isLoading,
    inputRef,
  });

  // Legacy handler for backward compatibility
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    handleInputKeyDown(e);
  };

  if (!isOpen) return null;

  return (
    <>
      {/* Overlay for resize cursor */}
      {isResizing && (
        <div className="fixed inset-0 z-50 cursor-col-resize" />
      )}
      
      <div
        ref={panelRef}
        className={cn(
          "fixed right-0 top-0 z-40 h-screen border-l border-border bg-background shadow-xl",
          "flex flex-col transition-all duration-300 ease-in-out",
          isMinimized && "h-14"
        )}
        style={{ width: isMinimized ? 280 : width }}
      >
        {/* Resize handle */}
        {!isMinimized && (
          <div
            onMouseDown={handleMouseDown}
            className={cn(
              "absolute left-0 top-0 bottom-0 w-1 cursor-col-resize",
              "hover:bg-primary/50 transition-colors",
              "flex items-center justify-center group",
              isResizing && "bg-primary/50"
            )}
          >
            <GripVertical className="h-6 w-6 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity -ml-2" />
          </div>
        )}

        {/* Header */}
        <div className="flex items-center justify-between h-14 px-4 border-b border-border bg-card shrink-0">
          <div className="flex items-center gap-2">
            <Bot className="h-5 w-5 text-primary" />
            <span className="font-semibold text-foreground">AI Assistant</span>
            {isLoading && (
              <span className="flex items-center gap-1.5 text-xs text-primary">
                <span className="h-2 w-2 rounded-full bg-primary animate-pulse" />
              </span>
            )}
          </div>
          <div className="flex items-center gap-1">
            {onOpenSettings && (
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={onOpenSettings}
              >
                <Settings className="h-4 w-4" />
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => setIsMinimized(!isMinimized)}
            >
              {isMinimized ? (
                <Maximize2 className="h-4 w-4" />
              ) : (
                <Minimize2 className="h-4 w-4" />
              )}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={onClose}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>


        {/* Messages area */}
        {!isMinimized && (
          <>
            <div 
              ref={scrollRef}
              className="flex-1 overflow-y-auto p-4 space-y-4"
            >
              {messages.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-center text-muted-foreground">
                  <Bot className="h-12 w-12 mb-4 opacity-50" />
                  <p className="text-sm">
                    Olá! Sou seu assistente de pentest.
                  </p>
                  <p className="text-xs mt-2">
                    Pergunte sobre ferramentas ou peça para escanear um alvo.
                  </p>
                </div>
              ) : (
                messages.map((message) => (
                  <div key={message.id}>
                    {message.toolExecution ? (
                      <ToolExecutionCard
                        execution={message.toolExecution}
                        onConfirm={onConfirmExecution}
                      />
                    ) : (
                      <ChatMessage
                        role={message.role}
                        content={message.content}
                        timestamp={message.timestamp}
                        findings={message.findings}
                      />
                    )}
                  </div>
                ))
              )}
              
              {isLoading && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <div className="flex gap-1">
                    <span className="h-2 w-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "0ms" }} />
                    <span className="h-2 w-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "150ms" }} />
                    <span className="h-2 w-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "300ms" }} />
                  </div>
                  <span className="text-xs">Pensando...</span>
                </div>
              )}
            </div>

            {/* Input area */}
            <div className="p-4 border-t border-border bg-card shrink-0">
              <div className="flex gap-2">
                <Textarea
                  ref={inputRef}
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Digite sua mensagem... (Enter para enviar)"
                  className="min-h-[60px] max-h-[120px] resize-none"
                  disabled={isLoading}
                />
                <Button
                  onClick={handleSend}
                  disabled={!inputValue.trim() || isLoading}
                  className="shrink-0 self-end"
                  size="icon"
                >
                  <Send className="h-4 w-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Shift+Enter para nova linha • Esc para fechar
              </p>
            </div>
          </>
        )}
      </div>
    </>
  );
}
