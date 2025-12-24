import { useState, useRef, useEffect, useCallback } from "react";
import { cn } from "@/lib/utils";
import { MainLayout } from "@/components/MainLayout";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { 
  Send, 
  Bot, 
  Settings,
  Trash2,
  Sparkles
} from "lucide-react";
import { ChatMessage } from "@/components/ChatMessage";
import { ToolExecutionCard } from "@/components/ToolExecutionCard";
import { ChatConfigModal } from "@/components/ChatConfigModal";
import { useChatContext } from "@/contexts/ChatContext";

export default function Assistant() {
  const [inputValue, setInputValue] = useState("");
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const {
    messages,
    isLoading,
    sendMessage,
    confirmExecution,
    clearSession,
  } = useChatContext();

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  // Focus input on mount
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
  }, []);

  const handleSend = useCallback(() => {
    const trimmed = inputValue.trim();
    if (trimmed && !isLoading) {
      sendMessage(trimmed);
      setInputValue("");
    }
  }, [inputValue, isLoading, sendMessage]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const quickActions = [
    { label: "Scan target", prompt: "scan " },
    { label: "List tools", prompt: "quais ferramentas você tem?" },
    { label: "Help", prompt: "como você pode me ajudar?" },
  ];

  return (
    <MainLayout>
      <div className="h-[calc(100vh-8rem)] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Bot className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">AI Assistant</h1>
              <p className="text-sm text-muted-foreground">
                Seu assistente de pentest com IA
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => clearSession?.()}
              disabled={messages.length === 0}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Limpar
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsConfigOpen(true)}
            >
              <Settings className="h-4 w-4 mr-2" />
              Configurar
            </Button>
          </div>
        </div>

        {/* Chat Area */}
        <Card className="flex-1 flex flex-col overflow-hidden">
          <CardContent className="flex-1 flex flex-col p-0 overflow-hidden">
            {/* Messages */}
            <div 
              ref={scrollRef}
              className="flex-1 overflow-y-auto p-4 space-y-4"
            >
              {messages.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-center">
                  <div className="p-4 rounded-full bg-primary/10 mb-4">
                    <Sparkles className="h-12 w-12 text-primary" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">
                    Olá! Sou o FRAGMENTUM AI
                  </h3>
                  <p className="text-muted-foreground max-w-md mb-6">
                    Posso ajudar você a executar scans, enumerar serviços, 
                    testar vulnerabilidades e muito mais. Basta me dizer o que precisa!
                  </p>
                  
                  {/* Quick Actions */}
                  <div className="flex flex-wrap gap-2 justify-center">
                    {quickActions.map((action) => (
                      <Button
                        key={action.label}
                        variant="outline"
                        size="sm"
                        onClick={() => setInputValue(action.prompt)}
                      >
                        {action.label}
                      </Button>
                    ))}
                  </div>
                </div>
              ) : (
                messages.map((message) => (
                  <div key={message.id}>
                    {message.toolExecution ? (
                      <ToolExecutionCard
                        execution={message.toolExecution}
                        onConfirm={confirmExecution}
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
                <div className="flex items-center gap-2 text-muted-foreground p-4">
                  <div className="flex gap-1">
                    <span className="h-2 w-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "0ms" }} />
                    <span className="h-2 w-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "150ms" }} />
                    <span className="h-2 w-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "300ms" }} />
                  </div>
                  <span className="text-sm">Processando...</span>
                </div>
              )}
            </div>

            {/* Input Area */}
            <div className="p-4 border-t border-border bg-card/50">
              <div className="flex gap-3">
                <Textarea
                  ref={inputRef}
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Digite sua mensagem... (ex: scan 192.168.1.1)"
                  className="min-h-[80px] max-h-[160px] resize-none"
                  disabled={isLoading}
                />
                <Button
                  onClick={handleSend}
                  disabled={!inputValue.trim() || isLoading}
                  className="shrink-0 self-end h-10"
                  size="lg"
                >
                  <Send className="h-5 w-5" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Enter para enviar • Shift+Enter para nova linha
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Config Modal */}
        <ChatConfigModal
          open={isConfigOpen}
          onOpenChange={setIsConfigOpen}
        />
      </div>
    </MainLayout>
  );
}
