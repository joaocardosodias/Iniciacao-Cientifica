import { useState, useEffect, useRef } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Terminal,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Shield,
} from "lucide-react";

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

interface ToolExecutionCardProps {
  execution: ToolExecutionState;
  onConfirm?: (executionId: string, confirmed: boolean) => void;
}

export function ToolExecutionCard({ execution, onConfirm }: ToolExecutionCardProps) {
  const [isExpanded, setIsExpanded] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const outputRef = useRef<HTMLDivElement>(null);

  // Auto-scroll output when streaming
  useEffect(() => {
    if (autoScroll && outputRef.current && execution.status === "running") {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [execution.output, autoScroll, execution.status]);

  const handleScroll = () => {
    if (outputRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = outputRef.current;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 50;
      setAutoScroll(isNearBottom);
    }
  };

  const getStatusIcon = () => {
    switch (execution.status) {
      case "pending":
        return <Clock className="h-4 w-4 text-muted-foreground" />;
      case "running":
        return <Loader2 className="h-4 w-4 text-primary animate-spin" />;
      case "completed":
        return <CheckCircle2 className="h-4 w-4 text-severity-low" />;
      case "error":
        return <XCircle className="h-4 w-4 text-severity-critical" />;
      default:
        return <Terminal className="h-4 w-4" />;
    }
  };


  const getStatusText = () => {
    switch (execution.status) {
      case "pending":
        return "Aguardando";
      case "running":
        return "Executando";
      case "completed":
        return "Concluído";
      case "error":
        return "Erro";
      default:
        return execution.status;
    }
  };

  const getStatusColor = () => {
    switch (execution.status) {
      case "pending":
        return "text-muted-foreground";
      case "running":
        return "text-primary";
      case "completed":
        return "text-severity-low";
      case "error":
        return "text-severity-critical";
      default:
        return "text-foreground";
    }
  };

  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString("pt-BR", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    } catch {
      return "";
    }
  };

  const getDuration = () => {
    if (!execution.startedAt) return null;
    
    const start = new Date(execution.startedAt).getTime();
    const end = execution.completedAt 
      ? new Date(execution.completedAt).getTime() 
      : Date.now();
    
    const seconds = Math.floor((end - start) / 1000);
    
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  };

  return (
    <Card className={cn(
      "border",
      execution.status === "running" && "border-primary/50",
      execution.status === "error" && "border-severity-critical/50",
      execution.status === "completed" && "border-severity-low/50",
      execution.requiresConfirmation && "border-severity-high/50"
    )}>
      <CardHeader className="py-3 px-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm font-mono">
              {execution.toolName}
            </CardTitle>
          </div>
          <div className="flex items-center gap-2">
            <div className={cn("flex items-center gap-1.5 text-xs", getStatusColor())}>
              {getStatusIcon()}
              <span>{getStatusText()}</span>
            </div>
            {getDuration() && (
              <span className="text-xs text-muted-foreground">
                {getDuration()}
              </span>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
              onClick={() => setIsExpanded(!isExpanded)}
            >
              {isExpanded ? (
                <ChevronUp className="h-3 w-3" />
              ) : (
                <ChevronDown className="h-3 w-3" />
              )}
            </Button>
          </div>
        </div>
      </CardHeader>


      {isExpanded && (
        <CardContent className="py-0 px-4 pb-4">
          {/* Confirmation prompt for ALL tool executions - Claude Desktop style */}
          {execution.requiresConfirmation && execution.status === "pending" && (
            <div className="mb-3 p-4 rounded-lg bg-gradient-to-r from-primary/5 to-primary/10 border border-primary/20">
              <div className="flex items-start gap-3">
                <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20">
                  <Terminal className="h-5 w-5 text-primary" />
                </div>
                <div className="flex-1">
                  <p className="text-sm font-semibold text-foreground">
                    FRAGMENTUM quer usar <span className="text-primary font-mono bg-primary/10 px-1.5 py-0.5 rounded">{execution.toolName}</span>
                  </p>
                  
                  {/* Show confirmation message with parameters */}
                  {execution.confirmationMessage && (
                    <div className="mt-3">
                      {/* Parse and display the message nicely */}
                      {execution.confirmationMessage.includes("```json") ? (
                        <div className="space-y-2">
                          <p className="text-xs text-muted-foreground">
                            {execution.confirmationMessage.split("```json")[0].replace(/[🔧*]/g, '').trim()}
                          </p>
                          <div className="rounded-lg bg-background/80 border border-border overflow-hidden">
                            <div className="px-3 py-1.5 bg-muted/50 border-b border-border">
                              <span className="text-xs font-medium text-muted-foreground">Parâmetros</span>
                            </div>
                            <pre className="p-3 font-mono text-xs text-foreground overflow-x-auto">
                              {execution.confirmationMessage.split("```json")[1]?.split("```")[0]?.trim()}
                            </pre>
                          </div>
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground whitespace-pre-wrap">
                          {execution.confirmationMessage}
                        </p>
                      )}
                    </div>
                  )}
                  
                  <div className="flex gap-3 mt-4">
                    <Button
                      size="sm"
                      onClick={() => onConfirm?.(execution.id, true)}
                      className="h-9 px-4 text-sm font-medium bg-primary hover:bg-primary/90 text-primary-foreground shadow-sm"
                    >
                      <CheckCircle2 className="h-4 w-4 mr-2" />
                      Permitir
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => onConfirm?.(execution.id, false)}
                      className="h-9 px-4 text-sm font-medium border-border hover:bg-muted"
                    >
                      <XCircle className="h-4 w-4 mr-2" />
                      Negar
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Output area */}
          {execution.output.length > 0 && (
            <div
              ref={outputRef}
              onScroll={handleScroll}
              className="rounded bg-[hsl(240_10%_3.9%)] p-3 font-mono text-xs max-h-[200px] overflow-auto"
            >
              {execution.output.map((line, i) => (
                <div key={i} className="text-primary whitespace-pre-wrap break-all">
                  <span className="text-muted-foreground mr-2 select-none">
                    {String(i + 1).padStart(3, " ")}│
                  </span>
                  {line}
                </div>
              ))}
              {execution.status === "running" && (
                <span className="text-primary animate-blink">▌</span>
              )}
            </div>
          )}

          {/* Empty state for pending */}
          {execution.output.length === 0 && execution.status === "pending" && !execution.requiresConfirmation && (
            <div className="text-xs text-muted-foreground flex items-center gap-2">
              <Clock className="h-3 w-3" />
              Aguardando execução...
            </div>
          )}

          {/* Error message */}
          {execution.error && (
            <div className="mt-2 p-2 rounded bg-severity-critical/10 border border-severity-critical/30">
              <div className="flex items-start gap-2">
                <XCircle className="h-4 w-4 text-severity-critical shrink-0 mt-0.5" />
                <div className="text-xs text-severity-critical">
                  {execution.error}
                </div>
              </div>
            </div>
          )}

          {/* Timestamps */}
          <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
            {execution.startedAt && (
              <span>Início: {formatTime(execution.startedAt)}</span>
            )}
            {execution.completedAt && (
              <span>Fim: {formatTime(execution.completedAt)}</span>
            )}
          </div>
        </CardContent>
      )}
    </Card>
  );
}
