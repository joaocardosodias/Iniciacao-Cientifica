import { cn } from "@/lib/utils";
import { Bot, User, Terminal, AlertCircle } from "lucide-react";
import { SeverityBadge } from "./SeverityBadge";
import ReactMarkdown from "react-markdown";
import type { SeverityLevel } from "@/types";

export interface Finding {
  id: string;
  type: string;
  value: any;
  severity: SeverityLevel;
  source: string;
  target: string;
  timestamp: string;
  details: Record<string, any>;
}

export interface ChatMessageProps {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  timestamp: string;
  findings?: Finding[];
}

export function ChatMessage({ role, content, timestamp, findings }: ChatMessageProps) {
  const isUser = role === "user";
  const isSystem = role === "system";
  const isTool = role === "tool";
  const isAssistant = role === "assistant";

  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString("pt-BR", {
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return "";
    }
  };

  const getIcon = () => {
    switch (role) {
      case "user":
        return <User className="h-4 w-4" />;
      case "assistant":
        return <Bot className="h-4 w-4" />;
      case "tool":
        return <Terminal className="h-4 w-4" />;
      case "system":
        return <AlertCircle className="h-4 w-4" />;
      default:
        return <Bot className="h-4 w-4" />;
    }
  };

  const getRoleLabel = () => {
    switch (role) {
      case "user":
        return "Você";
      case "assistant":
        return "FRAGMENTUM";
      case "tool":
        return "Tool Output";
      case "system":
        return "Sistema";
      default:
        return "AI";
    }
  };


  return (
    <div
      className={cn(
        "flex gap-3",
        isUser && "flex-row-reverse"
      )}
    >
      {/* Avatar */}
      <div
        className={cn(
          "flex-shrink-0 h-8 w-8 rounded-full flex items-center justify-center",
          isUser && "bg-primary text-primary-foreground",
          !isUser && !isTool && "bg-muted text-muted-foreground",
          isTool && "bg-card border border-border text-foreground",
          isSystem && "bg-severity-medium/20 text-severity-medium"
        )}
      >
        {getIcon()}
      </div>

      {/* Message content */}
      <div
        className={cn(
          "flex flex-col max-w-[80%]",
          isUser && "items-end"
        )}
      >
        {/* Header */}
        <div className={cn(
          "flex items-center gap-2 mb-1",
          isUser && "flex-row-reverse"
        )}>
          <span className="text-xs font-medium text-muted-foreground">
            {getRoleLabel()}
          </span>
          <span className="text-xs text-muted-foreground/60">
            {formatTime(timestamp)}
          </span>
        </div>

        {/* Message bubble */}
        <div
          className={cn(
            "rounded-lg px-4 py-2 text-sm",
            isUser && "bg-primary text-primary-foreground",
            !isUser && !isTool && !isSystem && "bg-muted text-foreground",
            isTool && "bg-card border border-border font-mono text-xs",
            isSystem && "bg-severity-medium/10 border border-severity-medium/30 text-severity-medium"
          )}
        >
          {isTool ? (
            <pre className="whitespace-pre-wrap break-all overflow-x-auto">
              {content}
            </pre>
          ) : isAssistant ? (
            <div className="prose prose-sm prose-invert max-w-none">
              <ReactMarkdown
                components={{
                  // Custom styling for markdown elements
                  p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
                  strong: ({ children }) => <strong className="font-semibold text-primary">{children}</strong>,
                  em: ({ children }) => <em className="italic text-muted-foreground">{children}</em>,
                  code: ({ children, className }) => {
                    const isInline = !className;
                    return isInline ? (
                      <code className="px-1 py-0.5 rounded bg-background text-primary font-mono text-xs">{children}</code>
                    ) : (
                      <code className="block p-2 rounded bg-background font-mono text-xs overflow-x-auto">{children}</code>
                    );
                  },
                  pre: ({ children }) => <pre className="p-3 rounded-lg bg-background overflow-x-auto my-2">{children}</pre>,
                  ul: ({ children }) => <ul className="list-disc list-inside mb-2 space-y-1">{children}</ul>,
                  ol: ({ children }) => <ol className="list-decimal list-inside mb-2 space-y-1">{children}</ol>,
                  li: ({ children }) => <li className="text-sm">{children}</li>,
                  h1: ({ children }) => <h1 className="text-lg font-bold mb-2">{children}</h1>,
                  h2: ({ children }) => <h2 className="text-base font-bold mb-2">{children}</h2>,
                  h3: ({ children }) => <h3 className="text-sm font-bold mb-1">{children}</h3>,
                  a: ({ href, children }) => (
                    <a href={href} className="text-primary underline hover:no-underline" target="_blank" rel="noopener noreferrer">
                      {children}
                    </a>
                  ),
                  blockquote: ({ children }) => (
                    <blockquote className="border-l-2 border-primary pl-3 italic text-muted-foreground my-2">
                      {children}
                    </blockquote>
                  ),
                }}
              >
                {content}
              </ReactMarkdown>
            </div>
          ) : (
            <div className="whitespace-pre-wrap break-words">
              {content}
            </div>
          )}
        </div>

        {/* Findings */}
        {findings && findings.length > 0 && (
          <div className="mt-2 space-y-2 w-full">
            <span className="text-xs font-medium text-muted-foreground">
              Findings ({findings.length})
            </span>
            <div className="space-y-1">
              {findings.map((finding) => (
                <FindingItem key={finding.id} finding={finding} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

interface FindingItemProps {
  finding: Finding;
}

function FindingItem({ finding }: FindingItemProps) {
  const getValueDisplay = () => {
    if (typeof finding.value === "string") {
      return finding.value;
    }
    if (typeof finding.value === "object") {
      // Handle common finding types
      if (finding.type === "port") {
        return `Port ${finding.value.port}/${finding.value.protocol || "tcp"} - ${finding.value.service || "unknown"}`;
      }
      if (finding.type === "vulnerability") {
        return finding.value.name || finding.value.cve || JSON.stringify(finding.value);
      }
      return JSON.stringify(finding.value);
    }
    return String(finding.value);
  };

  return (
    <div className="flex items-start gap-2 p-2 rounded bg-card border border-border text-xs">
      <SeverityBadge severity={finding.severity} showIcon={false} className="shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="font-medium text-foreground truncate">
          {getValueDisplay()}
        </div>
        <div className="text-muted-foreground mt-0.5">
          {finding.type} • {finding.source}
        </div>
      </div>
    </div>
  );
}
