import { cn } from "@/lib/utils";
import { Terminal as TerminalIcon, ChevronDown, ChevronUp, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

interface TerminalOutputProps {
  lines: string[];
  title?: string;
  isStreaming?: boolean;
  className?: string;
  maxHeight?: string;
  collapsible?: boolean;
  onClose?: () => void;
}

export function TerminalOutput({
  lines,
  title = "Output",
  isStreaming = false,
  className,
  maxHeight = "400px",
  collapsible = false,
  onClose,
}: TerminalOutputProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines, autoScroll]);

  const handleScroll = () => {
    if (scrollRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 50;
      setAutoScroll(isNearBottom);
    }
  };

  return (
    <div className={cn("rounded-lg border border-border bg-background overflow-hidden", className)}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-card">
        <div className="flex items-center gap-2">
          <TerminalIcon className="h-4 w-4 text-primary" />
          <span className="text-sm font-medium text-foreground">{title}</span>
          {isStreaming && (
            <span className="flex items-center gap-1.5 text-xs text-primary">
              <span className="h-2 w-2 rounded-full bg-primary animate-pulse" />
              Streaming
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {collapsible && (
            <button
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="p-1 hover:bg-muted rounded transition-colors"
            >
              {isCollapsed ? (
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              ) : (
                <ChevronUp className="h-4 w-4 text-muted-foreground" />
              )}
            </button>
          )}
          {onClose && (
            <button
              onClick={onClose}
              className="p-1 hover:bg-muted rounded transition-colors"
            >
              <X className="h-4 w-4 text-muted-foreground" />
            </button>
          )}
        </div>
      </div>

      {/* Terminal content */}
      {!isCollapsed && (
        <div
          ref={scrollRef}
          onScroll={handleScroll}
          className="p-4 overflow-auto font-mono text-sm"
          style={{ maxHeight, backgroundColor: "hsl(240 10% 3.9%)" }}
        >
          {lines.length === 0 ? (
            <div className="text-muted-foreground flex items-center gap-2">
              <span className="text-primary animate-blink">▌</span>
              Aguardando output...
            </div>
          ) : (
            lines.map((line, i) => (
              <div key={i} className="text-primary whitespace-pre-wrap break-all">
                <span className="text-muted-foreground mr-2 select-none">{String(i + 1).padStart(3, " ")}│</span>
                {line}
              </div>
            ))
          )}
          {isStreaming && lines.length > 0 && (
            <span className="text-primary animate-blink">▌</span>
          )}
        </div>
      )}
    </div>
  );
}
