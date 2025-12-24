import { useState } from "react";
import { useShellHistory, useExportShellHistory } from "@/hooks/useShells";
import { HistoryEntry } from "@/types";
import { cn } from "@/lib/utils";
import { formatTimestamp } from "@/lib/utils/validators";
import {
  Terminal,
  Download,
  Loader2,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Check,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { useToast } from "@/hooks/use-toast";

interface ShellHistoryProps {
  shellId: string;
  className?: string;
}

function HistoryEntryItem({ entry }: { entry: HistoryEntry }) {
  const [isOpen, setIsOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const handleCopyCommand = async () => {
    try {
      await navigator.clipboard.writeText(entry.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({
        title: "Failed to copy",
        description: "Could not copy command to clipboard",
        variant: "destructive",
      });
    }
  };

  const hasOutput = entry.output && entry.output.trim().length > 0;

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <div className="border border-border rounded-lg bg-secondary/30 overflow-hidden">
        <CollapsibleTrigger asChild>
          <div
            className={cn(
              "flex items-start gap-3 p-3 cursor-pointer hover:bg-secondary/50 transition-colors",
              isOpen && "border-b border-border"
            )}
          >
            <div className="mt-0.5">
              {hasOutput ? (
                isOpen ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                )
              ) : (
                <div className="w-4" />
              )}
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Terminal className="h-3.5 w-3.5 text-primary" />
                <code className="font-mono text-sm text-foreground break-all">
                  {entry.command}
                </code>
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Clock className="h-3 w-3" />
                <span>{formatTimestamp(entry.timestamp)}</span>
                {hasOutput && (
                  <Badge variant="outline" className="text-xs py-0 h-5">
                    {entry.output.split("\n").length} lines
                  </Badge>
                )}
              </div>
            </div>

            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0"
              onClick={(e) => {
                e.stopPropagation();
                handleCopyCommand();
              }}
            >
              {copied ? (
                <Check className="h-3.5 w-3.5 text-severity-low" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </Button>
          </div>
        </CollapsibleTrigger>

        {hasOutput && (
          <CollapsibleContent>
            <div className="p-3 bg-background/50">
              <pre className="font-mono text-xs text-muted-foreground whitespace-pre-wrap break-all overflow-x-auto">
                {entry.output}
              </pre>
            </div>
          </CollapsibleContent>
        )}
      </div>
    </Collapsible>
  );
}

export function ShellHistory({ shellId, className }: ShellHistoryProps) {
  const { toast } = useToast();
  const { data: history = [], isLoading, error } = useShellHistory(shellId);
  const exportHistory = useExportShellHistory();

  const handleExport = async () => {
    try {
      await exportHistory.mutateAsync(shellId);
      toast({
        title: "History exported",
        description: "Shell history has been downloaded",
      });
    } catch (err) {
      toast({
        title: "Export failed",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  // Sort entries chronologically (oldest first)
  const sortedHistory = [...history].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  if (isLoading) {
    return (
      <div className={cn("flex items-center justify-center py-8", className)}>
        <Loader2 className="h-6 w-6 animate-spin text-primary" />
      </div>
    );
  }

  if (error) {
    return (
      <div className={cn("text-center py-8 text-muted-foreground", className)}>
        <p className="text-severity-critical">Failed to load history</p>
        <p className="text-sm">{error instanceof Error ? error.message : "Unknown error"}</p>
      </div>
    );
  }

  return (
    <div className={cn("flex flex-col h-full", className)}>
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-border">
        <div className="flex items-center gap-2">
          <Terminal className="h-5 w-5 text-primary" />
          <h3 className="font-semibold">Command History</h3>
          <Badge variant="secondary">{history.length}</Badge>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handleExport}
          disabled={exportHistory.isPending || history.length === 0}
          className="border-border"
        >
          {exportHistory.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Download className="h-4 w-4 mr-2" />
          )}
          Export
        </Button>
      </div>

      {/* History List */}
      {sortedHistory.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center">
            <Terminal className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>No commands executed yet</p>
            <p className="text-sm">Commands will appear here as you use the shell</p>
          </div>
        </div>
      ) : (
        <ScrollArea className="flex-1 mt-4">
          <div className="space-y-2 pr-4">
            {sortedHistory.map((entry) => (
              <HistoryEntryItem key={entry.id} entry={entry} />
            ))}
          </div>
        </ScrollArea>
      )}
    </div>
  );
}
