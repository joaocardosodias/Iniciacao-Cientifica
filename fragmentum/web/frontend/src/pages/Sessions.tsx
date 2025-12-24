import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { MainLayout } from "@/components/MainLayout";
import { SeverityBadge } from "@/components/SeverityBadge";
import { useSessions, useSession } from "@/hooks/useApi";
import { formatTimestamp, formatDuration } from "@/lib/utils/validators";
import { Session, Finding, SeverityLevel } from "@/types";
import { cn } from "@/lib/utils";
import {
  History,
  Download,
  Filter,
  ChevronRight,
  ExternalLink,
  Clock,
  Target,
  Shield,
  Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export default function Sessions() {
  const { id } = useParams<{ id: string }>();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const { data: sessions = [], isLoading: sessionsLoading } = useSessions();
  const { data: sessionDetail, isLoading: sessionLoading } = useSession(id || "");

  // If viewing a specific session
  if (id) {
    if (sessionLoading) {
      return (
        <MainLayout>
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </div>
        </MainLayout>
      );
    }

    const session = sessionDetail || sessions.find((s) => s.id === id);
    
    if (!session) {
      return (
        <MainLayout>
          <div className="text-center py-12">
            <p className="text-muted-foreground">Session not found</p>
            <Link to="/sessions" className="text-accent hover:underline mt-2 inline-block">
              Back to sessions
            </Link>
          </div>
        </MainLayout>
      );
    }

    const filteredFindings = session.findings.filter((f) => {
      if (severityFilter !== "all" && f.severity !== severityFilter) return false;
      return true;
    });

    return (
      <MainLayout>
        <div className="space-y-6 animate-fade-in">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Link to="/sessions" className="hover:text-foreground">
                  Sessions
                </Link>
                <ChevronRight className="h-4 w-4" />
                <span className="text-foreground">{session.id}</span>
              </div>
              <div className="flex items-center gap-3">
                <h1 className="text-2xl font-bold font-mono text-foreground">
                  {session.target_value}
                </h1>
                <span
                  className={cn(
                    "px-2 py-0.5 text-xs font-medium rounded",
                    session.status === "running"
                      ? "bg-severity-low/20 text-severity-low"
                      : session.status === "completed"
                      ? "bg-severity-info/20 text-severity-info"
                      : "bg-severity-critical/20 text-severity-critical"
                  )}
                >
                  {session.status}
                </span>
              </div>
            </div>
            <Button
              variant="outline"
              className="border-primary/50 text-primary"
            >
              <Download className="h-4 w-4 mr-2" />
              Export JSON
            </Button>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-lg border border-border bg-card">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <Clock className="h-4 w-4" />
                Duration
              </div>
              <p className="mt-1 font-mono text-lg">
                {formatDuration(session.started_at, session.ended_at)}
              </p>
            </div>
            <div className="p-4 rounded-lg border border-border bg-card">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <Target className="h-4 w-4" />
                Started
              </div>
              <p className="mt-1 text-sm">{formatTimestamp(session.started_at)}</p>
            </div>
            <div className="p-4 rounded-lg border border-border bg-card">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <Shield className="h-4 w-4" />
                Findings
              </div>
              <p className="mt-1 font-mono text-lg">{session.findings.length}</p>
            </div>
            <div className="p-4 rounded-lg border border-border bg-card">
              <div className="text-muted-foreground text-sm">Agents</div>
              <div className="mt-1 flex flex-wrap gap-1">
                {session.agents?.map((agent) => (
                  <span
                    key={agent}
                    className="px-1.5 py-0.5 text-xs bg-secondary rounded"
                  >
                    {agent}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Timeline */}
          <div className="rounded-lg border border-border bg-card p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">Timeline</h2>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[150px] bg-secondary border-border">
                  <SelectValue placeholder="All severities" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="relative">
              <div className="absolute left-4 top-0 bottom-0 w-px bg-border" />
              <div className="space-y-4">
                {filteredFindings.map((finding, index) => (
                  <button
                    key={finding.id}
                    onClick={() => setSelectedFinding(finding)}
                    className="relative pl-10 pr-4 py-3 w-full text-left rounded-lg hover:bg-secondary/50 transition-colors"
                  >
                    <div
                      className={cn(
                        "absolute left-2.5 top-4 h-3 w-3 rounded-full border-2 bg-card",
                        finding.severity === "critical" && "border-severity-critical",
                        finding.severity === "high" && "border-severity-high",
                        finding.severity === "medium" && "border-severity-medium",
                        finding.severity === "low" && "border-severity-low",
                        finding.severity === "info" && "border-severity-info"
                      )}
                    />
                    <div className="flex items-center justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={finding.severity} showIcon={false} />
                          <span className="font-medium capitalize">{finding.type}</span>
                        </div>
                        <p className="text-sm text-muted-foreground font-mono">
                          {typeof finding.value === "string"
                            ? finding.value
                            : JSON.stringify(finding.value).slice(0, 60)}
                        </p>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {formatTimestamp(finding.timestamp)}
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Finding Detail Modal */}
        <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
          <DialogContent className="max-w-2xl bg-card border-border">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <SeverityBadge severity={selectedFinding?.severity || "info"} />
                <span className="capitalize">{selectedFinding?.type}</span>
              </DialogTitle>
            </DialogHeader>
            
            {selectedFinding && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Source:</span>
                    <p className="font-mono">{selectedFinding.source}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Timestamp:</span>
                    <p>{formatTimestamp(selectedFinding.timestamp)}</p>
                  </div>
                </div>

                <div>
                  <span className="text-muted-foreground text-sm">Value:</span>
                  <pre className="mt-1 p-3 rounded-lg bg-background font-mono text-sm overflow-auto">
                    {JSON.stringify(selectedFinding.value, null, 2)}
                  </pre>
                </div>

                {Object.keys(selectedFinding.details).length > 0 && (
                  <div>
                    <span className="text-muted-foreground text-sm">Details:</span>
                    <pre className="mt-1 p-3 rounded-lg bg-background font-mono text-sm overflow-auto">
                      {JSON.stringify(selectedFinding.details, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </DialogContent>
        </Dialog>
      </MainLayout>
    );
  }

  // Sessions list view
  const filteredSessions = sessions.filter((s) => {
    if (statusFilter !== "all" && s.status !== statusFilter) return false;
    return true;
  });

  return (
    <MainLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Sessions</h1>
            <p className="text-sm text-muted-foreground">
              View and manage scan sessions
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[150px] bg-secondary border-border">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="error">Error</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Sessions Table */}
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          {sessionsLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : (
          <table className="w-full">
            <thead className="bg-secondary/50">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                  ID
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                  Target
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                  Started
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                  Duration
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                  Findings
                </th>
                <th className="px-4 py-3 text-right text-sm font-medium text-muted-foreground">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredSessions.map((session) => (
                <tr
                  key={session.id}
                  className="hover:bg-secondary/30 transition-colors"
                >
                  <td className="px-4 py-3 font-mono text-sm text-muted-foreground">
                    {session.id.slice(0, 12)}
                  </td>
                  <td className="px-4 py-3 font-mono text-foreground">
                    {session.target_value}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={cn(
                        "px-2 py-0.5 text-xs font-medium rounded",
                        session.status === "running"
                          ? "bg-severity-low/20 text-severity-low"
                          : session.status === "completed"
                          ? "bg-severity-info/20 text-severity-info"
                          : "bg-severity-critical/20 text-severity-critical"
                      )}
                    >
                      {session.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {formatTimestamp(session.started_at)}
                  </td>
                  <td className="px-4 py-3 text-sm font-mono">
                    {formatDuration(session.started_at, session.ended_at)}
                  </td>
                  <td className="px-4 py-3 text-sm">{session.findings.length}</td>
                  <td className="px-4 py-3 text-right">
                    <Link to={`/sessions/${session.id}`}>
                      <Button size="sm" variant="outline" className="border-border">
                        <ExternalLink className="h-3 w-3 mr-1" />
                        View
                      </Button>
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          )}

          {!sessionsLoading && filteredSessions.length === 0 && (
            <div className="text-center py-12 text-muted-foreground">
              No sessions found.
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  );
}
