import { MainLayout } from "@/components/MainLayout";
import { StatCard } from "@/components/StatCard";
import { SeverityBadge } from "@/components/SeverityBadge";
import { useStats, useSessions, useRecentFindings } from "@/hooks/useApi";
import { formatTimestamp, formatDuration } from "@/lib/utils/validators";
import { Target, History, AlertTriangle, Shield, Activity, ExternalLink, Loader2 } from "lucide-react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";
import { Finding } from "@/types";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useState } from "react";

export default function Dashboard() {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  
  const stats = useStats();
  const { data: sessions, isLoading: sessionsLoading } = useSessions();
  const recentFindings = useRecentFindings(20);

  const severityData = [
    { severity: "critical", count: recentFindings.filter(f => f.severity === "critical").length, color: "bg-severity-critical" },
    { severity: "high", count: recentFindings.filter(f => f.severity === "high").length, color: "bg-severity-high" },
    { severity: "medium", count: recentFindings.filter(f => f.severity === "medium").length, color: "bg-severity-medium" },
    { severity: "low", count: recentFindings.filter(f => f.severity === "low").length, color: "bg-severity-low" },
    { severity: "info", count: recentFindings.filter(f => f.severity === "info").length, color: "bg-severity-info" },
  ];

  const totalFindings = severityData.reduce((acc, s) => acc + s.count, 0);

  return (
    <MainLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Total Targets"
            value={stats.totalTargets}
            icon={Target}
          />
          <StatCard
            title="Active Sessions"
            value={stats.activeSessions}
            icon={Activity}
            variant="success"
          />
          <StatCard
            title="Total Findings"
            value={stats.totalFindings}
            icon={Shield}
          />
          <StatCard
            title="Critical Findings"
            value={stats.criticalFindings}
            icon={AlertTriangle}
            variant="critical"
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Active Sessions */}
          <div className="lg:col-span-2 rounded-lg border border-border bg-card p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <History className="h-5 w-5 text-primary" />
                Active Sessions
              </h2>
              <Link
                to="/sessions"
                className="text-sm text-accent hover:underline flex items-center gap-1"
              >
                View all <ExternalLink className="h-3 w-3" />
              </Link>
            </div>

            <div className="space-y-3">
              {sessionsLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-primary" />
                </div>
              ) : sessions?.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  No sessions yet. Start a scan from the Arsenal.
                </div>
              ) : (
                sessions?.slice(0, 5).map((session) => (
                <Link
                  key={session.id}
                  to={`/sessions/${session.id}`}
                  className="block p-4 rounded-lg border border-border bg-secondary/30 hover:bg-secondary/50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-foreground">
                          {session.target_value}
                        </span>
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
                      <div className="text-xs text-muted-foreground">
                        Started {formatTimestamp(session.started_at)} • Duration:{" "}
                        {formatDuration(session.started_at, session.ended_at)}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-medium text-foreground">
                        {session.findings.length} findings
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {session.agents?.length || 0} agents
                      </div>
                    </div>
                  </div>
                </Link>
              )))}
            </div>
          </div>

          {/* Findings by Severity */}
          <div className="rounded-lg border border-border bg-card p-6">
            <h2 className="text-lg font-semibold mb-4">Findings by Severity</h2>
            
            <div className="space-y-3">
              {severityData.map((item) => (
                <div key={item.severity} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <span className="capitalize text-muted-foreground">{item.severity}</span>
                    <span className="font-medium">{item.count}</span>
                  </div>
                  <div className="h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className={cn("h-full rounded-full transition-all duration-500", item.color)}
                      style={{
                        width: totalFindings > 0 ? `${(item.count / totalFindings) * 100}%` : "0%",
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-6 pt-4 border-t border-border">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Total</span>
                <span className="font-bold text-lg">{totalFindings}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Findings */}
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-primary" />
              Recent Findings
            </h2>
          </div>

          <div className="space-y-2 max-h-[400px] overflow-y-auto">
            {recentFindings.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No findings yet.
              </div>
            ) : (
              recentFindings.map((finding) => (
              <button
                key={finding.id}
                onClick={() => setSelectedFinding(finding)}
                className="w-full text-left p-3 rounded-lg border border-border bg-secondary/20 hover:bg-secondary/40 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={finding.severity} />
                    <span className="font-medium text-foreground capitalize">
                      {finding.type}
                    </span>
                    <span className="text-sm text-muted-foreground font-mono">
                      {typeof finding.value === "string"
                        ? finding.value
                        : JSON.stringify(finding.value).slice(0, 40) + "..."}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {formatTimestamp(finding.timestamp)}
                  </div>
                </div>
              </button>
            )))}
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
                  <span className="text-muted-foreground">Target:</span>
                  <p className="font-mono">{selectedFinding.target}</p>
                </div>
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
