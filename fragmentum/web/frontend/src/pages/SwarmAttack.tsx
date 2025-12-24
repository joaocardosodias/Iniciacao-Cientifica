import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { MainLayout } from "@/components/MainLayout";
import { TerminalOutput } from "@/components/TerminalOutput";
import { SeverityBadge } from "@/components/SeverityBadge";
import { useTargets, useStartSwarm, useSwarmStatus } from "@/hooks/useApi";
import { cn } from "@/lib/utils";
import {
  Zap,
  Play,
  Square,
  CheckCircle2,
  Circle,
  Loader2,
  User,
  Globe,
  Network,
  Shield,
  Key,
  Search,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type SwarmPhase = "idle" | "reconnaissance" | "enumeration" | "exploitation" | "post-exploitation" | "completed";

interface Agent {
  id: string;
  name: string;
  icon: React.ElementType;
  status: "idle" | "running" | "completed";
  findings: number;
}

const phaseOrder: SwarmPhase[] = ["reconnaissance", "enumeration", "exploitation", "post-exploitation", "completed"];

export default function SwarmAttack() {
  const [searchParams] = useSearchParams();
  const [target, setTarget] = useState(searchParams.get("target") || "");
  const [enableExploitation, setEnableExploitation] = useState(true);
  const [enablePasswordAttacks, setEnablePasswordAttacks] = useState(true);
  const [aggressiveMode, setAggressiveMode] = useState(false);
  
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [currentPhase, setCurrentPhase] = useState<SwarmPhase>("idle");
  const [output, setOutput] = useState<string[]>([]);
  
  const { data: targets = [] } = useTargets();
  const startSwarmMutation = useStartSwarm();
  const { data: swarmStatus } = useSwarmStatus(currentSessionId);
  
  const isRunning = startSwarmMutation.isPending || swarmStatus?.status === "running";
  
  const [agents, setAgents] = useState<Agent[]>([
    { id: "recon", name: "ReconAgent", icon: Search, status: "idle", findings: 0 },
    { id: "web", name: "WebAgent", icon: Globe, status: "idle", findings: 0 },
    { id: "network", name: "NetworkAgent", icon: Network, status: "idle", findings: 0 },
    { id: "exploit", name: "ExploitAgent", icon: Shield, status: "idle", findings: 0 },
    { id: "password", name: "PasswordAgent", icon: Key, status: "idle", findings: 0 },
    { id: "osint", name: "OSINTAgent", icon: User, status: "idle", findings: 0 },
  ]);

  // Update UI based on swarm status
  useEffect(() => {
    if (swarmStatus) {
      if (swarmStatus.status === "completed") {
        setCurrentPhase("completed");
        setAgents(prev => prev.map(a => ({ ...a, status: "completed" })));
        setOutput(prev => [...prev, "", "[SWARM] Attack completed!", `[SWARM] Total findings: ${swarmStatus.findings?.length || 0}`]);
      } else if (swarmStatus.status === "running") {
        // Update agents based on swarm status
        if (swarmStatus.agents) {
          setAgents(prev => prev.map(a => ({
            ...a,
            status: swarmStatus.agents?.includes(a.name) ? "running" : a.status,
          })));
        }
      }
    }
  }, [swarmStatus]);

  const handleStartSwarm = async () => {
    if (!target) return;
    
    setOutput([]);
    setCurrentPhase("reconnaissance");
    setAgents(prev => prev.map(a => ({ ...a, status: "idle", findings: 0 })));
    
    setOutput([
      `[SWARM] Initializing attack on ${target}`,
      `[SWARM] Options: exploitation=${enableExploitation}, passwords=${enablePasswordAttacks}, aggressive=${aggressiveMode}`,
      "",
    ]);
    
    try {
      const result = await startSwarmMutation.mutateAsync({
        target,
        options: {
          enable_exploitation: enableExploitation,
          enable_password_attacks: enablePasswordAttacks,
          aggressive_mode: aggressiveMode,
        },
      });
      setCurrentSessionId(result.session_id);
      setOutput(prev => [...prev, `[SWARM] Session started: ${result.session_id}`]);
    } catch (error) {
      setOutput(prev => [...prev, "[SWARM] Error: Failed to start swarm attack"]);
      setCurrentPhase("idle");
    }
  };

  const handleStopSwarm = () => {
    setCurrentSessionId(null);
    setCurrentPhase("idle");
    setOutput(prev => [...prev, "", "[SWARM] Attack stopped by user"]);
  };

  const getPhaseStatus = (phase: SwarmPhase) => {
    if (currentPhase === "idle") return "pending";
    const currentIndex = phaseOrder.indexOf(currentPhase);
    const phaseIndex = phaseOrder.indexOf(phase);
    
    if (phaseIndex < currentIndex) return "completed";
    if (phaseIndex === currentIndex) return "active";
    return "pending";
  };

  return (
    <MainLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <Zap className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Swarm Attack</h1>
            <p className="text-sm text-muted-foreground">
              Multi-agent coordinated attack
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Configuration Panel */}
          <div className="lg:col-span-1 space-y-6">
            <div className="rounded-lg border border-border bg-card p-6">
              <h2 className="text-lg font-semibold mb-4">Configuration</h2>
              
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Target</Label>
                  <Select value={target} onValueChange={setTarget}>
                    <SelectTrigger className="bg-secondary border-border">
                      <SelectValue placeholder="Select or enter target" />
                    </SelectTrigger>
                    <SelectContent>
                      {targets.map((t) => (
                        <SelectItem key={t.id} value={t.value}>
                          {t.value}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Input
                    placeholder="Or enter custom target..."
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    className="bg-secondary border-border font-mono"
                  />
                </div>

                <div className="space-y-3 pt-2">
                  <div className="flex items-center gap-2">
                    <Checkbox
                      id="exploitation"
                      checked={enableExploitation}
                      onCheckedChange={(c) => setEnableExploitation(!!c)}
                    />
                    <Label htmlFor="exploitation" className="text-sm">
                      Enable Exploitation
                    </Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Checkbox
                      id="passwords"
                      checked={enablePasswordAttacks}
                      onCheckedChange={(c) => setEnablePasswordAttacks(!!c)}
                    />
                    <Label htmlFor="passwords" className="text-sm">
                      Enable Password Attacks
                    </Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Checkbox
                      id="aggressive"
                      checked={aggressiveMode}
                      onCheckedChange={(c) => setAggressiveMode(!!c)}
                    />
                    <Label htmlFor="aggressive" className="text-sm text-severity-high">
                      Aggressive Mode
                    </Label>
                  </div>
                </div>

                <Button
                  onClick={isRunning ? handleStopSwarm : handleStartSwarm}
                  disabled={!target}
                  className={cn(
                    "w-full mt-4",
                    isRunning
                      ? "bg-severity-critical hover:bg-severity-critical/90"
                      : "bg-primary hover:bg-primary/90"
                  )}
                >
                  {isRunning ? (
                    <>
                      <Square className="h-4 w-4 mr-2" />
                      Stop Attack
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Start Swarm
                    </>
                  )}
                </Button>
              </div>
            </div>

            {/* Agents Status */}
            <div className="rounded-lg border border-border bg-card p-6">
              <h2 className="text-lg font-semibold mb-4">Agents</h2>
              <div className="space-y-3">
                {agents.map((agent) => {
                  const Icon = agent.icon;
                  return (
                    <div
                      key={agent.id}
                      className={cn(
                        "flex items-center justify-between p-3 rounded-lg border",
                        agent.status === "running"
                          ? "border-primary/50 bg-primary/5"
                          : agent.status === "completed"
                          ? "border-severity-low/50 bg-severity-low/5"
                          : "border-border bg-secondary/30"
                      )}
                    >
                      <div className="flex items-center gap-2">
                        <Icon className={cn(
                          "h-4 w-4",
                          agent.status === "running" ? "text-primary" :
                          agent.status === "completed" ? "text-severity-low" :
                          "text-muted-foreground"
                        )} />
                        <span className="text-sm font-medium">{agent.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">
                          {agent.findings} findings
                        </span>
                        {agent.status === "running" && (
                          <Loader2 className="h-3 w-3 animate-spin text-primary" />
                        )}
                        {agent.status === "completed" && (
                          <CheckCircle2 className="h-3 w-3 text-severity-low" />
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Attack Progress */}
          <div className="lg:col-span-2 space-y-6">
            {/* Phase Progress */}
            <div className="rounded-lg border border-border bg-card p-6">
              <h2 className="text-lg font-semibold mb-4">Attack Phases</h2>
              <div className="flex items-center justify-between">
                {phaseOrder.slice(0, -1).map((phase, index) => {
                  const status = getPhaseStatus(phase);
                  return (
                    <div key={phase} className="flex items-center">
                      <div className="flex flex-col items-center">
                        <div
                          className={cn(
                            "h-10 w-10 rounded-full flex items-center justify-center border-2 transition-all",
                            status === "completed"
                              ? "bg-severity-low border-severity-low text-primary-foreground"
                              : status === "active"
                              ? "bg-primary/20 border-primary text-primary animate-pulse"
                              : "bg-secondary border-border text-muted-foreground"
                          )}
                        >
                          {status === "completed" ? (
                            <CheckCircle2 className="h-5 w-5" />
                          ) : status === "active" ? (
                            <Loader2 className="h-5 w-5 animate-spin" />
                          ) : (
                            <Circle className="h-5 w-5" />
                          )}
                        </div>
                        <span className="mt-2 text-xs capitalize text-center max-w-[80px]">
                          {phase.replace("-", " ")}
                        </span>
                      </div>
                      {index < phaseOrder.length - 2 && (
                        <div
                          className={cn(
                            "w-16 h-0.5 mx-2",
                            status === "completed" ? "bg-severity-low" : "bg-border"
                          )}
                        />
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Live Feed */}
            <TerminalOutput
              lines={output}
              title="Live Feed"
              isStreaming={isRunning}
              maxHeight="500px"
            />
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
