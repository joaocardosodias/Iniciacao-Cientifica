import { useState } from "react";
import { MainLayout } from "@/components/MainLayout";
import { cn } from "@/lib/utils";
import { ShellConnection, Listener, ShellStatus, ListenerStatus } from "@/types";
import {
  useShells,
  useListeners,
  useCreateListener,
  useStopListener,
  useUpgradeShell,
  useCloseShell,
} from "@/hooks/useShells";
import { formatTimestamp } from "@/lib/utils/validators";
import { ShellTerminal } from "@/components/ShellTerminal";
import { ShellHistory } from "@/components/ShellHistory";
import {
  Terminal,
  Radio,
  Plus,
  Trash2,
  ArrowUpCircle,
  X,
  Loader2,
  Wifi,
  WifiOff,
  Clock,
  Server,
  ExternalLink,
  Maximize2,
  Minimize2,
  History,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";

// Status badge component for shells
function ShellStatusBadge({ status }: { status: ShellStatus }) {
  return (
    <Badge
      className={cn(
        "capitalize",
        status === "connected" && "bg-severity-low/20 text-severity-low border-severity-low/30",
        status === "disconnected" && "bg-severity-critical/20 text-severity-critical border-severity-critical/30",
        status === "idle" && "bg-severity-medium/20 text-severity-medium border-severity-medium/30"
      )}
    >
      {status === "connected" && <Wifi className="h-3 w-3 mr-1" />}
      {status === "disconnected" && <WifiOff className="h-3 w-3 mr-1" />}
      {status === "idle" && <Clock className="h-3 w-3 mr-1" />}
      {status}
    </Badge>
  );
}

// Status badge component for listeners
function ListenerStatusBadge({ status }: { status: ListenerStatus }) {
  return (
    <Badge
      className={cn(
        "capitalize",
        status === "active" && "bg-severity-low/20 text-severity-low border-severity-low/30",
        status === "stopped" && "bg-severity-critical/20 text-severity-critical border-severity-critical/30"
      )}
    >
      {status === "active" && <Radio className="h-3 w-3 mr-1 animate-pulse" />}
      {status}
    </Badge>
  );
}

export default function Shells() {
  const { toast } = useToast();
  const [createListenerOpen, setCreateListenerOpen] = useState(false);
  const [selectedShell, setSelectedShell] = useState<ShellConnection | null>(null);
  const [terminalShell, setTerminalShell] = useState<ShellConnection | null>(null);
  const [isTerminalFullscreen, setIsTerminalFullscreen] = useState(false);
  const [newListenerPort, setNewListenerPort] = useState("");
  const [newListenerProtocol, setNewListenerProtocol] = useState<"tcp" | "udp">("tcp");

  // Data hooks
  const { data: shells = [], isLoading: shellsLoading } = useShells();
  const { data: listeners = [], isLoading: listenersLoading } = useListeners();

  // Mutation hooks
  const createListener = useCreateListener();
  const stopListener = useStopListener();
  const upgradeShell = useUpgradeShell();
  const closeShell = useCloseShell();

  const handleCreateListener = async () => {
    const port = parseInt(newListenerPort, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
      toast({
        title: "Invalid port",
        description: "Port must be a number between 1 and 65535",
        variant: "destructive",
      });
      return;
    }

    try {
      await createListener.mutateAsync({ port, protocol: newListenerProtocol });
      toast({
        title: "Listener created",
        description: `Listening on port ${port}/${newListenerProtocol.toUpperCase()}`,
      });
      setCreateListenerOpen(false);
      setNewListenerPort("");
      setNewListenerProtocol("tcp");
    } catch (error) {
      toast({
        title: "Failed to create listener",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const handleStopListener = async (id: string) => {
    try {
      await stopListener.mutateAsync(id);
      toast({
        title: "Listener stopped",
        description: "The listener has been stopped",
      });
    } catch (error) {
      toast({
        title: "Failed to stop listener",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const handleUpgradeShell = async (id: string) => {
    try {
      const result = await upgradeShell.mutateAsync(id);
      toast({
        title: result.is_pty ? "Shell upgraded" : "Upgrade failed",
        description: result.is_pty
          ? "Shell has been upgraded to PTY"
          : "Could not upgrade shell to PTY",
        variant: result.is_pty ? "default" : "destructive",
      });
      if (selectedShell?.id === id) {
        setSelectedShell({ ...selectedShell, is_pty: result.is_pty });
      }
    } catch (error) {
      toast({
        title: "Failed to upgrade shell",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const handleCloseShell = async (id: string) => {
    try {
      await closeShell.mutateAsync(id);
      toast({
        title: "Shell closed",
        description: "The shell connection has been closed",
      });
      if (selectedShell?.id === id) {
        setSelectedShell(null);
      }
    } catch (error) {
      toast({
        title: "Failed to close shell",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Shell Manager</h1>
            <p className="text-sm text-muted-foreground">
              Manage shell connections and listeners
            </p>
          </div>
          <Button
            onClick={() => setCreateListenerOpen(true)}
            className="bg-primary hover:bg-primary/90"
          >
            <Plus className="h-4 w-4 mr-2" />
            New Listener
          </Button>
        </div>

        {/* Listeners Section */}
        <div className="rounded-lg border border-border bg-card">
          <div className="p-4 border-b border-border">
            <div className="flex items-center gap-2">
              <Radio className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-semibold">Listeners</h2>
              <Badge variant="secondary" className="ml-2">
                {listeners.length}
              </Badge>
            </div>
          </div>

          {listenersLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
          ) : listeners.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Radio className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No active listeners</p>
              <p className="text-sm">Create a listener to receive reverse shells</p>
            </div>
          ) : (
            <div className="divide-y divide-border">
              {listeners.map((listener) => (
                <div
                  key={listener.id}
                  className="p-4 flex items-center justify-between hover:bg-secondary/30 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <div className="p-2 rounded-lg bg-secondary">
                      <Server className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-medium">
                          :{listener.port}
                        </span>
                        <Badge variant="outline" className="text-xs">
                          {listener.protocol.toUpperCase()}
                        </Badge>
                        <ListenerStatusBadge status={listener.status} />
                      </div>
                      <div className="text-sm text-muted-foreground mt-1">
                        {listener.connection_count} connection{listener.connection_count !== 1 ? "s" : ""} •{" "}
                        Created {formatTimestamp(listener.created_at)}
                      </div>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleStopListener(listener.id)}
                    disabled={listener.status === "stopped" || stopListener.isPending}
                    className="border-severity-critical/50 text-severity-critical hover:bg-severity-critical/10"
                  >
                    <Trash2 className="h-4 w-4 mr-1" />
                    Stop
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Shells Section */}
        <div className="rounded-lg border border-border bg-card">
          <div className="p-4 border-b border-border">
            <div className="flex items-center gap-2">
              <Terminal className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-semibold">Active Shells</h2>
              <Badge variant="secondary" className="ml-2">
                {shells.length}
              </Badge>
            </div>
          </div>

          {shellsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
          ) : shells.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Terminal className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No active shells</p>
              <p className="text-sm">Shells will appear here when connections are established</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-secondary/50">
                <tr>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                    Target
                  </th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                    Type
                  </th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                    PTY
                  </th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                    Source
                  </th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                    Last Activity
                  </th>
                  <th className="px-4 py-3 text-right text-sm font-medium text-muted-foreground">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {shells.map((shell) => (
                  <tr
                    key={shell.id}
                    className="hover:bg-secondary/30 transition-colors cursor-pointer"
                    onClick={() => setSelectedShell(shell)}
                  >
                    <td className="px-4 py-3 font-mono text-foreground">
                      {shell.target_ip}:{shell.target_port}
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className="capitalize">
                        {shell.shell_type}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      <ShellStatusBadge status={shell.status} />
                    </td>
                    <td className="px-4 py-3">
                      {shell.is_pty ? (
                        <Badge className="bg-severity-info/20 text-severity-info border-severity-info/30">
                          PTY
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-muted-foreground">
                          Basic
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground capitalize">
                      {shell.source}
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {formatTimestamp(shell.last_activity)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        className="border-border"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedShell(shell);
                        }}
                      >
                        <ExternalLink className="h-3 w-3 mr-1" />
                        Open
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Create Listener Modal */}
      <Dialog open={createListenerOpen} onOpenChange={setCreateListenerOpen}>
        <DialogContent className="bg-card border-border">
          <DialogHeader>
            <DialogTitle>Create New Listener</DialogTitle>
            <DialogDescription>
              Start a listener to receive incoming reverse shell connections.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="port">Port</Label>
              <Input
                id="port"
                type="number"
                placeholder="4444"
                value={newListenerPort}
                onChange={(e) => setNewListenerPort(e.target.value)}
                className="bg-secondary border-border"
                min={1}
                max={65535}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="protocol">Protocol</Label>
              <Select
                value={newListenerProtocol}
                onValueChange={(value: "tcp" | "udp") => setNewListenerProtocol(value)}
              >
                <SelectTrigger className="bg-secondary border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setCreateListenerOpen(false)}
              className="border-border"
            >
              Cancel
            </Button>
            <Button
              onClick={handleCreateListener}
              disabled={createListener.isPending || !newListenerPort}
              className="bg-primary hover:bg-primary/90"
            >
              {createListener.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Create Listener
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Shell Details Panel */}
      <Sheet open={!!selectedShell} onOpenChange={() => setSelectedShell(null)}>
        <SheetContent className="bg-card border-border w-[400px] sm:w-[540px] flex flex-col">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5 text-primary" />
              Shell Details
            </SheetTitle>
            <SheetDescription>
              View shell information, history, and perform actions
            </SheetDescription>
          </SheetHeader>

          {selectedShell && (
            <Tabs defaultValue="details" className="mt-4 flex-1 flex flex-col min-h-0">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="details" className="flex items-center gap-2">
                  <Terminal className="h-4 w-4" />
                  Details
                </TabsTrigger>
                <TabsTrigger value="history" className="flex items-center gap-2">
                  <History className="h-4 w-4" />
                  History
                </TabsTrigger>
              </TabsList>

              <TabsContent value="details" className="flex-1 mt-4 space-y-6">
                {/* Shell Info */}
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <span className="text-sm text-muted-foreground">Target IP</span>
                      <p className="font-mono">{selectedShell.target_ip}</p>
                    </div>
                    <div className="space-y-1">
                      <span className="text-sm text-muted-foreground">Target Port</span>
                      <p className="font-mono">{selectedShell.target_port}</p>
                    </div>
                    <div className="space-y-1">
                      <span className="text-sm text-muted-foreground">Local Port</span>
                      <p className="font-mono">{selectedShell.local_port}</p>
                    </div>
                    <div className="space-y-1">
                      <span className="text-sm text-muted-foreground">Type</span>
                      <p className="capitalize">{selectedShell.shell_type}</p>
                    </div>
                    <div className="space-y-1">
                      <span className="text-sm text-muted-foreground">Status</span>
                      <div>
                        <ShellStatusBadge status={selectedShell.status} />
                      </div>
                    </div>
                    <div className="space-y-1">
                      <span className="text-sm text-muted-foreground">PTY</span>
                      <p>{selectedShell.is_pty ? "Yes" : "No"}</p>
                    </div>
                    <div className="space-y-1">
                      <span className="text-sm text-muted-foreground">Source</span>
                      <p className="capitalize">{selectedShell.source}</p>
                    </div>
                    <div className="space-y-1">
                      <span className="text-sm text-muted-foreground">Created</span>
                      <p className="text-sm">{formatTimestamp(selectedShell.created_at)}</p>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-sm text-muted-foreground">Last Activity</span>
                    <p className="text-sm">{formatTimestamp(selectedShell.last_activity)}</p>
                  </div>

                  <div className="space-y-1">
                    <span className="text-sm text-muted-foreground">Shell ID</span>
                    <p className="font-mono text-xs text-muted-foreground break-all">
                      {selectedShell.id}
                    </p>
                  </div>
                </div>

                {/* Actions */}
                <div className="space-y-3 pt-4 border-t border-border">
                  <h3 className="text-sm font-medium">Actions</h3>

                  <div className="flex flex-col gap-2">
                    {selectedShell.status === "connected" && (
                      <Button
                        onClick={() => {
                          setTerminalShell(selectedShell);
                          setSelectedShell(null);
                        }}
                        className="w-full justify-start bg-primary hover:bg-primary/90"
                      >
                        <Terminal className="h-4 w-4 mr-2" />
                        Open Terminal
                      </Button>
                    )}

                    {!selectedShell.is_pty && selectedShell.status === "connected" && (
                      <Button
                        onClick={() => handleUpgradeShell(selectedShell.id)}
                        disabled={upgradeShell.isPending}
                        className="w-full justify-start"
                        variant="outline"
                      >
                        {upgradeShell.isPending ? (
                          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        ) : (
                          <ArrowUpCircle className="h-4 w-4 mr-2" />
                        )}
                        Upgrade to PTY
                      </Button>
                    )}

                    <Button
                      onClick={() => handleCloseShell(selectedShell.id)}
                      disabled={closeShell.isPending || selectedShell.status === "disconnected"}
                      variant="outline"
                      className="w-full justify-start border-severity-critical/50 text-severity-critical hover:bg-severity-critical/10"
                    >
                      {closeShell.isPending ? (
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <X className="h-4 w-4 mr-2" />
                      )}
                      Close Shell
                    </Button>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="history" className="flex-1 mt-4 min-h-0">
                <ShellHistory shellId={selectedShell.id} className="h-full" />
              </TabsContent>
            </Tabs>
          )}
        </SheetContent>
      </Sheet>

      {/* Terminal Dialog */}
      <Dialog open={!!terminalShell} onOpenChange={() => setTerminalShell(null)}>
        <DialogContent
          className={cn(
            "bg-card border-border p-0 gap-0",
            isTerminalFullscreen
              ? "max-w-[100vw] w-[100vw] h-[100vh] max-h-[100vh] rounded-none"
              : "max-w-4xl w-[90vw] h-[70vh]"
          )}
        >
          {terminalShell && (
            <>
              {/* Terminal Header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-secondary/50">
                <div className="flex items-center gap-3">
                  <Terminal className="h-5 w-5 text-primary" />
                  <div>
                    <h3 className="font-medium text-sm">
                      {terminalShell.target_ip}:{terminalShell.target_port}
                    </h3>
                    <p className="text-xs text-muted-foreground">
                      {terminalShell.is_pty ? "PTY Shell" : "Basic Shell"} • {terminalShell.source}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setIsTerminalFullscreen(!isTerminalFullscreen)}
                    className="h-8 w-8"
                  >
                    {isTerminalFullscreen ? (
                      <Minimize2 className="h-4 w-4" />
                    ) : (
                      <Maximize2 className="h-4 w-4" />
                    )}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setTerminalShell(null)}
                    className="h-8 w-8"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              {/* Terminal Content */}
              <div className="flex-1 h-full min-h-0">
                <ShellTerminal
                  shellId={terminalShell.id}
                  onConnect={() => {
                    toast({
                      title: "Connected",
                      description: `Connected to shell ${terminalShell.target_ip}`,
                    });
                  }}
                  onDisconnect={() => {
                    toast({
                      title: "Disconnected",
                      description: "Shell connection lost",
                      variant: "destructive",
                    });
                  }}
                  onError={(error) => {
                    toast({
                      title: "Error",
                      description: error,
                      variant: "destructive",
                    });
                  }}
                />
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
