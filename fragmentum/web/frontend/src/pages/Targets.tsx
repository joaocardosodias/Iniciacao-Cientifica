import { useState } from "react";
import { MainLayout } from "@/components/MainLayout";
import { useTargets, useAddTarget, useDeleteTarget } from "@/hooks/useApi";
import { Target } from "@/types";
import { detectTargetType, formatTimestamp } from "@/lib/utils/validators";
import { Plus, Trash2, Zap, Globe, Server, Network, X, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { toast } from "@/hooks/use-toast";
import { Link } from "react-router-dom";

const typeIcons = {
  ip: Server,
  domain: Globe,
  cidr: Network,
};

const typeColors = {
  ip: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/50",
  domain: "bg-cyber-green/20 text-cyber-green border-cyber-green/50",
  cidr: "bg-cyber-purple/20 text-cyber-purple border-cyber-purple/50",
};

export default function Targets() {
  const { data: targets = [], isLoading } = useTargets();
  const addTargetMutation = useAddTarget();
  const deleteTargetMutation = useDeleteTarget();
  
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [targetToDelete, setTargetToDelete] = useState<Target | null>(null);
  const [newTargetValue, setNewTargetValue] = useState("");
  const [detectedType, setDetectedType] = useState<"ip" | "domain" | "cidr" | null>(null);

  const handleTargetInputChange = (value: string) => {
    setNewTargetValue(value);
    setDetectedType(detectTargetType(value));
  };

  const handleAddTarget = async () => {
    if (!detectedType) {
      toast({
        title: "Invalid format",
        description: "Please enter a valid IP, domain, or CIDR",
        variant: "destructive",
      });
      return;
    }

    try {
      await addTargetMutation.mutateAsync({ value: newTargetValue, type: detectedType });
      setNewTargetValue("");
      setDetectedType(null);
      setIsAddModalOpen(false);
      toast({
        title: "Target added",
        description: `${newTargetValue} has been added to your targets`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to add target. Is the backend running?",
        variant: "destructive",
      });
    }
  };

  const handleDeleteTarget = async () => {
    if (!targetToDelete) return;

    try {
      await deleteTargetMutation.mutateAsync(targetToDelete.id);
      toast({
        title: "Target deleted",
        description: `${targetToDelete.value} has been removed`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to delete target",
        variant: "destructive",
      });
    }
    setTargetToDelete(null);
  };

  return (
    <MainLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Targets</h1>
            <p className="text-sm text-muted-foreground">
              Manage your attack targets
            </p>
          </div>
          <Button
            onClick={() => setIsAddModalOpen(true)}
            className="bg-primary text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-4 w-4 mr-2" />
            Add Target
          </Button>
        </div>

        {/* Targets Table */}
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
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
                  Sessions
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">
                  Created
                </th>
                <th className="px-4 py-3 text-right text-sm font-medium text-muted-foreground">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {targets.map((target) => {
                const Icon = typeIcons[target.type];
                return (
                  <tr
                    key={target.id}
                    className="hover:bg-secondary/30 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                        <span className="font-mono text-foreground">
                          {target.value}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          "inline-flex px-2 py-0.5 text-xs font-medium rounded border uppercase",
                          typeColors[target.type]
                        )}
                      >
                        {target.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {target.session_count}
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {formatTimestamp(target.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <Link to={`/swarm?target=${target.value}`}>
                          <Button
                            size="sm"
                            variant="outline"
                            className="border-primary/50 text-primary hover:bg-primary hover:text-primary-foreground"
                          >
                            <Zap className="h-3 w-3 mr-1" />
                            Swarm
                          </Button>
                        </Link>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setTargetToDelete(target)}
                          className="border-severity-critical/50 text-severity-critical hover:bg-severity-critical hover:text-foreground"
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          )}

          {!isLoading && targets.length === 0 && (
            <div className="text-center py-12 text-muted-foreground">
              No targets yet. Add your first target to get started.
            </div>
          )}
        </div>
      </div>

      {/* Add Target Modal */}
      <Dialog open={isAddModalOpen} onOpenChange={setIsAddModalOpen}>
        <DialogContent className="bg-card border-border">
          <DialogHeader>
            <DialogTitle>Add Target</DialogTitle>
            <DialogDescription>
              Enter an IP address, domain, or CIDR range
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Input
                placeholder="e.g., 192.168.1.1, example.com, 10.0.0.0/24"
                value={newTargetValue}
                onChange={(e) => handleTargetInputChange(e.target.value)}
                className="bg-secondary border-border font-mono"
              />
              {newTargetValue && (
                <div className="flex items-center gap-2 text-sm">
                  {detectedType ? (
                    <>
                      <span className="text-severity-low">✓</span>
                      <span className="text-muted-foreground">
                        Detected as{" "}
                        <span
                          className={cn(
                            "px-1.5 py-0.5 rounded text-xs font-medium uppercase",
                            typeColors[detectedType]
                          )}
                        >
                          {detectedType}
                        </span>
                      </span>
                    </>
                  ) : (
                    <>
                      <span className="text-severity-critical">✗</span>
                      <span className="text-muted-foreground">Invalid format</span>
                    </>
                  )}
                </div>
              )}
            </div>

            <div className="flex gap-2 justify-end">
              <Button
                variant="outline"
                onClick={() => setIsAddModalOpen(false)}
              >
                Cancel
              </Button>
              <Button
                onClick={handleAddTarget}
                disabled={!detectedType}
                className="bg-primary text-primary-foreground"
              >
                <Plus className="h-4 w-4 mr-2" />
                Add Target
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog
        open={!!targetToDelete}
        onOpenChange={() => setTargetToDelete(null)}
      >
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Target</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete{" "}
              <span className="font-mono text-foreground">
                {targetToDelete?.value}
              </span>
              ? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteTarget}
              className="bg-severity-critical text-foreground hover:bg-severity-critical/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </MainLayout>
  );
}
