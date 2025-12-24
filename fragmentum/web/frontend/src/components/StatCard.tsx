import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: number | string;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  variant?: "default" | "critical" | "success" | "warning";
  className?: string;
}

const variantStyles = {
  default: "border-border hover:border-primary/50",
  critical: "border-severity-critical/30 hover:border-severity-critical/60 bg-severity-critical/5",
  success: "border-severity-low/30 hover:border-severity-low/60 bg-severity-low/5",
  warning: "border-severity-high/30 hover:border-severity-high/60 bg-severity-high/5",
};

const iconVariantStyles = {
  default: "text-primary",
  critical: "text-severity-critical",
  success: "text-severity-low",
  warning: "text-severity-high",
};

export function StatCard({ title, value, icon: Icon, trend, variant = "default", className }: StatCardProps) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-lg border bg-card p-6 transition-all duration-300 hover:shadow-lg",
        variantStyles[variant],
        className
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-muted-foreground">{title}</p>
          <p className="mt-2 text-3xl font-bold text-foreground">{value}</p>
          {trend && (
            <p
              className={cn(
                "mt-1 text-xs",
                trend.isPositive ? "text-severity-low" : "text-severity-critical"
              )}
            >
              {trend.isPositive ? "↑" : "↓"} {Math.abs(trend.value)}% from last week
            </p>
          )}
        </div>
        <div className={cn("rounded-lg bg-muted p-3", iconVariantStyles[variant])}>
          <Icon className="h-6 w-6" />
        </div>
      </div>
      
      {/* Decorative gradient */}
      <div
        className={cn(
          "absolute -bottom-4 -right-4 h-24 w-24 rounded-full opacity-10 blur-2xl",
          variant === "critical" && "bg-severity-critical",
          variant === "success" && "bg-severity-low",
          variant === "warning" && "bg-severity-high",
          variant === "default" && "bg-primary"
        )}
      />
    </div>
  );
}
