import { cn } from "@/lib/utils";
import { SeverityLevel } from "@/types";

interface SeverityBadgeProps {
  severity: SeverityLevel;
  showIcon?: boolean;
  className?: string;
}

const severityConfig: Record<SeverityLevel, { icon: string; classes: string }> = {
  critical: {
    icon: "🔴",
    classes: "bg-severity-critical/20 text-severity-critical border-severity-critical/50",
  },
  high: {
    icon: "🟠",
    classes: "bg-severity-high/20 text-severity-high border-severity-high/50",
  },
  medium: {
    icon: "🟡",
    classes: "bg-severity-medium/20 text-severity-medium border-severity-medium/50",
  },
  low: {
    icon: "🟢",
    classes: "bg-severity-low/20 text-severity-low border-severity-low/50",
  },
  info: {
    icon: "⚪",
    classes: "bg-severity-info/20 text-severity-info border-severity-info/50",
  },
};

export function SeverityBadge({ severity, showIcon = true, className }: SeverityBadgeProps) {
  const config = severityConfig[severity];

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded border uppercase tracking-wide",
        config.classes,
        className
      )}
    >
      {showIcon && <span>{config.icon}</span>}
      {severity}
    </span>
  );
}
