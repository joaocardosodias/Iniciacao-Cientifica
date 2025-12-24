import { SeverityLevel } from "@/types";

export const validateIPv4 = (value: string): boolean => {
  const regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!regex.test(value)) return false;
  const parts = value.split(".");
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
};

export const validateDomain = (value: string): boolean => {
  const regex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;
  return regex.test(value);
};

export const validateCIDR = (value: string): boolean => {
  const regex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
  if (!regex.test(value)) return false;
  const [ip, prefix] = value.split("/");
  if (!validateIPv4(ip)) return false;
  const prefixNum = parseInt(prefix, 10);
  return prefixNum >= 0 && prefixNum <= 32;
};

export const detectTargetType = (value: string): "ip" | "domain" | "cidr" | null => {
  if (validateCIDR(value)) return "cidr";
  if (validateIPv4(value)) return "ip";
  if (validateDomain(value)) return "domain";
  return null;
};

export const getSeverityColor = (severity: SeverityLevel): string => {
  const colors: Record<SeverityLevel, string> = {
    critical: "text-severity-critical",
    high: "text-severity-high",
    medium: "text-severity-medium",
    low: "text-severity-low",
    info: "text-severity-info",
  };
  return colors[severity];
};

export const getSeverityBgColor = (severity: SeverityLevel): string => {
  const colors: Record<SeverityLevel, string> = {
    critical: "bg-severity-critical/20",
    high: "bg-severity-high/20",
    medium: "bg-severity-medium/20",
    low: "bg-severity-low/20",
    info: "bg-severity-info/20",
  };
  return colors[severity];
};

export const getSeverityIcon = (severity: SeverityLevel): string => {
  const icons: Record<SeverityLevel, string> = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🟢",
    info: "⚪",
  };
  return icons[severity];
};

export const formatTimestamp = (timestamp: string): string => {
  const date = new Date(timestamp);
  return date.toLocaleString("pt-BR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

export const formatDuration = (start: string, end?: string): string => {
  const startDate = new Date(start);
  const endDate = end ? new Date(end) : new Date();
  const diff = endDate.getTime() - startDate.getTime();
  
  const hours = Math.floor(diff / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((diff % (1000 * 60)) / 1000);
  
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
};

export const getCategoryColor = (category: string): string => {
  const colors: Record<string, string> = {
    scanning: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/50",
    enumeration: "bg-cyber-purple/20 text-cyber-purple border-cyber-purple/50",
    web: "bg-cyber-green/20 text-cyber-green border-cyber-green/50",
    exploit: "bg-cyber-red/20 text-cyber-red border-cyber-red/50",
    password: "bg-cyber-orange/20 text-cyber-orange border-cyber-orange/50",
    osint: "bg-cyber-yellow/20 text-cyber-yellow border-cyber-yellow/50",
    network: "bg-severity-info/20 text-severity-info border-severity-info/50",
    cloud: "bg-primary/20 text-primary border-primary/50",
    binary: "bg-muted text-muted-foreground border-muted-foreground/50",
    forensics: "bg-secondary text-secondary-foreground border-border",
  };
  return colors[category] || "bg-secondary text-secondary-foreground border-border";
};
