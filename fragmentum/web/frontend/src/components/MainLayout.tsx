import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";
import { SidebarNavLink } from "@/components/SidebarNavLink";
import { useWebSocket } from "@/hooks/useWebSocket";
import {
  LayoutDashboard,
  Bot,
  Crosshair,
  Target,
  History,
  Terminal,
  Zap,
  ChevronLeft,
  ChevronRight,
  Wifi,
  WifiOff,
} from "lucide-react";

interface MainLayoutProps {
  children: React.ReactNode;
}

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/assistant", icon: Bot, label: "AI Assistant" },
  { to: "/arsenal", icon: Crosshair, label: "Arsenal" },
  { to: "/targets", icon: Target, label: "Targets" },
  { to: "/sessions", icon: History, label: "Sessions" },
  { to: "/shells", icon: Terminal, label: "Shells" },
  { to: "/swarm", icon: Zap, label: "Swarm Attack" },
];

export function MainLayout({ children }: MainLayoutProps) {
  const [collapsed, setCollapsed] = useState(false);
  const { isConnected } = useWebSocket();
  const location = useLocation();

  return (
    <div className="min-h-screen flex w-full bg-background">
      {/* Sidebar */}
      <aside
        className={cn(
          "fixed left-0 top-0 z-40 h-screen border-r border-border bg-sidebar transition-all duration-300",
          collapsed ? "w-16" : "w-64"
        )}
      >
        {/* Logo */}
        <div className="flex h-16 items-center justify-between border-b border-border px-4">
          <Link to="/" className="flex items-center gap-2">
            <Terminal className="h-6 w-6 text-primary" />
            {!collapsed && (
              <span className="font-bold text-lg text-foreground tracking-tight">
                <span className="text-primary">FRAG</span>MENTUM
              </span>
            )}
          </Link>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1.5 rounded-lg hover:bg-muted transition-colors"
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronLeft className="h-4 w-4 text-muted-foreground" />
            )}
          </button>
        </div>

        {/* Navigation */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => (
            <SidebarNavLink
              key={item.to}
              to={item.to}
              icon={item.icon}
              label={item.label}
              collapsed={collapsed}
            />
          ))}
        </nav>

        {/* Footer - Connection Status */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-border">
          <div
            className={cn(
              "flex items-center gap-2 text-xs",
              collapsed && "justify-center"
            )}
          >
            {isConnected ? (
              <Wifi className="h-4 w-4 text-severity-low" />
            ) : (
              <WifiOff className="h-4 w-4 text-severity-critical" />
            )}
            {!collapsed && (
              <span
                className={cn(
                  "font-medium",
                  isConnected ? "text-severity-low" : "text-severity-critical"
                )}
              >
                {isConnected ? "Connected" : "Disconnected"}
              </span>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main
        className={cn(
          "flex-1 transition-all duration-300",
          collapsed ? "ml-16" : "ml-64"
        )}
      >
        {/* Header */}
        <header className="sticky top-0 z-30 h-16 border-b border-border bg-background/80 backdrop-blur-sm">
          <div className="flex h-full items-center justify-between px-6">
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground text-sm">
                {location.pathname === "/"
                  ? "Dashboard"
                  : navItems.find((item) => item.to === location.pathname)?.label ||
                    "FRAGMENTUM"}
              </span>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-xs text-muted-foreground font-mono">
                v1.0.0-alpha
              </span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <div className="p-6">{children}</div>
      </main>
    </div>
  );
}
