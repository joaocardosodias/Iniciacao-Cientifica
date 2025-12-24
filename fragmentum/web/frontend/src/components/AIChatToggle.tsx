import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Bot, MessageSquare } from "lucide-react";

interface AIChatToggleProps {
  unreadCount: number;
  onClick: () => void;
  isOpen?: boolean;
  className?: string;
}

export function AIChatToggle({ 
  unreadCount, 
  onClick, 
  isOpen = false,
  className 
}: AIChatToggleProps) {
  return (
    <Button
      onClick={onClick}
      variant="cyber"
      size="icon"
      className={cn(
        "fixed bottom-6 right-6 z-50 h-14 w-14 rounded-full shadow-lg",
        "hover:scale-105 transition-all duration-200",
        "hover:shadow-[0_0_30px_hsl(var(--primary)/0.5)]",
        isOpen && "bg-primary text-primary-foreground",
        className
      )}
      aria-label={isOpen ? "Fechar chat" : "Abrir chat com AI"}
    >
      <div className="relative">
        {isOpen ? (
          <MessageSquare className="h-6 w-6" />
        ) : (
          <Bot className="h-6 w-6" />
        )}
        
        {/* Notification badge */}
        {unreadCount > 0 && !isOpen && (
          <span
            className={cn(
              "absolute -top-2 -right-2 flex items-center justify-center",
              "min-w-[20px] h-5 px-1.5 rounded-full",
              "bg-severity-critical text-white text-xs font-bold",
              "animate-pulse"
            )}
          >
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </div>
    </Button>
  );
}
