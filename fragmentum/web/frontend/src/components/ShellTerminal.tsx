import { useEffect, useRef, useCallback } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { useShellWebSocket } from "@/hooks/useShellWebSocket";
import "@xterm/xterm/css/xterm.css";

interface ShellTerminalProps {
  shellId: string;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: string) => void;
}

export function ShellTerminal({
  shellId,
  onConnect,
  onDisconnect,
  onError,
}: ShellTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  // Handle terminal output from WebSocket
  const handleOutput = useCallback((data: string) => {
    if (xtermRef.current) {
      xtermRef.current.write(data);
    }
  }, []);

  // WebSocket connection
  const { isConnected, error, sendInput, sendResize } = useShellWebSocket(
    shellId,
    {
      onOutput: handleOutput,
      onConnect,
      onDisconnect,
      onError,
    }
  );

  // Initialize terminal
  useEffect(() => {
    if (!terminalRef.current || xtermRef.current) return;

    // Create terminal with FRAGMENTUM dark theme
    const terminal = new Terminal({
      cursorBlink: true,
      cursorStyle: "block",
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 14,
      lineHeight: 1.2,
      theme: {
        background: "hsl(240, 10%, 4%)",
        foreground: "hsl(240, 5%, 90%)",
        cursor: "hsl(160, 100%, 50%)",
        cursorAccent: "hsl(240, 10%, 4%)",
        selectionBackground: "hsl(160, 100%, 50%, 0.3)",
        black: "hsl(240, 10%, 10%)",
        red: "hsl(0, 100%, 63%)",
        green: "hsl(155, 100%, 50%)",
        yellow: "hsl(45, 100%, 50%)",
        blue: "hsl(210, 100%, 60%)",
        magenta: "hsl(270, 100%, 63%)",
        cyan: "hsl(195, 100%, 50%)",
        white: "hsl(240, 5%, 90%)",
        brightBlack: "hsl(240, 10%, 30%)",
        brightRed: "hsl(0, 100%, 70%)",
        brightGreen: "hsl(155, 100%, 60%)",
        brightYellow: "hsl(45, 100%, 60%)",
        brightBlue: "hsl(210, 100%, 70%)",
        brightMagenta: "hsl(270, 100%, 70%)",
        brightCyan: "hsl(195, 100%, 60%)",
        brightWhite: "hsl(240, 5%, 100%)",
      },
      allowProposedApi: true,
    });

    // Create fit addon for auto-resize
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);

    // Open terminal in container
    terminal.open(terminalRef.current);
    fitAddon.fit();

    // Store refs
    xtermRef.current = terminal;
    fitAddonRef.current = fitAddon;

    // Handle user input
    terminal.onData((data) => {
      sendInput(data);
    });

    // Send initial size
    sendResize(terminal.cols, terminal.rows);

    // Cleanup
    return () => {
      terminal.dispose();
      xtermRef.current = null;
      fitAddonRef.current = null;
    };
  }, [shellId, sendInput, sendResize]);

  // Handle window resize
  useEffect(() => {
    const handleResize = () => {
      if (fitAddonRef.current && xtermRef.current) {
        fitAddonRef.current.fit();
        sendResize(xtermRef.current.cols, xtermRef.current.rows);
      }
    };

    window.addEventListener("resize", handleResize);

    // Also observe container size changes
    const resizeObserver = new ResizeObserver(() => {
      handleResize();
    });

    if (terminalRef.current) {
      resizeObserver.observe(terminalRef.current);
    }

    return () => {
      window.removeEventListener("resize", handleResize);
      resizeObserver.disconnect();
    };
  }, [sendResize]);

  // Focus terminal when connected
  useEffect(() => {
    if (isConnected && xtermRef.current) {
      xtermRef.current.focus();
    }
  }, [isConnected]);

  return (
    <div className="shell-terminal-container relative w-full h-full min-h-[300px]">
      {/* Connection status indicator */}
      <div className="absolute top-2 right-2 z-10 flex items-center gap-2">
        <div
          className={`w-2 h-2 rounded-full ${
            isConnected ? "bg-severity-low animate-pulse" : "bg-severity-critical"
          }`}
        />
        <span className="text-xs text-muted-foreground">
          {isConnected ? "Connected" : "Disconnected"}
        </span>
      </div>

      {/* Error display */}
      {error && (
        <div className="absolute top-2 left-2 z-10 px-2 py-1 bg-severity-critical/20 border border-severity-critical/50 rounded text-xs text-severity-critical">
          {error}
        </div>
      )}

      {/* Terminal container */}
      <div
        ref={terminalRef}
        className="w-full h-full rounded-lg overflow-hidden"
        style={{ padding: "8px" }}
      />
    </div>
  );
}
