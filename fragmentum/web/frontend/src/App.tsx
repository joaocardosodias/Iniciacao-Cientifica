import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ChatProvider } from "@/contexts/ChatContext";
import Dashboard from "./pages/Dashboard";
import Assistant from "./pages/Assistant";
import Arsenal from "./pages/Arsenal";
import Targets from "./pages/Targets";
import Sessions from "./pages/Sessions";
import Shells from "./pages/Shells";
import SwarmAttack from "./pages/SwarmAttack";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <ChatProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/assistant" element={<Assistant />} />
            <Route path="/arsenal" element={<Arsenal />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route path="/sessions/:id" element={<Sessions />} />
            <Route path="/shells" element={<Shells />} />
            <Route path="/swarm" element={<SwarmAttack />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </ChatProvider>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
