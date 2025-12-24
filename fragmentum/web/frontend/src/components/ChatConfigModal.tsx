/**
 * Chat Configuration Modal
 * 
 * Provides UI for configuring the AI chat LLM provider settings.
 * Supports Claude, OpenAI, and Ollama providers.
 * 
 * Requirements:
 * - 2.1: Support Claude API as a provider option
 * - 2.2: Support OpenAI API as a provider option
 * - 2.3: Support Ollama local models as a provider option
 * - 2.4: Display setup prompt with instructions when no API key is configured
 */

import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Bot,
  Cloud,
  Server,
  Key,
  AlertCircle,
  CheckCircle2,
  Loader2,
  ExternalLink,
} from "lucide-react";
import { useChatConfig, useChatConfigStatus, useUpdateChatConfig } from "@/hooks/useAIChat";
import type { ChatConfig, ChatConfigUpdate } from "@/hooks/useAIChat";

interface ChatConfigModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type Provider = "claude" | "openai" | "ollama" | "gemini" | "groq" | "cerebras" | "grok" | "deepseek" | "together" | "mistral";

interface ProviderInfo {
  name: string;
  description: string;
  icon: React.ReactNode;
  requiresApiKey: boolean;
  defaultModel: string;
  models: string[];
  docsUrl?: string;
}

const PROVIDERS: Record<Provider, ProviderInfo> = {
  claude: {
    name: "Claude (Anthropic)",
    description: "Powerful AI assistant by Anthropic",
    icon: <Bot className="h-5 w-5" />,
    requiresApiKey: true,
    defaultModel: "claude-sonnet-4-20250514",
    models: [
      "claude-sonnet-4-20250514",
      "claude-3-5-sonnet-20241022",
      "claude-3-opus-20240229",
      "claude-3-haiku-20240307",
    ],
    docsUrl: "https://console.anthropic.com/",
  },
  openai: {
    name: "OpenAI",
    description: "GPT models by OpenAI",
    icon: <Cloud className="h-5 w-5" />,
    requiresApiKey: true,
    defaultModel: "gpt-4",
    models: [
      "gpt-4",
      "gpt-4-turbo",
      "gpt-4o",
      "gpt-4o-mini",
      "gpt-3.5-turbo",
    ],
    docsUrl: "https://platform.openai.com/api-keys",
  },
  gemini: {
    name: "Gemini (Google)",
    description: "Google's most capable AI model",
    icon: <Cloud className="h-5 w-5 text-blue-500" />,
    requiresApiKey: true,
    defaultModel: "gemini-2.0-flash-exp",
    models: [
      "gemini-2.0-flash-exp",
      "gemini-1.5-pro",
      "gemini-1.5-flash",
      "gemini-1.5-flash-8b",
    ],
    docsUrl: "https://aistudio.google.com/apikey",
  },
  groq: {
    name: "Groq",
    description: "Ultra-fast inference with LPU hardware",
    icon: <Cloud className="h-5 w-5 text-orange-500" />,
    requiresApiKey: true,
    defaultModel: "llama-3.3-70b-versatile",
    models: [
      "llama-3.3-70b-versatile",
      "llama-3.1-70b-versatile",
      "llama-3.1-8b-instant",
      "llama3-70b-8192",
      "mixtral-8x7b-32768",
      "gemma2-9b-it",
    ],
    docsUrl: "https://console.groq.com/keys",
  },
  cerebras: {
    name: "Cerebras",
    description: "Fast inference on wafer-scale chips",
    icon: <Cloud className="h-5 w-5 text-purple-500" />,
    requiresApiKey: true,
    defaultModel: "llama3.1-70b",
    models: [
      "llama3.1-70b",
      "llama3.1-8b",
    ],
    docsUrl: "https://cloud.cerebras.ai/",
  },
  grok: {
    name: "Grok (xAI)",
    description: "Elon Musk's AI with real-time knowledge",
    icon: <Cloud className="h-5 w-5 text-gray-400" />,
    requiresApiKey: true,
    defaultModel: "grok-beta",
    models: [
      "grok-beta",
      "grok-2-1212",
      "grok-2-vision-1212",
    ],
    docsUrl: "https://console.x.ai/",
  },
  deepseek: {
    name: "DeepSeek",
    description: "Powerful models at competitive prices",
    icon: <Cloud className="h-5 w-5 text-cyan-500" />,
    requiresApiKey: true,
    defaultModel: "deepseek-chat",
    models: [
      "deepseek-chat",
      "deepseek-coder",
      "deepseek-reasoner",
    ],
    docsUrl: "https://platform.deepseek.com/",
  },
  together: {
    name: "Together AI",
    description: "Open source models with fast inference",
    icon: <Cloud className="h-5 w-5 text-green-500" />,
    requiresApiKey: true,
    defaultModel: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    models: [
      "meta-llama/Llama-3.3-70B-Instruct-Turbo",
      "meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
      "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
      "mistralai/Mixtral-8x22B-Instruct-v0.1",
      "Qwen/Qwen2.5-72B-Instruct-Turbo",
      "deepseek-ai/DeepSeek-V3",
    ],
    docsUrl: "https://api.together.xyz/settings/api-keys",
  },
  mistral: {
    name: "Mistral AI",
    description: "European AI lab with powerful models",
    icon: <Cloud className="h-5 w-5 text-amber-500" />,
    requiresApiKey: true,
    defaultModel: "mistral-large-latest",
    models: [
      "mistral-large-latest",
      "mistral-small-latest",
      "codestral-latest",
      "ministral-8b-latest",
      "open-mistral-nemo",
    ],
    docsUrl: "https://console.mistral.ai/api-keys/",
  },
  ollama: {
    name: "Ollama (Local)",
    description: "Run models locally - 100% private",
    icon: <Server className="h-5 w-5" />,
    requiresApiKey: false,
    defaultModel: "llama3",
    models: [
      "llama3",
      "llama3:70b",
      "mistral",
      "mixtral",
      "codellama",
      "deepseek-coder",
      "qwen2.5",
    ],
    docsUrl: "https://ollama.ai/",
  },
};

export function ChatConfigModal({ open, onOpenChange }: ChatConfigModalProps) {
  const { data: config, isLoading: configLoading } = useChatConfig();
  const { data: status, isLoading: statusLoading } = useChatConfigStatus();
  const updateConfig = useUpdateChatConfig();

  // Local form state
  const [provider, setProvider] = useState<Provider>("ollama");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [ollamaUrl, setOllamaUrl] = useState("http://localhost:11434");
  const [temperature, setTemperature] = useState(0.7);
  const [maxTokens, setMaxTokens] = useState(4096);
  const [showApiKey, setShowApiKey] = useState(false);

  // Sync form state with loaded config
  useEffect(() => {
    if (config) {
      setProvider(config.provider);
      setModel(config.model);
      setOllamaUrl(config.ollama_url || "http://localhost:11434");
      setTemperature(config.temperature);
      setMaxTokens(config.max_tokens);
    }
  }, [config]);

  // Reset model when provider changes
  useEffect(() => {
    const providerInfo = PROVIDERS[provider];
    if (providerInfo && !providerInfo.models.includes(model)) {
      setModel(providerInfo.defaultModel);
    }
  }, [provider, model]);

  const handleSave = async () => {
    const update: ChatConfigUpdate = {
      provider,
      model,
      temperature,
      max_tokens: maxTokens,
    };

    if (provider === "ollama") {
      update.ollama_url = ollamaUrl;
    } else if (apiKey) {
      update.api_key = apiKey;
    }

    try {
      await updateConfig.mutateAsync(update);
      setApiKey(""); // Clear API key from form after save
      onOpenChange(false);
    } catch (error) {
      console.error("Failed to update config:", error);
    }
  };

  const providerInfo = PROVIDERS[provider];
  const isLoading = configLoading || statusLoading;
  const needsApiKey = providerInfo?.requiresApiKey && !status?.has_api_key;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Bot className="h-5 w-5 text-primary" />
            AI Chat Configuration
          </DialogTitle>
          <DialogDescription>
            Configure the LLM provider for the AI assistant.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </div>
        ) : (
          <div className="space-y-6 py-4">
            {/* Provider Selection */}
            <div className="space-y-2">
              <Label htmlFor="provider">Provider</Label>
              <Select value={provider} onValueChange={(v) => setProvider(v as Provider)}>
                <SelectTrigger id="provider">
                  <SelectValue placeholder="Select provider" />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(PROVIDERS).map(([key, info]) => (
                    <SelectItem key={key} value={key}>
                      <div className="flex items-center gap-2">
                        {info.icon}
                        <span>{info.name}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {providerInfo?.description}
              </p>
            </div>

            {/* Model Selection */}
            <div className="space-y-2">
              <Label htmlFor="model">Model</Label>
              <Select value={model} onValueChange={setModel}>
                <SelectTrigger id="model">
                  <SelectValue placeholder="Select model" />
                </SelectTrigger>
                <SelectContent>
                  {providerInfo?.models.map((m) => (
                    <SelectItem key={m} value={m}>
                      {m}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* API Key (for cloud providers) */}
            {providerInfo?.requiresApiKey && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="apiKey">API Key</Label>
                  {providerInfo.docsUrl && (
                    <a
                      href={providerInfo.docsUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline flex items-center gap-1"
                    >
                      Get API Key
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </div>
                <div className="relative">
                  <Input
                    id="apiKey"
                    type={showApiKey ? "text" : "password"}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={status?.has_api_key ? "••••••••••••••••" : "Enter API key"}
                    className="pr-10"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-0 top-0 h-full px-3"
                    onClick={() => setShowApiKey(!showApiKey)}
                  >
                    <Key className="h-4 w-4" />
                  </Button>
                </div>
                {status?.has_api_key ? (
                  <p className="text-xs text-muted-foreground flex items-center gap-1">
                    <CheckCircle2 className="h-3 w-3 text-green-500" />
                    API key is configured. Enter a new key to update.
                  </p>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    Your API key is stored securely and never exposed.
                  </p>
                )}
              </div>
            )}

            {/* Ollama URL (for local provider) */}
            {provider === "ollama" && (
              <div className="space-y-2">
                <Label htmlFor="ollamaUrl">Ollama Server URL</Label>
                <Input
                  id="ollamaUrl"
                  value={ollamaUrl}
                  onChange={(e) => setOllamaUrl(e.target.value)}
                  placeholder="http://localhost:11434"
                />
                <p className="text-xs text-muted-foreground">
                  Make sure Ollama is running locally.{" "}
                  <a
                    href="https://ollama.ai/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  >
                    Download Ollama
                  </a>
                </p>
              </div>
            )}

            {/* Temperature */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="temperature">Temperature</Label>
                <span className="text-sm text-muted-foreground">{temperature.toFixed(1)}</span>
              </div>
              <Slider
                id="temperature"
                min={0}
                max={2}
                step={0.1}
                value={[temperature]}
                onValueChange={([v]) => setTemperature(v)}
              />
              <p className="text-xs text-muted-foreground">
                Lower values make responses more focused, higher values more creative.
              </p>
            </div>

            {/* Max Tokens */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="maxTokens">Max Tokens</Label>
                <span className="text-sm text-muted-foreground">{maxTokens}</span>
              </div>
              <Slider
                id="maxTokens"
                min={256}
                max={16384}
                step={256}
                value={[maxTokens]}
                onValueChange={([v]) => setMaxTokens(v)}
              />
              <p className="text-xs text-muted-foreground">
                Maximum length of the AI response.
              </p>
            </div>

            {/* Warning for missing API key */}
            {needsApiKey && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>API Key Required</AlertTitle>
                <AlertDescription>
                  {status?.message || `Please configure an API key for ${providerInfo?.name}.`}
                </AlertDescription>
              </Alert>
            )}

            {/* Status message */}
            {status?.configured && !needsApiKey && (
              <Alert>
                <CheckCircle2 className="h-4 w-4 text-green-500" />
                <AlertTitle>Ready</AlertTitle>
                <AlertDescription>
                  {status.message || `Using ${PROVIDERS[status.provider as Provider]?.name || status.provider} with ${status.model}`}
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            disabled={updateConfig.isPending || (needsApiKey && !apiKey)}
          >
            {updateConfig.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : (
              "Save Configuration"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
