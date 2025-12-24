import { useState, useMemo, useRef, useEffect } from "react";
import { MainLayout } from "@/components/MainLayout";
import { CategoryBadge } from "@/components/CategoryBadge";
import { TerminalOutput } from "@/components/TerminalOutput";
import { useTools, useExecuteTool, useJobStatus, useExecuteShell } from "@/hooks/useApi";
import { useJobStream } from "@/hooks/useWebSocket";
import { Tool, ToolCategory, ToolItem, ToolGroup, StandaloneTool } from "@/types";
import { Search, Play, Loader2, ChevronDown, Layers, Terminal, Edit3, RotateCcw, Send } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "@/hooks/use-toast";

const categories: ToolCategory[] = [
  "scanning",
  "enumeration",
  "web",
  "exploit",
  "password",
  "osint",
  "network",
  "cloud",
  "binary",
  "forensics",
];

export default function Arsenal() {
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<ToolCategory | "all">("all");
  const [selectedItem, setSelectedItem] = useState<ToolItem | null>(null);
  const [selectedVariant, setSelectedVariant] = useState<string>("");
  const [formValues, setFormValues] = useState<Record<string, any>>({});
  const [currentJobId, setCurrentJobId] = useState<string | null>(null);
  const [localOutput, setLocalOutput] = useState<string[]>([]);
  const [customCommand, setCustomCommand] = useState<string>("");
  const [isEditingCommand, setIsEditingCommand] = useState(false);
  const [shellInput, setShellInput] = useState<string>("");
  const [shellHistory, setShellHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const shellInputRef = useRef<HTMLInputElement>(null);

  const { data: tools = [], isLoading } = useTools();
  const executeTool = useExecuteTool();
  const executeShell = useExecuteShell();
  const { data: jobStatus } = useJobStatus(currentJobId);
  const { output: wsOutput, isStreaming, clearOutput } = useJobStream(currentJobId);

  const output = wsOutput.length > 0 ? wsOutput : localOutput;
  const isExecuting = executeTool.isPending || executeShell.isPending || jobStatus?.status === "running";

  // Get the current tool based on selection
  const currentTool = useMemo((): Tool | null => {
    if (!selectedItem) return null;
    
    if (selectedItem.isGroup === true && selectedItem.variants) {
      const variant = selectedItem.variants.find(v => v.id === selectedVariant);
      return variant?.tool || null;
    } else if (selectedItem.isGroup === false) {
      return selectedItem.tool || null;
    }
    
    return null;
  }, [selectedItem, selectedVariant]);

  const filteredTools = useMemo(() => {
    return tools.filter((item) => {
      const matchesSearch =
        item.name.toLowerCase().includes(search.toLowerCase()) ||
        item.description.toLowerCase().includes(search.toLowerCase());
      const matchesCategory =
        selectedCategory === "all" || item.category === selectedCategory;
      return matchesSearch && matchesCategory;
    });
  }, [tools, search, selectedCategory]);

  const handleOpenTool = (item: ToolItem) => {
    setSelectedItem(item);
    clearOutput();
    setLocalOutput([]);
    setCurrentJobId(null);
    setCustomCommand("");
    setIsEditingCommand(false);
    
    // Initialize form based on tool type
    let toolToInit: Tool | undefined;
    
    if (item.isGroup === true && item.variants && item.variants.length > 0) {
      const defaultVariantId = item.defaultVariant || item.variants[0].id;
      setSelectedVariant(defaultVariantId);
      toolToInit = item.variants.find(v => v.id === defaultVariantId)?.tool;
    } else if (item.isGroup === false && item.tool) {
      setSelectedVariant("");
      toolToInit = item.tool;
    }
    
    if (toolToInit) {
      initFormDefaults(toolToInit);
    } else {
      setFormValues({});
    }
  };

  const initFormDefaults = (tool: Tool) => {
    const defaults: Record<string, any> = {};
    Object.entries(tool.parameters.properties).forEach(([key, prop]) => {
      if (prop.default !== undefined) {
        defaults[key] = prop.default;
      }
    });
    setFormValues(defaults);
  };

  const handleVariantChange = (variantId: string) => {
    setSelectedVariant(variantId);
    setCustomCommand("");
    setIsEditingCommand(false);
    if (selectedItem?.isGroup) {
      const variant = selectedItem.variants.find(v => v.id === variantId);
      if (variant) {
        initFormDefaults(variant.tool);
      }
    }
  };

  const handleExecute = async () => {
    if (!currentTool) return;

    // If editing command, use custom command directly
    const commandToExecute = isEditingCommand && customCommand ? customCommand : null;

    // Only validate required fields if not using custom command
    if (!commandToExecute) {
      const missingFields = currentTool.parameters.required.filter(
        (field) => !formValues[field] || formValues[field] === ""
      );

      if (missingFields.length > 0) {
        toast({
          title: "Campos obrigatórios",
          description: `Preencha: ${missingFields.join(", ")}`,
          variant: "destructive",
        });
        return;
      }
    }

    setLocalOutput([`[*] Iniciando ${currentTool.name}...`]);
    if (commandToExecute) {
      setLocalOutput(prev => [...prev, `[*] Comando customizado: ${commandToExecute}`]);
    }

    try {
      const { job_id } = await executeTool.mutateAsync({
        tool: currentTool.name,
        parameters: formValues,
        customCommand: commandToExecute || undefined,
      });
      setCurrentJobId(job_id);
      setLocalOutput(prev => [...prev, `[+] Job iniciado: ${job_id}`]);
      toast({
        title: "Ferramenta iniciada",
        description: `${currentTool.name} está executando`,
      });
    } catch (e) {
      toast({
        title: "Erro",
        description: "Falha ao executar. O backend está rodando?",
        variant: "destructive",
      });
      setLocalOutput(prev => [...prev, `[!] Erro: Falha ao executar`]);
    }
  };

  const handleFieldChange = (field: string, value: any) => {
    setFormValues((prev) => ({ ...prev, [field]: value }));
  };

  // Handle shell command execution
  const handleShellExecute = async () => {
    if (!shellInput.trim()) return;
    
    const cmd = shellInput.trim();
    setShellHistory(prev => [...prev, cmd]);
    setHistoryIndex(-1);
    setLocalOutput(prev => [...prev, `$ ${cmd}`]);
    setShellInput("");

    try {
      const { job_id } = await executeShell.mutateAsync({
        command: cmd,
        timeout: 180,
      });
      setCurrentJobId(job_id);
    } catch (e) {
      setLocalOutput(prev => [...prev, `[!] Erro ao executar comando`]);
    }
  };

  // Handle shell input key events (history navigation)
  const handleShellKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleShellExecute();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (shellHistory.length > 0) {
        const newIndex = historyIndex < shellHistory.length - 1 ? historyIndex + 1 : historyIndex;
        setHistoryIndex(newIndex);
        setShellInput(shellHistory[shellHistory.length - 1 - newIndex] || "");
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex > 0) {
        const newIndex = historyIndex - 1;
        setHistoryIndex(newIndex);
        setShellInput(shellHistory[shellHistory.length - 1 - newIndex] || "");
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setShellInput("");
      }
    }
  };

  // Generate command preview
  const commandPreview = useMemo(() => {
    if (!currentTool?.command) return null;
    
    let cmd = currentTool.command;
    
    // Replace placeholders with actual values or highlight missing
    Object.entries(currentTool.parameters.properties).forEach(([key, prop]) => {
      const value = formValues[key] ?? prop.default ?? "";
      const placeholder = `{${key}}`;
      const placeholderUpper = `{${key.toUpperCase()}}`;
      
      if (value) {
        cmd = cmd.replace(placeholder, String(value));
        cmd = cmd.replace(placeholderUpper, String(value));
      } else {
        // Highlight missing required fields
        const isRequired = currentTool.parameters.required.includes(key);
        const replacement = isRequired ? `<${key}>` : `[${key}]`;
        cmd = cmd.replace(placeholder, replacement);
        cmd = cmd.replace(placeholderUpper, replacement);
      }
    });
    
    return cmd;
  }, [currentTool, formValues]);

  return (
    <MainLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Search */}
        <div className="flex flex-col md:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Buscar ferramentas..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10 bg-secondary border-border"
            />
          </div>
        </div>

        {/* Category Tabs */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setSelectedCategory("all")}
            className={cn(
              "px-3 py-1.5 text-sm rounded-lg transition-colors",
              selectedCategory === "all"
                ? "bg-primary text-primary-foreground"
                : "bg-secondary text-muted-foreground hover:text-foreground"
            )}
          >
            Todos ({tools.length})
          </button>
          {categories.map((cat) => {
            const count = tools.filter((t) => t.category === cat).length;
            if (count === 0) return null;
            return (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={cn(
                  "px-3 py-1.5 text-sm rounded-lg capitalize transition-colors",
                  selectedCategory === cat
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-muted-foreground hover:text-foreground"
                )}
              >
                {cat} ({count})
              </button>
            );
          })}
        </div>

        {/* Tools Grid */}
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredTools.map((item) => (
              <div
                key={item.id}
                className="group p-4 rounded-lg border border-border bg-card hover:border-primary/50 transition-all duration-200"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    {item.isGroup && (
                      <Layers className="h-4 w-4 text-primary" />
                    )}
                    <h3 className="font-mono font-medium text-foreground group-hover:text-primary transition-colors">
                      {item.name}
                    </h3>
                  </div>
                  <CategoryBadge category={item.category as ToolCategory} />
                </div>
                <p className="text-sm text-muted-foreground mb-2 line-clamp-2">
                  {item.description}
                </p>
                {item.isGroup && (
                  <p className="text-xs text-primary mb-3">
                    {item.variants.length} variantes disponíveis
                  </p>
                )}
                <Button
                  size="sm"
                  onClick={() => handleOpenTool(item)}
                  className="w-full bg-primary/10 text-primary hover:bg-primary hover:text-primary-foreground border border-primary/30"
                >
                  <Play className="h-4 w-4 mr-2" />
                  Executar
                </Button>
              </div>
            ))}
          </div>
        )}

        {!isLoading && filteredTools.length === 0 && (
          <div className="text-center py-12 text-muted-foreground">
            Nenhuma ferramenta encontrada.
          </div>
        )}
      </div>

      {/* Tool Execution Modal */}
      <Dialog open={!!selectedItem} onOpenChange={() => setSelectedItem(null)}>
        <DialogContent className="max-w-2xl bg-card border-border max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-mono">
              {selectedItem?.isGroup && <Layers className="h-5 w-5 text-primary" />}
              {selectedItem?.name}
              {selectedItem && <CategoryBadge category={selectedItem.category as ToolCategory} />}
            </DialogTitle>
            <DialogDescription>{selectedItem?.description}</DialogDescription>
          </DialogHeader>

          {selectedItem && (
            <div className="space-y-6">
              {/* Variant Selector for Groups */}
              {selectedItem.isGroup && (
                <div className="space-y-2">
                  <Label>Modo</Label>
                  <Select value={selectedVariant} onValueChange={handleVariantChange}>
                    <SelectTrigger className="bg-secondary w-full">
                      <SelectValue placeholder="Selecione o modo" />
                    </SelectTrigger>
                    <SelectContent className="max-h-[300px]">
                      {selectedItem.variants.map((variant) => (
                        <SelectItem key={variant.id} value={variant.id}>
                          <span>{variant.label}</span>
                          <span className="ml-2 text-xs text-muted-foreground">
                            - {variant.description}
                          </span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {/* Show selected variant description */}
                  {selectedVariant && (
                    <p className="text-xs text-muted-foreground">
                      {selectedItem.variants.find(v => v.id === selectedVariant)?.description}
                    </p>
                  )}
                </div>
              )}

              {/* Parameters Form */}
              {currentTool && (
                <div className="space-y-4">
                  <h4 className="text-sm font-medium text-foreground">Parâmetros</h4>
                  {Object.entries(currentTool.parameters.properties).map(
                    ([key, prop]) => {
                      const isRequired = currentTool.parameters.required.includes(key);
                      return (
                        <div key={key} className="space-y-2">
                          <Label className="flex items-center gap-1">
                            {key}
                            {isRequired && <span className="text-red-500">*</span>}
                          </Label>
                          {prop.type === "boolean" ? (
                            <div className="flex items-center gap-2">
                              <Checkbox
                                checked={formValues[key] ?? prop.default ?? false}
                                onCheckedChange={(checked) =>
                                  handleFieldChange(key, checked)
                                }
                              />
                              <span className="text-sm text-muted-foreground">
                                {prop.description}
                              </span>
                            </div>
                          ) : (
                            <>
                              <Input
                                type={prop.type === "integer" || prop.type === "number" ? "number" : "text"}
                                placeholder={prop.description}
                                value={formValues[key] ?? ""}
                                onChange={(e) =>
                                  handleFieldChange(
                                    key,
                                    prop.type === "integer" || prop.type === "number"
                                      ? parseInt(e.target.value) || ""
                                      : e.target.value
                                  )
                                }
                                className="bg-secondary border-border"
                              />
                              <p className="text-xs text-muted-foreground">
                                {prop.description}
                                {prop.default !== undefined && (
                                  <span className="ml-1">(padrão: {String(prop.default)})</span>
                                )}
                              </p>
                            </>
                          )}
                        </div>
                      );
                    }
                  )}
                </div>
              )}

              {/* Command Preview/Editor */}
              {(commandPreview || isEditingCommand) && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label className="flex items-center gap-2">
                      <Terminal className="h-4 w-4" />
                      Comando
                    </Label>
                    <div className="flex items-center gap-2">
                      {isEditingCommand && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setIsEditingCommand(false);
                            setCustomCommand("");
                          }}
                          className="h-7 px-2 text-xs"
                        >
                          <RotateCcw className="h-3 w-3 mr-1" />
                          Resetar
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (!isEditingCommand) {
                            setCustomCommand(commandPreview || "");
                          }
                          setIsEditingCommand(!isEditingCommand);
                        }}
                        className="h-7 px-2 text-xs"
                      >
                        <Edit3 className="h-3 w-3 mr-1" />
                        {isEditingCommand ? "Visualizar" : "Editar"}
                      </Button>
                    </div>
                  </div>
                  {isEditingCommand ? (
                    <Textarea
                      value={customCommand}
                      onChange={(e) => setCustomCommand(e.target.value)}
                      className="font-mono text-sm bg-black/90 border-border text-green-400 min-h-[80px]"
                      placeholder="Digite o comando customizado..."
                    />
                  ) : (
                    <div className="p-3 rounded-lg bg-black/90 border border-border font-mono text-sm text-green-400 overflow-x-auto">
                      <code>{commandPreview}</code>
                    </div>
                  )}
                  {isEditingCommand && (
                    <p className="text-xs text-muted-foreground">
                      Modo de edição ativo. O comando customizado será executado diretamente.
                    </p>
                  )}
                </div>
              )}

              {/* Execute Button */}
              <Button
                onClick={handleExecute}
                disabled={isExecuting || !currentTool}
                className="w-full bg-primary text-primary-foreground hover:bg-primary/90"
              >
                {isExecuting ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Executando...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Executar
                  </>
                )}
              </Button>

              {/* Terminal Output */}
              {(output.length > 0 || isStreaming) && (
                <TerminalOutput
                  lines={output}
                  title={`${currentTool?.name || selectedItem.name} output`}
                  isStreaming={isStreaming}
                  maxHeight="300px"
                />
              )}

              {/* Interactive Shell Input */}
              {(output.length > 0 || currentJobId) && (
                <div className="space-y-2">
                  <Label className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Terminal className="h-3 w-3" />
                    Shell Interativa - Execute comandos adicionais
                  </Label>
                  <div className="flex gap-2">
                    <div className="flex-1 relative">
                      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-green-400 font-mono text-sm">$</span>
                      <Input
                        ref={shellInputRef}
                        value={shellInput}
                        onChange={(e) => setShellInput(e.target.value)}
                        onKeyDown={handleShellKeyDown}
                        placeholder="Digite um comando..."
                        className="pl-7 font-mono text-sm bg-black/90 border-border text-green-400 placeholder:text-green-400/50"
                        disabled={isStreaming}
                      />
                    </div>
                    <Button
                      onClick={handleShellExecute}
                      disabled={!shellInput.trim() || isStreaming}
                      size="sm"
                      className="bg-green-600 hover:bg-green-700"
                    >
                      <Send className="h-4 w-4" />
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Use ↑↓ para navegar no histórico. Enter para executar.
                  </p>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
