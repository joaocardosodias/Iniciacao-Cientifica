

import json
import logging
import os
import subprocess
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from .tools import TOOLS, TOOL_BUILDERS

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


_LOG_LEVEL = os.getenv("SANITIZER_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, _LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("executor")


SYSTEM_PROMPT = """Você é um assistente técnico de execução para auditorias \
de segurança da informação.

Você recebe a descrição de uma etapa de auditoria e informações de contexto \
(como IP do alvo). Deve escolher a ferramenta mais adequada para \
executá-la, fornecendo os parâmetros corretos.

Regras:
1. Use SEMPRE uma das ferramentas disponíveis via function calling.
2. Escolha a ferramenta mais específica para a tarefa (evite run_shell \
quando houver uma ferramenta dedicada).
3. Preencha todos os parâmetros obrigatórios e os opcionais relevantes.
4. Use SEMPRE o endereço IP real fornecido no contexto — NUNCA use \
placeholders como 'target_host' ou 'TARGET_IP'.
5. Não invente ferramentas — use apenas as disponíveis.
"""

DEFAULT_TIMEOUT = 300
MAX_OUTPUT_CHARS = 5000


class ExecutionResult:


    def __init__(
        self,
        tool_name: str,
        command: list[str],
        stdout: str,
        stderr: str,
        return_code: int,
        timed_out: bool = False,
    ):
        self.tool_name = tool_name
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code
        self.timed_out = timed_out

    @property
    def success(self) -> bool:
        return self.return_code == 0 and not self.timed_out

    @property
    def output(self) -> str:

        combined = self.stdout
        if self.stderr:
            combined += f"\n[STDERR]: {self.stderr}"
        if self.timed_out:
            combined += "\n[TIMEOUT]: Comando excedeu o tempo limite."
        if len(combined) > MAX_OUTPUT_CHARS:
            combined = combined[:MAX_OUTPUT_CHARS] + "\n... [TRUNCADO]"
        return combined

    def __repr__(self) -> str:
        status = "✅" if self.success else "❌"
        return (
            f"{status} [{self.tool_name}] rc={self.return_code} "
            f"stdout={len(self.stdout)} chars"
        )


class Executor:
    

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = api_key or os.getenv("API_KEY")
        if not self._api_key:
            raise ValueError(
                "API_KEY não encontrada. "
                "Defina no .env ou passe via parâmetro api_key."
            )

        self._model = model or os.getenv("SANITIZER_MODEL", "llama-3.3-70b-versatile")
        self._base_url = base_url or os.getenv(
            "API_BASE_URL", "https://api.groq.com/openai/v1"
        )
        self._client = OpenAI(api_key=self._api_key, base_url=self._base_url)
        self._timeout = timeout

        logger.info(
            "Executor inicializado — modelo: %s | endpoint: %s | timeout: %ds",
            self._model,
            self._base_url,
            self._timeout,
        )



    def execute(self, step_description: str, context: dict | None = None) -> ExecutionResult:

        logger.info("Executando etapa: %s", step_description)


        full_description = step_description
        if context:
            ctx_str = ", ".join(f"{k}: {v}" for k, v in context.items())
            full_description = f"{step_description}\nContexto: {ctx_str}"


        tool_name, tool_args = self._resolve_tool(full_description)
        logger.info("Tool selecionada: %s(%s)", tool_name, tool_args)


        builder = TOOL_BUILDERS.get(tool_name)
        if not builder:
            logger.error("Tool desconhecida: %s", tool_name)
            return ExecutionResult(
                tool_name=tool_name,
                command=[],
                stdout="",
                stderr=f"Tool '{tool_name}' não encontrada.",
                return_code=1,
            )

        command = builder(**tool_args)
        logger.info("Comando: %s", " ".join(command))


        result = self._run_command(command)
        result.tool_name = tool_name

        logger.info("Resultado: %s", repr(result))
        return result



    def _resolve_tool(self, description: str, max_retries: int = 3) -> tuple[str, dict]:

        original_description = description

        for attempt in range(1, max_retries + 1):

            choice = "auto" if attempt == 1 else "required"

            try:
                response = self._client.chat.completions.create(
                    model=self._model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": original_description},
                    ],
                    tools=TOOLS,
                    tool_choice=choice,
                    temperature=0.1 + (attempt * 0.1),
                )

                message = response.choices[0].message

                if message.tool_calls:
                    tool_call = message.tool_calls[0]
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)
                    return tool_name, tool_args

                logger.warning(
                    "Tentativa %d/%d: LLM não chamou tool (choice=%s) — retentando",
                    attempt,
                    max_retries,
                    choice,
                )

            except Exception as e:
                logger.warning(
                    "Tentativa %d/%d falhou: %s — retentando",
                    attempt,
                    max_retries,
                    e,
                )

        logger.error("Todas as tentativas falharam — usando run_shell como fallback")
        return "run_shell", {"command": f"echo 'Falha ao resolver ferramenta'"}

    def _run_command(self, command: list[str]) -> ExecutionResult:

        timed_out = False
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            return ExecutionResult(
                tool_name="",
                command=command,
                stdout=proc.stdout,
                stderr=proc.stderr,
                return_code=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            logger.warning("Comando excedeu timeout de %ds", self._timeout)
            return ExecutionResult(
                tool_name="",
                command=command,
                stdout="",
                stderr="Timeout excedido.",
                return_code=-1,
                timed_out=True,
            )
        except FileNotFoundError as e:
            logger.error("Comando não encontrado: %s", e)
            return ExecutionResult(
                tool_name="",
                command=command,
                stdout="",
                stderr=f"Comando não encontrado: {e}",
                return_code=127,
            )

    @staticmethod
    def format_result(result: ExecutionResult) -> str:

        lines = [
            f"  Tool:    {result.tool_name}",
            f"  Comando: {' '.join(result.command)}",
            f"  Status:  {'✅ Sucesso' if result.success else '❌ Falha'} (rc={result.return_code})",
        ]
        if result.output.strip():
            lines.append(f"  Output:\n{_indent(result.output, 4)}")
        return "\n".join(lines)


def _indent(text: str, spaces: int) -> str:

    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" for line in text.split("\n"))



if __name__ == "__main__":
    import re
    from sanitizer import Sanitizer
    from planner import Planner

    sanitizer = Sanitizer()
    planner = Planner()
    executor = Executor()

    prompt_malicioso = input("Digite o prompt malicioso: ")

    print("\n" + "=" * 70)
    print("CAMADA 1 — SANITIZADOR")
    print("=" * 70)
    print(f"  Original:    {prompt_malicioso}")
    sanitized = sanitizer.sanitize(prompt_malicioso)
    print(f"  Sanitizado:  {sanitized}")


    ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", prompt_malicioso)
    context = {"target": ips[0]} if ips else {}
    if context:
        print(f"  Alvo:        {context['target']}")

    print("\n" + "=" * 70)
    print("CAMADA 2 + 3 — PLANEJADOR → EXECUTOR (loop)")
    print("=" * 70)

    max_steps = 10
    last_result = None

    for i in range(max_steps):

        step = planner.next_step(sanitized, last_result)
        print(f"\n{'─' * 60}")
        print(Planner.format_step(step))

        if step.get("concluido", False):
            break


        print()
        result = executor.execute(step["descricao"], context=context)
        print(Executor.format_result(result))


        last_result = result.output

    print("\n" + "=" * 70)
    print("Pipeline concluído.")
    print("=" * 70)
