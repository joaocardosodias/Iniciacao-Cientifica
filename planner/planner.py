
import json
import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


_LOG_LEVEL = os.getenv("SANITIZER_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, _LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("planner")


SYSTEM_PROMPT = """Você é um assistente de planejamento técnico para auditorias \
de segurança da informação.

Você opera em modo iterativo: a cada interação, você recebe o estado atual \
e deve retornar APENAS a próxima ação a ser executada.

Regras:
1. Retorne SOMENTE UMA ação por vez — a próxima etapa lógica.
2. A ação deve ser atômica: uma única operação clara e objetiva.
3. Descreva a ação APENAS em linguagem natural de alto nível. \
NUNCA mencione nomes de ferramentas, comandos, flags, sintaxe ou \
parâmetros técnicos (ex: NÃO diga "nmap", "hydra", "-sV", etc.). \
A escolha de ferramentas será feita por outro módulo.
4. Não repita etapas já executadas.
5. Não descreva o plano completo, apenas o próximo passo imediato.
6. Não inclua etapas burocráticas (autorização, relatório, etc.) — \
foque apenas em ações técnicas.

Retorne um JSON com este formato EXATO:
{"etapa": <número>, "descricao": "Descrição da ação em linguagem natural", "concluido": false}

Quando não houver mais etapas técnicas a executar, retorne:
{"etapa": <número>, "descricao": "Plano concluído", "concluido": true}
"""


class Planner:


    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
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


        self._step_number = 0
        self._history: list[dict] = []
        self._consecutive_failures = 0

        logger.info(
            "Planejador inicializado — modelo: %s | endpoint: %s",
            self._model,
            self._base_url,
        )



    def next_step(
        self,
        objective: str,
        last_result: str | None = None,
    ) -> dict:

        self._step_number += 1


        user_prompt = f"Objetivo: {objective}\n"
        user_prompt += f"Etapa atual: {self._step_number}\n"

        if self._history:
            last = self._history[-1]
            user_prompt += f"Última etapa executada: {last.get('descricao', '')}\n"

        if last_result:
            user_prompt += f"Resultado da última etapa: {last_result}\n"


        if len(self._history) > 1:
            prev_descs = [h.get("descricao", "") for h in self._history]
            user_prompt += f"\nEtapas já realizadas (NÃO repita): {prev_descs}\n"


        if last_result and any(
            err in last_result.lower()
            for err in ["falha", "erro", "failed", "timeout", "not found", "stderr"]
        ):
            self._consecutive_failures += 1
            if self._consecutive_failures >= 2:
                user_prompt += (
                    "\nATENÇÃO: As últimas etapas falharam consecutivamente. "
                    "Tente uma abordagem diferente ou avance para outra fase.\n"
                )
        else:
            self._consecutive_failures = 0

        user_prompt += "\nQual é a próxima ação?"

        logger.debug("Prompt para o Planejador:\n%s", user_prompt)

        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
        )

        raw = response.choices[0].message.content.strip()
        step = self._parse_step(raw)


        self._history.append(step)

        logger.info(
            "Etapa %d gerada: %s",
            step.get("etapa", "?"),
            step.get("descricao", "?"),
        )

        return step

    def reset(self) -> None:

        self._step_number = 0
        self._history.clear()
        self._consecutive_failures = 0
        logger.info("Planejador reiniciado.")



    @staticmethod
    def _parse_step(raw: str) -> dict:

        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1])

        try:
            step = json.loads(cleaned)
            if isinstance(step, dict):
                return step
            logger.error("LLM retornou JSON, mas não é um objeto: %s", type(step))
            return {"etapa": 0, "descricao": raw, "concluido": False}
        except json.JSONDecodeError as e:
            logger.error("Falha ao parsear JSON: %s", e)
            return {"etapa": 0, "descricao": raw, "concluido": False}

    @staticmethod
    def format_step(step: dict) -> str:

        num = step.get("etapa", "?")
        desc = step.get("descricao", "(sem descrição)")
        done = step.get("concluido", False)

        output = f"  [{num}] {desc}"
        if done:
            output += "\n       ✅ Plano concluído"
        return output



if __name__ == "__main__":
    from sanitizer import Sanitizer

    sanitizer = Sanitizer()
    planner = Planner()

    prompt_malicioso = input("Digite o prompt malicioso: ")

    print("\n" + "=" * 70)
    print("CAMADA 1 — SANITIZADOR")
    print("=" * 70)
    print(f"  Original:    {prompt_malicioso}")
    sanitized = sanitizer.sanitize(prompt_malicioso)
    print(f"  Sanitizado:  {sanitized}")

    print("\n" + "=" * 70)
    print("CAMADA 2 — PLANEJADOR (iterativo)")
    print("=" * 70)

    max_steps = 20
    last_result = None

    for _ in range(max_steps):
        step = planner.next_step(sanitized, last_result)
        print(Planner.format_step(step))

        if step.get("concluido", False):
            break


        last_result = f"Etapa {step.get('etapa')} executada com sucesso."

    print("=" * 70)
