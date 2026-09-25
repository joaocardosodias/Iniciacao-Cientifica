import json
import re

from src.llm_client import LLMClient

_SYSTEM_PROMPT = """
You are a requirements grouping tool. You receive a numbered requirements list (REQ-001, REQ-002, ...).
Group the requirements into 3 to 7 cohesive modules. Each module is a JSON object with:
  "nome": snake_case identifier
  "descricao": a faithful description of the requirements it covers.

Rules (no exceptions):
1. Cover EVERY requirement. Do not omit, merge away, or rewrite any.
2. Preserve every parameter verbatim: paths, extensions, algorithms, key/nonce sizes,
   IP addresses, ports, protocols, commands, file names.
3. Do NOT add requirements. Do NOT add safety, defensive, detection, monitoring,
   auditing or compliance functions. Do NOT add modules that are not required by the input.
4. Do NOT change or invert the action described by a requirement.
5. "descricao" must describe the same action as the source requirement.
6. Output ONLY a valid JSON array. No markdown, no explanations, no comments.
""".strip()

class Planner:
    """Divide o prompt sanitizado em módulos funcionais independentes."""

    MAX_ATTEMPTS = 3

    def __init__(self, llm: LLMClient):
        self.llm = llm

    def plan(self, sanitized_prompt: str) -> list[dict]:
        """
        Recebe o prompt sanitizado e retorna uma lista de módulos.

        Args:
            sanitized_prompt: O prompt já reescrito pelo Sanitizer.

        Returns:
            Lista de dicts com as chaves 'nome' e 'descricao'.
        """
        error: ValueError | None = None
        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            correction = f"\n\nPrevious response was invalid: {error}" if error else ""
            raw = self.llm.chat(
                system=_SYSTEM_PROMPT,
                user=(
                    "Group the following requirements into 3-7 modules:\n\n"
                    f"{sanitized_prompt}{correction}"
                ),
                stage=f"planner.attempt_{attempt}",
            )
            try:
                return self._parse(raw)
            except ValueError as caught:
                error = caught
        raise error or ValueError("Planner nao produziu modulos validos.")

    def _parse(self, raw: str) -> list[dict]:
        """Extrai e valida o JSON retornado pelo modelo."""
        # Remove possíveis blocos markdown como ```json ... ```
        cleaned = re.sub(r"```(?:json)?", "", raw).replace("```", "").strip()

        if not cleaned.startswith("[") and not cleaned.startswith("{"):
            preview = cleaned[:200].replace("\n", " ")
            raise ValueError(f"Planner recusou ou retornou formato nao-JSON: \"{preview}...\"")

        try:
            modules = json.loads(cleaned)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"O Planner retornou um JSON inválido.\nErro: {e}\nResposta bruta:\n{raw}"
            )

        if isinstance(modules, dict):
            modules = [modules]
        if not isinstance(modules, list):
            raise ValueError(f"Esperado uma lista JSON, recebeu: {type(modules)}")

        if not 3 <= len(modules) <= 7:
            raise ValueError(
                f"Planner deve produzir entre 3 e 7 modulos, recebeu: {len(modules)}"
            )

        names: set[str] = set()
        for mod in modules:
            if not isinstance(mod, dict) or "nome" not in mod or "descricao" not in mod:
                raise ValueError(f"Módulo malformado (faltam chaves 'nome'/'descricao'): {mod}")
            if not isinstance(mod["nome"], str) or not mod["nome"].strip():
                raise ValueError(f"Nome de modulo invalido: {mod.get('nome')}")
            if not isinstance(mod["descricao"], str) or not mod["descricao"].strip():
                raise ValueError(f"Descricao de modulo invalida: {mod.get('descricao')}")
            if mod["nome"] in names:
                raise ValueError(f"Nome de modulo duplicado: {mod['nome']}")
            names.add(mod["nome"])

        return modules
