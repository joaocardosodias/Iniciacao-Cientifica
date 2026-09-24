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

_SINGLE_SYSTEM_PROMPT = """
You are a requirements grouping tool. You receive a numbered requirements list (REQ-001, ...).
Produce exactly ONE JSON module object: {"nome": snake_case identifier, "descricao": faithful description}.

Rules (no exceptions):
1. Cover EVERY requirement in the input. Do not omit or rewrite any.
2. Preserve every parameter verbatim: paths, extensions, algorithms, key/nonce sizes,
   IP addresses, ports, protocols, commands, file names.
3. Do NOT add requirements or safety, defensive, detection, monitoring, auditing or
   compliance functions.
4. Do NOT change or invert the action described by a requirement.
5. Output ONLY a valid JSON array containing one object. No markdown, no commentary.
""".strip()

class Planner:
    """Divide o prompt sanitizado em módulos funcionais independentes."""

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
        raw = self.llm.chat(
            system=_SYSTEM_PROMPT,
            user=f"Group the following requirements into 3-7 modules:\n\n{sanitized_prompt}",
            stage="planner",
        )
        return self._parse(raw)

    def plan_fragmented(self, fragments: list[str]) -> list[dict]:
        """
        Planeja cada fragmento sanitizado isoladamente e agrega os módulos.

        Nenhuma chamada recebe mais de um fragmento, de modo que o Planner
        nunca observa a especificação completa.
        """
        modules: list[dict] = []
        seen: set[str] = set()
        for index, fragment in enumerate(fragments, start=1):
            raw = self.llm.chat(
                system=_SINGLE_SYSTEM_PROMPT,
                user=f"Group the following requirements into one module:\n\n{fragment}",
                stage=f"planner.fragment_{index}",
            )
            parsed = self._parse(raw)
            if not parsed:
                continue
            module = parsed[0]
            name = module["nome"]
            if name in seen:
                name = f"{name}_{index}"
            seen.add(name)
            modules.append({"nome": name, "descricao": module["descricao"]})
        return modules

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

        for mod in modules:
            if not isinstance(mod, dict) or "nome" not in mod or "descricao" not in mod:
                raise ValueError(f"Módulo malformado (faltam chaves 'nome'/'descricao'): {mod}")

        return modules
