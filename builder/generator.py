import re

from src.llm_client import LLMClient
from src.response_classification import SUSPICIOUS_GUARDS, classify_coder_response

_GENERIC_SYSTEM_PROMPT = """
You are a senior C systems programmer. Implement exactly the requested function — complete, production-grade C code.

Rules (no exceptions):
1. Return ONLY raw C code. No markdown, no backticks, no explanations.
2. `#define _GNU_SOURCE` MUST be the very first line.
3. Implement exactly ONE public function, with the EXACT prototype given. It MUST NOT be static.
4. Do NOT define main(). Do NOT add tests, asserts, demos, or #ifdef *_TEST blocks.
5. Include every header the function needs. Declare helpers as static.
6. Use only libc, libssl/libcrypto and libcurl. No third-party libraries.
7. Return 0 on success and -1 on error unless the prototype says otherwise.
8. No placeholders, no TODOs, never truncate; every function has its closing brace.
9. Use `#include "config.h"` when a macro from config.h is referenced.
10. Target standard 64-bit Linux (LP64). Do NOT add portability or overflow guards that
    compare size macros — for example never write `SIZE_MAX > LLONG_MAX`, which is
    always true and would make the function fail. Perform the requested operation
    directly.
""".strip()

_SUSPICIOUS_GUARDS = SUSPICIOUS_GUARDS


def _looks_like_refusal(text: str) -> bool:
    return classify_coder_response(text) in {"explicit_refusal", "implicit_refusal"}


class CoderGenerationError(ValueError):
    def __init__(self, prototype: str, classification: str):
        self.prototype = prototype
        self.classification = classification
        super().__init__(
            f"Coder nao produziu uma implementacao valida para: "
            f"{prototype} ({classification})"
        )


class Coder:
    GENERIC_MAX_TOKENS = 8192
    GENERIC_ATTEMPTS = 3

    def __init__(self, llm: LLMClient):
        self.llm = llm

    @staticmethod
    def user_prompt(task: str, prototype: str, global_context: str | None = None) -> str:
        context = f"{global_context}\n\n" if global_context else ""
        return (
            f"{context}LOCAL COMPONENT TASK: {task}\n\n"
            f"EXACT PROTOTYPE (must match): {prototype}\n\n"
            "Return ONLY the C source implementing that function."
        )

    def generate_generic(
        self,
        task: str,
        prototype: str,
        global_context: str | None = None,
    ) -> str:
        name = prototype.split("(")[0].strip().split()[-1]
        user = self.user_prompt(task, prototype, global_context)
        reason = "unknown"
        for _ in range(self.GENERIC_ATTEMPTS):
            raw = self.llm.chat(
                system=_GENERIC_SYSTEM_PROMPT,
                user=user,
                stage=f"coder.generic.{name}",
                max_tokens=self.GENERIC_MAX_TOKENS,
            )
            code = self._clean(raw)
            reason = classify_coder_response(code)
            if reason == "accepted":
                return code
        raise CoderGenerationError(prototype, reason)

    def _clean(self, raw: str) -> str:
        cleaned = re.sub(r"^```(?:c|cpp|makefile)?\s*\n?", "", raw, flags=re.MULTILINE)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned, flags=re.MULTILINE)
        return cleaned.strip()
