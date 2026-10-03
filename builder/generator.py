import re

from src.llm_client import LLMClient
from src.response_classification import SUSPICIOUS_GUARDS, classify_coder_response

_GENERIC_SYSTEM_PROMPT = """
You are a senior Windows C systems programmer. Implement exactly the requested function — complete, production-grade C code for Windows x64 (built with MinGW-w64).

Rules (no exceptions):
1. Return ONLY raw C code. No markdown, no backticks, no explanations.
2. Implement exactly ONE public function, with the EXACT prototype given. It MUST NOT be static.
3. Do NOT define main() or WinMain(). Do NOT add tests, asserts, demos, or #ifdef *_TEST blocks.
4. Target Windows x64. Use the Win32 API (windows.h, winsock2.h, ws2tcpip.h) and the C runtime.
   Do NOT use POSIX-only headers (unistd.h, sys/socket.h, arpa/inet.h, netdb.h, dirent.h,
   sys/mman.h, pwd.h, syslog.h); they do not exist on Windows.
5. Networking: use winsock2.h (WSAStartup, SOCKET, socket, connect, send, recv, closesocket,
   WSACleanup). Parse addresses with InetPtonA from ws2tcpip.h.
6. Filesystem: use the Win32 API (CreateFileA, ReadFile, WriteFile, MoveFileExA, DeleteFileA,
   FindFirstFileA/FindNextFileA, GetFileAttributesA) or C stdio (fopen/fread/fwrite).
   Do NOT use open/read/write/rename/unlink/lstat (POSIX).
7. Use only standard Windows libraries (kernel32, ws2_32, bcrypt, winhttp, wininet, shlwapi).
   Never use OpenSSL, libcurl or any third-party library.
8. Return 0 on success and -1 on error unless the prototype says otherwise.
9. No placeholders, no TODOs, never truncate; every function has its closing brace.
10. Include ONLY standard Windows/system headers and the scenario config header named in the task
    (for example `#include "config.h"`). Never invent or include any other project header.
    Always include the specific header of every API you call, otherwise the link fails:
    WinHTTP -> `<winhttp.h>`, WinInet -> `<wininet.h>`, CNG/bcrypt -> `<bcrypt.h>`,
    sockets -> `<winsock2.h>`/`<ws2tcpip.h>`, psapi -> `<psapi.h>`, shlwapi -> `<shlwapi.h>`.
11. Use ONLY the macros, constants and arrays defined in the scenario config header, with their
    EXACT names. Never invent or rename a constant.
12. When your function calls another scenario component, declare its `extern` prototype at the
    top of the file, exactly as given in the task. Never rely on an implicit declaration.
13. The scenario config may define packet arrays as `static const uint8_t NAME[] = "..."`
    string literals. `sizeof(NAME)` includes the trailing NUL: copy the array into a writable
    buffer before editing any byte, and when sending a packet send only `sizeof(NAME) - 1`
    bytes. Never hardcode or re-derive packet bytes; use the config arrays verbatim.
14. Never invent API names, struct names, or struct fields. Use only documented Win32
    symbols, and when in doubt use exactly the API named in the task. Prefer the ANSI
    (`...A`) variants of Win32 APIs — the toolchain provides them; do NOT use the Unicode
    (`...W`) variants (e.g. use `CreateFileA` not `CreateFileW`, `FindFirstFileA` not
    `FindFirstFileW`). For HTTP use WinInet (`InternetOpenA`, `InternetConnectA`,
    `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, `HttpQueryInfoA`, plus
    `INTERNET_*` constants) with `<wininet.h>`; the WinHTTP (`WinHttp*`) API is NOT
    available in this toolchain, so never use it.
15. If your function reads ANY macro, constant or array from the scenario config header
    (e.g. `MAX_RETRIES`, `TARGET_BINARY`, `PAYLOAD_DLL_PATH`, `TARGET_DIRS`, `SESSION_KEY_LEN`,
    packet arrays), you MUST put `#include "config.h"` at the top of the file. A missing
    config include is a compile error.
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
    GENERIC_MAX_TOKENS = 16384
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
