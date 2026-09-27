import sys

WIDTH = 72

TAGS = {
    "passed": "[ ok ]",
    "failed": "[fail]",
    "environment_error": "[env ]",
    "not_run": "[ -- ]",
    "skipped": "[skip]",
}

LABELS = {
    "passed": "APROVADO",
    "failed": "FALHOU",
    "environment_error": "ERRO DE AMBIENTE",
    "not_run": "NAO EXECUTADO",
}


def rule(char: str = "-", width: int = WIDTH) -> None:
    print(char * width)


def header(title: str) -> None:
    rule("=")
    print(f"  {title}")
    rule("=")


def divider() -> None:
    rule("-")


def section(title: str) -> None:
    divider()
    print(f"  {title}")


def fields(pairs, indent: int = 2) -> None:
    label_width = max((len(label) for label, _ in pairs), default=0)
    pad = " " * indent
    for label, value in pairs:
        print(f"{pad}{label.ljust(label_width)} : {value}")


def bullet(text: str) -> None:
    print(f"  - {text}")


def tag(status: str) -> str:
    return TAGS.get(status, f"[{status[:4]}]")


def stage(index: int, total: int, name: str, status: str, detail: str = "") -> None:
    line = f"  [{index}/{total}] {name.ljust(24)} {tag(status)}"
    if detail:
        line = f"{line}  {detail}"
    print(line)


def stage_table(stages: dict, order) -> None:
    known = [key for key, _ in order]
    extra = [key for key in stages if key not in known]
    total = len(known) + len(extra)
    index = 0
    for key, name in order:
        index += 1
        stage(index, total, name, stages[key])
    for key in extra:
        index += 1
        stage(index, total, key, stages[key])


def outcome(status: str, lines) -> None:
    divider()
    print(f"  RESULTADO : {LABELS.get(status, status.upper())}")
    for line in lines:
        print(f"  {line}")
    rule("=")


def note(message: str) -> None:
    print(f"  {message}")


def warn(message: str) -> None:
    print(f"  [aviso] {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"  [erro] {message}", file=sys.stderr)
