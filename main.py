# main.py
# CLI que orquestra a geração, montagem e compilação de payloads.

import sys

import pipeline
from prompts import PROMPTS


def _list() -> None:
    print("Cenários disponíveis:")
    for key, data in PROMPTS.items():
        base = data.get("base_scenarios") or []
        suffix = f"  (base: {', '.join(base)})" if base else ""
        print(f"  - {key}: {data['nome']}{suffix}")


def _run_scenario(scenario: str, extra: list[str]) -> int:
    sys.argv = ["pipeline.py", "--scenario", scenario, *extra]
    try:
        return pipeline.main() or 0
    except SystemExit as exit_error:
        return exit_error.code or 0


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("list", "--list", "-l"):
        _list()
        return 0

    if args[0] == "run":
        if len(args) < 2:
            print("uso: python main.py run <cenario|all> [opções]")
            _list()
            return 1
        target = args[1].lower()
        extra = args[2:]
        if target == "all":
            code = 0
            for scenario in PROMPTS:
                print(f"\n{'=' * 60}\n  CENÁRIO: {scenario}\n{'=' * 60}")
                code = _run_scenario(scenario, extra) or code
            return code
        if target not in PROMPTS:
            print(f"[ERRO] Cenário '{target}' não encontrado.")
            _list()
            return 1
        return _run_scenario(target, extra)

    if args[0] in PROMPTS:
        return _run_scenario(args[0], args[1:])

    sys.argv = ["pipeline.py", *args]
    return pipeline.main() or 0


if __name__ == "__main__":
    raise SystemExit(main())
