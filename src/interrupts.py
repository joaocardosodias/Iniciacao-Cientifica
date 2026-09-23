import atexit
import logging
import signal
import threading
from types import FrameType
from typing import Any

from src.trace import RunTrace

log = logging.getLogger("pipeline.interrupts")


def signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except ValueError:
        return str(signum)


class RunInterrupted(BaseException):
    def __init__(self, signum: int):
        self.signum = signum
        self.signame = signal_name(signum)
        super().__init__(f"execucao interrompida por {self.signame}")


class RunGuard:
    def __init__(self, trace: RunTrace):
        self.trace = trace
        self._previous: dict[int, Any] = {}
        self._installed = False
        self._triggered = threading.Event()

    def install(self) -> bool:
        if threading.current_thread() is not threading.main_thread():
            log.warning("RunGuard ignorado fora da thread principal")
            return False
        for signum in (signal.SIGINT, signal.SIGTERM):
            self._previous[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle)
        atexit.register(self._on_exit)
        self._installed = True
        return True

    def restore(self) -> None:
        if not self._installed:
            return
        for signum, handler in self._previous.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError):
                pass
        self._installed = False

    def _handle(self, signum: int, frame: FrameType | None) -> None:
        name = signal_name(signum)
        if self._triggered.is_set():
            log.warning(f"{name} repetido durante encerramento — ignorado")
            return
        self._triggered.set()
        log.warning(f"Recebido {name} — interrompendo execucao")
        self.trace.emit("run.interrupted", signal=signum, signal_name=name)
        raise RunInterrupted(signum)

    def _on_exit(self) -> None:
        if getattr(self.trace, "_finalized", False):
            return
        try:
            self.trace.emit("run.abandoned", reason="interpreter_exit")
            self.trace.finalize(
                status="abandoned",
                error=RuntimeError("processo encerrado inesperadamente"),
            )
        except Exception:
            log.exception("Falha ao registrar execucao abandonada")
