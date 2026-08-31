from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


class ProviderWorkerCapacityError(RuntimeError):
    """The bounded provider-worker pool has no safe execution slot left."""


class ProviderCallSupervisor:
    """Bound the number of provider calls that may outlive their deadlines.

    Python cannot safely terminate an arbitrary thread. A timed-out provider may
    therefore continue running, but it retains one capacity slot until it really
    exits. Once all slots are occupied, new calls fail closed without creating
    another worker. This converts an unbounded thread leak into a finite,
    observable availability failure.
    """

    def __init__(self, *, max_outstanding_workers: int = 32) -> None:
        if max_outstanding_workers <= 0:
            raise ValueError("max_outstanding_workers must be positive")
        self.max_outstanding_workers = max_outstanding_workers
        self._slots = threading.BoundedSemaphore(max_outstanding_workers)
        self._lock = threading.Lock()
        self._outstanding = 0

    @property
    def outstanding_workers(self) -> int:
        with self._lock:
            return self._outstanding

    def call(self, fn: Callable[[], T], timeout_seconds: float) -> T:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not self._slots.acquire(blocking=False):
            raise ProviderWorkerCapacityError(
                f"provider worker capacity exhausted ({self.max_outstanding_workers})"
            )
        with self._lock:
            self._outstanding += 1

        results: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)

        def worker() -> None:
            try:
                try:
                    results.put(("ok", fn()))
                except BaseException as exc:  # preserve provider exception classification
                    results.put(("err", exc))
            finally:
                with self._lock:
                    self._outstanding -= 1
                self._slots.release()

        thread = threading.Thread(target=worker, name="illusiontion-provider-call", daemon=True)
        thread.start()
        thread.join(timeout_seconds)
        if thread.is_alive():
            raise TimeoutError(f"provider call exceeded {timeout_seconds:.3f}s wall-clock deadline")
        kind, value = results.get_nowait()
        if kind == "err":
            raise value  # type: ignore[misc]
        return value  # type: ignore[return-value]


_DEFAULT_SUPERVISOR = ProviderCallSupervisor()


def call_with_wall_clock_timeout(fn: Callable[[], T], timeout_seconds: float) -> T:
    """Run one potentially hanging provider call behind a hard controller deadline.

    The worker is daemonized so a provider that never returns cannot block process
    shutdown. No retry is performed. The caller receives TimeoutError and must
    preserve that terminal failure in the signed record.
    """
    return _DEFAULT_SUPERVISOR.call(fn, timeout_seconds)
