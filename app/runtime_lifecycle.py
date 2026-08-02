"""Bounded ownership of runtime background work."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
import json
import math
import os
import signal
import sys
import threading
import time


class RuntimeShuttingDown(RuntimeError):
    """Raised when work is submitted after runtime shutdown begins."""


@dataclass(frozen=True)
class ShutdownReport:
    """Immutable outcome of a lifecycle shutdown attempt."""

    cancelled: tuple[tuple[str, object], ...]
    remaining: tuple[tuple[str, object], ...]


class JobHandle:
    """Cancellation and join handle for one lifecycle-owned job."""

    def __init__(
        self,
        lifecycle,
        job_id,
        name,
        owner_id,
        cancel_event,
        defer_cancel_until_callbacks,
    ):
        self._lifecycle = lifecycle
        self._job_id = job_id
        self.name = name
        self.owner_id = owner_id
        self.cancel_event = cancel_event
        self.defer_cancel_until_callbacks = defer_cancel_until_callbacks
        self._future = None

    def _set_future(self, future):
        self._future = future

    def cancel(self):
        """Signal cancellation once and report whether this call changed state."""
        return self._lifecycle._cancel_handle(self)

    def done(self):
        """Return whether the executor has completed the job."""
        return self._future is not None and self._future.done()

    def join(self, timeout=None):
        """Wait up to ``timeout`` seconds without propagating worker errors."""
        if self._future is None or self._lifecycle._is_current_job(self._job_id):
            return False
        try:
            self._future.result(timeout=timeout)
        except TimeoutError:
            return False
        except Exception:
            return True
        return True


class RuntimeLifecycle:
    """Own a bounded set of cancelable runtime background jobs."""

    def __init__(self, max_workers):
        if (
            isinstance(max_workers, bool)
            or not isinstance(max_workers, int)
            or max_workers <= 0
        ):
            raise ValueError('max_workers must be a positive integer')

        self._lock = threading.RLock()
        self._shutdown_condition = threading.Condition(self._lock)
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix='webssh-runtime',
        )
        self._jobs = {}
        self._shutdown_callbacks = {}
        self._next_job_id = 0
        self._accepting_jobs = True
        self._shutdown_started = False
        self._shutdown_report = None
        self._executor_shutdown = False
        self._worker_state = threading.local()
        self._process_shutdown_signals_installed = False
        self._process_shutdown_signal_guard = None

    def register_shutdown_callback(self, name, callback):
        """Register one bounded cancellation callback within shutdown grace."""
        if not isinstance(name, str) or not name:
            raise ValueError('name is required')
        if not callable(callback):
            raise ValueError('callback must be callable')
        with self._lock:
            if not self._accepting_jobs:
                raise RuntimeShuttingDown('runtime lifecycle is shutting down')
            if name in self._shutdown_callbacks:
                raise ValueError(f'shutdown callback already registered: {name}')
            self._shutdown_callbacks[name] = callback

    def accepting_work(self):
        """Return whether this runtime may still allocate new resources."""
        with self._lock:
            return self._accepting_jobs

    def start_job(
        self,
        name,
        target,
        *,
        owner_id=None,
        defer_cancel_until_callbacks=False,
    ):
        """Start ``target(cancel_event)`` or atomically reject it at shutdown."""
        if not isinstance(name, str) or not name:
            raise ValueError('name is required')
        if not callable(target):
            raise ValueError('target must be callable')
        if not isinstance(defer_cancel_until_callbacks, bool):
            raise ValueError(
                'defer_cancel_until_callbacks must be a boolean'
            )

        with self._lock:
            if not self._accepting_jobs:
                raise RuntimeShuttingDown('runtime lifecycle is shutting down')

            job_id = self._next_job_id
            self._next_job_id += 1
            cancel_event = threading.Event()
            handle = JobHandle(
                self,
                job_id,
                name,
                owner_id,
                cancel_event,
                defer_cancel_until_callbacks,
            )
            self._jobs[job_id] = handle

            def run():
                self._worker_state.job_id = job_id
                try:
                    target(cancel_event)
                finally:
                    self._worker_state.job_id = None

            try:
                future = self._executor.submit(run)
            except Exception:
                self._jobs.pop(job_id, None)
                raise
            handle._set_future(future)
            future.add_done_callback(
                lambda _completed, completed_id=job_id: self._remove_job(
                    completed_id
                )
            )
            return handle

    def begin_shutdown(self, grace_seconds):
        """Reject new work, signal active jobs, and wait for bounded completion."""
        if (
            isinstance(grace_seconds, bool)
            or not isinstance(grace_seconds, (int, float))
            or not math.isfinite(grace_seconds)
            or grace_seconds < 0
        ):
            raise ValueError('grace_seconds must be a non-negative finite number')

        if self._is_current_job():
            raise RuntimeError(
                'begin_shutdown cannot run from a lifecycle worker'
            )

        with self._shutdown_condition:
            if self._shutdown_report is not None:
                report = self._shutdown_report
                shutdown_executor = not self._executor_shutdown
                if shutdown_executor:
                    self._executor_shutdown = True
            elif self._shutdown_started:
                while self._shutdown_report is None:
                    self._shutdown_condition.wait()
                report = self._shutdown_report
                shutdown_executor = not self._executor_shutdown
                if shutdown_executor:
                    self._executor_shutdown = True
            else:
                self._shutdown_started = True
                self._accepting_jobs = False
                handles = tuple(self._jobs.values())
                callbacks = tuple(self._shutdown_callbacks.items())
                snapshots = tuple(
                    (handle.name, handle.owner_id) for handle in handles
                )
                report = None
                shutdown_executor = False

        if report is None:
            deadline = time.monotonic() + float(grace_seconds)
            callback_waiters = []
            for callback_name, callback in callbacks:
                try:
                    result = callback(deadline)
                    for waiter in result or ():
                        if (
                            not isinstance(waiter, tuple)
                            or len(waiter) != 3
                            or not hasattr(waiter[2], 'is_set')
                            or not hasattr(waiter[2], 'wait')
                        ):
                            raise TypeError(
                                'shutdown callback waiters must be '
                                '(name, owner_id, event) tuples'
                            )
                        callback_waiters.append(waiter)
                except Exception as error:
                    print(json.dumps({
                        'event': 'runtime_lifecycle_shutdown_callback_failed',
                        'callback': callback_name,
                        'error_type': type(error).__name__,
                    }), file=sys.stderr, flush=True)
            immediate_handles = tuple(
                handle
                for handle in handles
                if not handle.defer_cancel_until_callbacks
            )
            deferred_handles = tuple(
                handle
                for handle in handles
                if handle.defer_cancel_until_callbacks
            )
            for handle in immediate_handles:
                handle.cancel()
            for _name, _owner_id, done_event in callback_waiters:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                done_event.wait(remaining)
            for handle in deferred_handles:
                handle.cancel()
            for handle in handles:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                handle.join(remaining)

            with self._shutdown_condition:
                remaining_jobs = tuple(
                    (handle.name, handle.owner_id)
                    for handle in handles
                    if not handle.done()
                )
                remaining_callbacks = tuple(
                    (name, owner_id)
                    for name, owner_id, done_event in callback_waiters
                    if not done_event.is_set()
                )
                cancelled_callbacks = tuple(
                    (name, owner_id)
                    for name, owner_id, _done_event in callback_waiters
                )
                report = ShutdownReport(
                    cancelled=snapshots + cancelled_callbacks,
                    remaining=remaining_jobs + remaining_callbacks,
                )
                self._shutdown_report = report
                if not self._executor_shutdown:
                    self._executor_shutdown = True
                    shutdown_executor = True
                self._shutdown_condition.notify_all()

        if shutdown_executor:
            self._executor.shutdown(wait=False, cancel_futures=False)
        print(json.dumps({
            'event': 'runtime_lifecycle_shutdown',
            'cancelled': list(report.cancelled),
            'remaining': list(report.remaining),
        }), flush=True)
        return report

    def install_process_shutdown_signals(self, grace_seconds):
        """Signal work before interpreter shutdown can join executor workers.

        ``ThreadPoolExecutor`` registers its own interpreter-exit join ahead of
        normal ``atexit`` handlers.  The process bootstrap therefore installs
        these SIGTERM/SIGINT handlers while the application is alive, so active
        jobs receive cancellation and the configured grace period before the
        existing server/default signal behavior continues.
        """
        if threading.current_thread() is not threading.main_thread():
            return False

        with self._lock:
            if self._process_shutdown_signals_installed:
                return True
            # Python delivers handlers on the main thread, but can interrupt a
            # blocking call made by one handler with another signal. The shared
            # nonblocking lock therefore covers both SIGTERM and SIGINT.
            signal_handler_guard = threading.Lock()
            self._process_shutdown_signal_guard = signal_handler_guard
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous = signal.getsignal(signum)
                if previous is signal.SIG_IGN:
                    continue

                def shutdown_handler(
                        received_signal, frame, previous=previous,
                        guard=signal_handler_guard):
                    if not guard.acquire(blocking=False):
                        os._exit(128 + received_signal)
                        return
                    try:
                        report = self.begin_shutdown(grace_seconds)
                        if callable(previous):
                            try:
                                return previous(received_signal, frame)
                            finally:
                                if report.remaining:
                                    os._exit(128 + received_signal)
                        signal.signal(received_signal, signal.SIG_DFL)
                        os.kill(os.getpid(), received_signal)
                    finally:
                        guard.release()

                signal.signal(signum, shutdown_handler)
            self._process_shutdown_signals_installed = True
        return True

    def _remove_job(self, job_id):
        with self._lock:
            self._jobs.pop(job_id, None)

    def _cancel_handle(self, handle):
        with self._lock:
            if handle.cancel_event.is_set():
                return False
            handle.cancel_event.set()
            return True

    def _is_current_job(self, job_id=None):
        current_job_id = getattr(self._worker_state, 'job_id', None)
        return current_job_id is not None and (
            job_id is None or current_job_id == job_id
        )
