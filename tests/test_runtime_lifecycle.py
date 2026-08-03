import dataclasses
import json
import os
import runpy
import signal
import subprocess
import sys
import threading
import time
import textwrap
from pathlib import Path

import pytest

from app.runtime_lifecycle import RuntimeLifecycle, RuntimeShuttingDown


def test_shutdown_callbacks_cancel_request_owned_work_once_before_job_wait():
    lifecycle = RuntimeLifecycle(max_workers=1)
    callback_ran = threading.Event()
    job_observed_callback = []

    lifecycle.register_shutdown_callback(
        'active_transfers',
        lambda _deadline: callback_ran.set(),
    )

    def job(cancel_event):
        cancel_event.wait(1)
        job_observed_callback.append(callback_ran.is_set())

    lifecycle.start_job('reader', job)

    lifecycle.begin_shutdown(1)
    lifecycle.begin_shutdown(1)

    assert job_observed_callback == [True]


def test_shutdown_callback_registration_is_unique_and_closed_at_shutdown():
    lifecycle = RuntimeLifecycle(max_workers=1)
    lifecycle.register_shutdown_callback(
        'active_transfers', lambda _deadline: ()
    )

    with pytest.raises(ValueError, match='already registered'):
        lifecycle.register_shutdown_callback(
            'active_transfers', lambda _deadline: ()
        )

    lifecycle.begin_shutdown(0)

    with pytest.raises(RuntimeShuttingDown):
        lifecycle.register_shutdown_callback('late', lambda _deadline: ())


def test_shutdown_callback_residue_uses_shared_deadline_and_is_reported():
    lifecycle = RuntimeLifecycle(max_workers=1)
    request_done = threading.Event()
    observed_deadlines = []

    def cancel_request_work(deadline):
        observed_deadlines.append(deadline)
        return (('http_upload', 'transfer-7', request_done),)

    lifecycle.register_shutdown_callback(
        'active_transfers', cancel_request_work
    )

    started_at = time.monotonic()
    report = lifecycle.begin_shutdown(0.02)
    elapsed = time.monotonic() - started_at

    assert elapsed < 0.25
    assert len(observed_deadlines) == 1
    assert observed_deadlines[0] >= started_at
    assert report.cancelled == (('http_upload', 'transfer-7'),)
    assert report.remaining == (('http_upload', 'transfer-7'),)


def test_deferred_job_cancels_only_after_request_cleanup_waiter_finishes():
    lifecycle = RuntimeLifecycle(max_workers=1)
    request_done = threading.Event()
    deferred_started = threading.Event()
    deferred_observed_request_done = []

    lifecycle.register_shutdown_callback(
        'active_transfers',
        lambda _deadline: (('http_upload', 'transfer-7', request_done),),
    )

    def close_pool(cancel_event):
        deferred_started.set()
        cancel_event.wait(1)
        deferred_observed_request_done.append(request_done.is_set())

    lifecycle.start_job(
        'temporary_connection_cleanup',
        close_pool,
        defer_cancel_until_callbacks=True,
    )
    assert deferred_started.wait(1)

    shutdown = threading.Thread(target=lambda: lifecycle.begin_shutdown(1))
    shutdown.start()
    time.sleep(0.02)
    assert deferred_observed_request_done == []

    request_done.set()
    shutdown.join(1)

    assert deferred_observed_request_done == [True]


def test_shutdown_emits_structured_empty_remaining_report(capsys):
    lifecycle = RuntimeLifecycle(max_workers=1)

    report = lifecycle.begin_shutdown(0)

    events = [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if line.startswith('{')
    ]
    assert report.remaining == ()
    assert events[-1] == {
        'event': 'runtime_lifecycle_shutdown',
        'cancelled': [],
        'remaining': [],
    }


def test_start_job_exposes_owner_metadata_and_native_cancellation_event():
    """Removing owner metadata or replacing the cancellation Event breaks ownership."""
    lifecycle = RuntimeLifecycle(max_workers=1)
    started = threading.Event()
    observed = []

    def job(cancel_event):
        observed.append(cancel_event)
        started.set()
        cancel_event.wait(1)

    try:
        handle = lifecycle.start_job('reader', job, owner_id='user-7')

        assert started.wait(1)
        assert handle.name == 'reader'
        assert handle.owner_id == 'user-7'
        assert isinstance(handle.cancel_event, threading.Event)
        assert observed == [handle.cancel_event]
    finally:
        lifecycle.begin_shutdown(1)


def test_cancel_is_idempotent_and_join_waits_for_the_job():
    """Dropping the Event signal or join behavior leaves worker jobs running."""
    lifecycle = RuntimeLifecycle(max_workers=1)
    stopped = threading.Event()

    def job(cancel_event):
        cancel_event.wait(1)
        stopped.set()

    try:
        handle = lifecycle.start_job('reader', job)

        assert handle.cancel() is True
        assert handle.cancel() is False
        assert handle.join(1) is True
        assert stopped.is_set()
    finally:
        lifecycle.begin_shutdown(1)


def test_parallel_cancel_calls_have_exactly_one_state_transition():
    """A check-then-set cancel race reports two owners unless it shares the registry lock."""
    lifecycle = RuntimeLifecycle(max_workers=1)

    class SlowEvent:
        def __init__(self):
            self._set = False
            self.checked = threading.Event()

        def is_set(self):
            result = self._set
            self.checked.set()
            time.sleep(0.05)
            return result

        def set(self):
            self._set = True

    handle = lifecycle.start_job('reader', lambda _cancel_event: None)
    handle.cancel_event = SlowEvent()
    results = []
    first = threading.Thread(target=lambda: results.append(handle.cancel()))
    second = threading.Thread(target=lambda: results.append(handle.cancel()))

    try:
        first.start()
        assert handle.cancel_event.checked.wait(1)
        second.start()
        first.join(1)
        second.join(1)

        assert not first.is_alive()
        assert not second.is_alive()
        assert results.count(True) == 1
    finally:
        lifecycle.begin_shutdown(1)


def test_process_shutdown_signal_cancels_before_executor_exit(monkeypatch):
    """A normal atexit hook runs too late for ThreadPoolExecutor workers."""
    import signal
    import app.runtime_lifecycle as runtime_lifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    started = threading.Event()

    def job(cancel_event):
        started.set()
        cancel_event.wait(1)

    handle = lifecycle.start_job('reader', job)
    installed = {}
    delegated = []

    def server_handler(signum, frame):
        delegated.append((signum, frame))

    monkeypatch.setattr(
        runtime_lifecycle.signal, 'getsignal', lambda _sig: server_handler
    )
    monkeypatch.setattr(
        runtime_lifecycle.signal,
        'signal',
        lambda signum, handler: installed.setdefault(signum, handler),
    )

    try:
        assert started.wait(1)
        lifecycle.install_process_shutdown_signals(1)
        installed[signal.SIGTERM](signal.SIGTERM, None)

        assert handle.cancel_event.is_set()
        assert handle.join(1) is True
        assert delegated == [(signal.SIGTERM, None)]
    finally:
        lifecycle.begin_shutdown(1)


def test_process_shutdown_delegates_to_the_existing_server_handler(monkeypatch):
    """Replacing a Gunicorn worker handler would skip its normal termination."""
    import signal
    import app.runtime_lifecycle as runtime_lifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    delegated = []
    installed = {}

    def server_handler(signum, frame):
        delegated.append((signum, frame))

    monkeypatch.setattr(runtime_lifecycle.signal, 'getsignal', lambda _sig: server_handler)
    monkeypatch.setattr(
        runtime_lifecycle.signal,
        'signal',
        lambda signum, handler: installed.setdefault(signum, handler),
    )

    lifecycle.install_process_shutdown_signals(0)
    installed[signal.SIGTERM](signal.SIGTERM, None)

    assert delegated == [(signal.SIGTERM, None)]


def test_callable_signal_handler_forces_exit_after_grace_when_jobs_remain(
        monkeypatch):
    """A returning server handler must not leave a stuck executor worker alive."""
    import app.runtime_lifecycle as runtime_lifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    started = threading.Event()
    release = threading.Event()
    installed = {}
    calls = []

    def job(_cancel_event):
        started.set()
        release.wait(1)

    def server_handler(signum, frame):
        calls.append(('server_handler', signum, frame))

    monkeypatch.setattr(
        runtime_lifecycle.signal, 'getsignal', lambda _sig: server_handler)
    monkeypatch.setattr(
        runtime_lifecycle.signal, 'signal',
        lambda signum, handler: installed.__setitem__(signum, handler),
    )
    monkeypatch.setattr(
        runtime_lifecycle.os, '_exit',
        lambda code: calls.append(('exit', code)),
    )
    handle = lifecycle.start_job('stuck', job)

    try:
        assert started.wait(1)
        lifecycle.install_process_shutdown_signals(0)
        installed[signal.SIGTERM](signal.SIGTERM, None)

        assert calls == [
            ('server_handler', signal.SIGTERM, None),
            ('exit', 128 + signal.SIGTERM),
        ]
    finally:
        release.set()
        handle.join(1)


def test_callable_signal_handler_exit_fallback_runs_when_delegation_raises(
        monkeypatch):
    """The fallback belongs in finally so a raising server handler cannot hang."""
    import app.runtime_lifecycle as runtime_lifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    started = threading.Event()
    release = threading.Event()
    installed = {}
    exits = []

    def job(_cancel_event):
        started.set()
        release.wait(1)

    def server_handler(_signum, _frame):
        raise RuntimeError('server shutdown failed')

    monkeypatch.setattr(
        runtime_lifecycle.signal, 'getsignal', lambda _sig: server_handler)
    monkeypatch.setattr(
        runtime_lifecycle.signal, 'signal',
        lambda signum, handler: installed.__setitem__(signum, handler),
    )
    monkeypatch.setattr(runtime_lifecycle.os, '_exit', exits.append)
    handle = lifecycle.start_job('stuck', job)

    try:
        assert started.wait(1)
        lifecycle.install_process_shutdown_signals(0)
        with pytest.raises(RuntimeError, match='server shutdown failed'):
            installed[signal.SIGTERM](signal.SIGTERM, None)

        assert exits == [128 + signal.SIGTERM]
    finally:
        release.set()
        handle.join(1)


def test_ignored_process_signal_is_left_unwrapped(monkeypatch):
    """Ignoring a signal must not secretly start a half-shutdown."""
    import app.runtime_lifecycle as runtime_lifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    installed = []
    monkeypatch.setattr(
        runtime_lifecycle.signal, 'getsignal', lambda _sig: signal.SIG_IGN)
    monkeypatch.setattr(
        runtime_lifecycle.signal, 'signal',
        lambda signum, handler: installed.append((signum, handler)),
    )

    assert lifecycle.install_process_shutdown_signals(0) is True
    assert installed == []


def test_default_process_signal_resets_then_terminates_without_recursion(
        monkeypatch):
    """A default SIGTERM must still terminate after lifecycle cancellation."""
    import signal
    import app.runtime_lifecycle as runtime_lifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    installed = {}
    calls = []
    monkeypatch.setattr(
        runtime_lifecycle.signal, 'getsignal', lambda _sig: signal.SIG_DFL)
    def set_signal(signum, handler):
        calls.append(('signal', signum, handler))
        installed[signum] = handler

    monkeypatch.setattr(runtime_lifecycle.signal, 'signal', set_signal)
    monkeypatch.setattr(
        runtime_lifecycle.os, 'kill',
        lambda pid, signum: calls.append(('kill', pid, signum)),
    )

    lifecycle.install_process_shutdown_signals(0)
    calls.clear()
    installed[signal.SIGTERM](signal.SIGTERM, None)

    assert calls == [
        ('signal', signal.SIGTERM, signal.SIG_DFL),
        ('kill', runtime_lifecycle.os.getpid(), signal.SIGTERM),
    ]


def test_process_shutdown_signal_installation_is_main_thread_only_and_idempotent(
        monkeypatch):
    """Repeated factories must not wrap server handlers into a signal chain."""
    import app.runtime_lifecycle as runtime_lifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    installed = []

    def server_handler(_signum, _frame):
        pass

    monkeypatch.setattr(
        runtime_lifecycle.signal, 'getsignal', lambda _sig: server_handler)
    monkeypatch.setattr(
        runtime_lifecycle.signal, 'signal',
        lambda signum, handler: installed.append((signum, handler)),
    )

    assert lifecycle.install_process_shutdown_signals(0) is True
    assert lifecycle.install_process_shutdown_signals(0) is True
    assert len(installed) == 2

    monkeypatch.setattr(
        runtime_lifecycle.threading, 'current_thread', lambda: object())
    assert RuntimeLifecycle(max_workers=1).install_process_shutdown_signals(0) is False


@pytest.mark.skipif(os.name == 'nt', reason='POSIX signals are required')
def test_delegated_signal_force_exits_posix_process_with_stuck_worker():
    """A noncooperative executor job cannot keep a signalled worker alive."""
    project_root = Path(__file__).resolve().parents[1]
    script = textwrap.dedent(
        """
        import signal
        import threading
        import time
        from app.runtime_lifecycle import RuntimeLifecycle

        def server_handler(_signum, _frame):
            print('SERVER_HANDLER', flush=True)

        signal.signal(signal.SIGTERM, server_handler)
        lifecycle = RuntimeLifecycle(max_workers=1)
        started = threading.Event()

        def stuck_job(_cancel_event):
            started.set()
            time.sleep(60)

        lifecycle.start_job('stuck', stuck_job)
        assert started.wait(1)
        lifecycle.install_process_shutdown_signals(0.05)
        print('READY', flush=True)
        while True:
            time.sleep(1)
        """
    )
    environment = os.environ.copy()
    current_pythonpath = environment.get('PYTHONPATH')
    environment['PYTHONPATH'] = str(project_root) + (
        os.pathsep + current_pythonpath if current_pythonpath else ''
    )
    process = subprocess.Popen(
        [sys.executable, '-u', '-c', script],
        cwd=project_root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        assert process.stdout.readline().strip() == 'READY'
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=3)
            pytest.fail(
                'delegated SIGTERM did not terminate the stuck executor worker; '
                f'stdout={stdout!r} stderr={stderr!r}'
            )
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=3)

    assert process.returncode == 128 + signal.SIGTERM
    assert 'SERVER_HANDLER' in stdout


@pytest.mark.skipif(os.name == 'nt', reason='POSIX signals are required')
def test_second_termination_signal_force_exits_stuck_process_immediately():
    """A nested signal must never re-enter the first bounded shutdown wait."""
    project_root = Path(__file__).resolve().parents[1]
    script = textwrap.dedent(
        """
        import signal
        import threading
        import time
        from app.runtime_lifecycle import RuntimeLifecycle

        def server_handler(signum, _frame):
            print(f'SERVER_HANDLER_{signum}', flush=True)

        signal.signal(signal.SIGTERM, server_handler)
        signal.signal(signal.SIGINT, server_handler)
        lifecycle = RuntimeLifecycle(max_workers=1)
        started = threading.Event()

        def stuck_job(cancel_event):
            started.set()
            cancel_event.wait()
            print('CANCELLED', flush=True)
            time.sleep(60)

        lifecycle.start_job('stuck', stuck_job)
        assert started.wait(1)
        lifecycle.install_process_shutdown_signals(0.25)
        print('READY', flush=True)
        while True:
            time.sleep(1)
        """
    )
    environment = os.environ.copy()
    current_pythonpath = environment.get('PYTHONPATH')
    environment['PYTHONPATH'] = str(project_root) + (
        os.pathsep + current_pythonpath if current_pythonpath else ''
    )
    process = subprocess.Popen(
        [sys.executable, '-u', '-c', script],
        cwd=project_root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        assert process.stdout.readline().strip() == 'READY'
        os.kill(process.pid, signal.SIGTERM)
        assert process.stdout.readline().strip() == 'CANCELLED'
        started_at = time.monotonic()
        os.kill(process.pid, signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=3)
            pytest.fail(
                'second termination signal re-entered bounded shutdown; '
                f'stdout={stdout!r} stderr={stderr!r}'
            )
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=3)

    assert time.monotonic() - started_at < 2
    assert process.returncode == 128 + signal.SIGINT


def test_second_installed_termination_handler_never_reenters_shutdown(
        monkeypatch):
    """A SIGINT during SIGTERM must force exit without a second shutdown wait."""
    import app.runtime_lifecycle as runtime_lifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    installed = {}
    shutdown_calls = []
    delegated = []
    exits = []

    def server_handler(signum, frame):
        delegated.append((signum, frame))

    def begin_shutdown(grace_seconds):
        shutdown_calls.append(grace_seconds)
        if len(shutdown_calls) == 1:
            installed[signal.SIGINT](signal.SIGINT, None)
        return runtime_lifecycle.ShutdownReport((), ())

    monkeypatch.setattr(
        runtime_lifecycle.signal, 'getsignal', lambda _signum: server_handler
    )
    monkeypatch.setattr(
        runtime_lifecycle.signal, 'signal',
        lambda signum, handler: installed.__setitem__(signum, handler),
    )
    monkeypatch.setattr(runtime_lifecycle.os, '_exit', exits.append)
    monkeypatch.setattr(lifecycle, 'begin_shutdown', begin_shutdown)

    lifecycle.install_process_shutdown_signals(1)
    installed[signal.SIGTERM](signal.SIGTERM, None)

    assert shutdown_calls == [1]
    assert exits == [128 + signal.SIGINT]
    assert delegated == [(signal.SIGTERM, None)]


def test_shutdown_from_lifecycle_worker_raises_before_state_changes():
    """A worker cannot publish a partial report that blocks real shutdown."""
    lifecycle = RuntimeLifecycle(max_workers=1)
    attempted = threading.Event()
    errors = []

    def job(_cancel_event):
        try:
            lifecycle.begin_shutdown(0)
        except RuntimeError as error:
            errors.append(str(error))
        finally:
            attempted.set()

    handle = lifecycle.start_job('bad_shutdown', job)
    assert attempted.wait(1)
    assert handle.join(1) is True
    assert errors == ['begin_shutdown cannot run from a lifecycle worker']

    report = lifecycle.begin_shutdown(1)

    assert report.cancelled == ()
    assert report.remaining == ()
    with pytest.raises(RuntimeError, match='cannot schedule new futures'):
        lifecycle._executor.submit(lambda: None)


def test_start_bootstrap_installs_the_app_runtime_shutdown_gate(monkeypatch):
    """The production WSGI bootstrap owns early signal installation, not tests."""
    import app as app_module
    import config

    calls = []
    lifecycle = type(
        'Lifecycle', (), {
            'install_process_shutdown_signals': lambda self, grace: calls.append(grace)
        }
    )()
    fake_app = type('App', (), {'extensions': {'runtime_lifecycle': lifecycle}})()
    monkeypatch.setattr(app_module, 'create_app', lambda: fake_app)

    namespace = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / 'start.py'),
        run_name='webssh_start_test',
    )

    assert namespace['app'] is fake_app
    assert calls == [config.RUNTIME_SHUTDOWN_GRACE_SECONDS]


def test_shutdown_rejects_new_jobs_and_reports_no_remaining_job():
    """Allowing work after shutdown can leak it past application teardown."""
    lifecycle = RuntimeLifecycle(max_workers=1)

    def job(cancel_event):
        cancel_event.wait(1)

    handle = lifecycle.start_job('reader', job, owner_id='user-7')
    report = lifecycle.begin_shutdown(1)

    assert handle.cancel_event.is_set()
    assert report.cancelled == (('reader', 'user-7'),)
    assert report.remaining == ()
    with pytest.raises(RuntimeShuttingDown):
        lifecycle.start_job('late', lambda _cancel_event: None)


def test_shutdown_returns_after_the_grace_period_with_remaining_jobs():
    """A stuck job must not make shutdown wait indefinitely."""
    lifecycle = RuntimeLifecycle(max_workers=1)
    started = threading.Event()
    release = threading.Event()

    def stuck_job(cancel_event):
        started.set()
        assert cancel_event.wait(1)
        release.wait(1)

    handle = lifecycle.start_job('stuck', stuck_job, owner_id='user-7')
    assert started.wait(1)

    started_at = time.monotonic()
    report = lifecycle.begin_shutdown(0.05)
    elapsed = time.monotonic() - started_at

    try:
        assert elapsed < 0.25
        assert handle.cancel_event.is_set()
        assert report.remaining == (('stuck', 'user-7'),)
    finally:
        release.set()
        handle.join(1)


def test_done_callback_removes_jobs_after_target_exception():
    """An exception must not leave a stale registry entry at shutdown."""
    lifecycle = RuntimeLifecycle(max_workers=1)
    raised = threading.Event()

    def broken_job(_cancel_event):
        raised.set()
        raise RuntimeError('boom')

    handle = lifecycle.start_job('broken', broken_job, owner_id='user-7')
    assert raised.wait(1)
    assert handle.join(1) is True

    report = lifecycle.begin_shutdown(0)

    assert report.cancelled == ()
    assert report.remaining == ()


def test_shutdown_is_idempotent_and_its_report_is_immutable():
    """Repeated teardown must not create a different lifecycle outcome."""
    lifecycle = RuntimeLifecycle(max_workers=1)
    report = lifecycle.begin_shutdown(0)

    assert lifecycle.begin_shutdown(1) is report
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        report.remaining = ()


def test_app_owns_and_stops_all_permanent_cleanup_jobs(app):
    """Unowned cleanup loops survive a Flask app factory and leak into later apps."""
    lifecycle = app.extensions['runtime_lifecycle']

    report = lifecycle.begin_shutdown(1)

    assert report.remaining == ()
    assert report.cancelled == (
        ('backup-operation-cleanup', None),
        ('inactive_socket_session_cleanup', None),
        ('idle_ssh_session_cleanup', None),
        ('temporary_connection_cleanup', None),
    )


def test_background_worker_default_reserves_cleanup_reader_and_transfer_slots():
    """Permanent cleanup jobs must not starve accepted readers or transfers."""
    import config

    assert config.BACKGROUND_WORKERS_MIN == (
        config.BACKGROUND_CLEANUP_JOBS
        + config.QUOTA_SSH_SESSION_GLOBAL
        + config.QUOTA_BACKGROUND_JOB_GLOBAL
    )
    assert config.BACKGROUND_WORKERS >= config.BACKGROUND_WORKERS_MIN
    assert config.BACKGROUND_WORKERS <= config.BACKGROUND_WORKERS_MAX


def test_sequential_app_factories_rebind_the_global_connection_pool(app):
    """A second test app must not keep its pool cleanup job on the first app."""
    from app import create_app, connection_pool

    first_lifecycle = app.extensions['runtime_lifecycle']
    first_pool = connection_pool.temp_connection_pool
    second_app = create_app()
    second_lifecycle = second_app.extensions['runtime_lifecycle']

    try:
        assert connection_pool.temp_connection_pool is not first_pool
        assert connection_pool.temp_connection_pool._cleanup_lifecycle is second_lifecycle
        assert first_pool.cleanup_handle.cancel_event.is_set()
    finally:
        first_lifecycle.begin_shutdown(1)
        second_lifecycle.begin_shutdown(1)


def test_app_factory_stops_started_jobs_when_pool_binding_fails(monkeypatch):
    """A partial cleanup startup must not leave its first jobs running."""
    import app as app_module
    from app import connection_pool
    import config

    real_lifecycle = RuntimeLifecycle
    created = []

    class TrackingLifecycle(real_lifecycle):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.shutdown_calls = []
            created.append(self)

        def begin_shutdown(self, grace_seconds):
            self.shutdown_calls.append(grace_seconds)
            return super().begin_shutdown(grace_seconds)

    def fail_pool_binding(_lifecycle):
        raise RuntimeError('pool binding failed')

    monkeypatch.setattr(app_module, 'RuntimeLifecycle', TrackingLifecycle)
    monkeypatch.setattr(
        connection_pool, 'bind_temp_connection_pool', fail_pool_binding
    )

    try:
        with pytest.raises(RuntimeError, match='pool binding failed'):
            app_module.create_app()

        lifecycle = created[-1]
        assert lifecycle.shutdown_calls == [
            config.RUNTIME_SHUTDOWN_GRACE_SECONDS
        ]
        assert lifecycle._jobs == {}
    finally:
        if created and created[-1]._shutdown_report is None:
            created[-1].begin_shutdown(config.RUNTIME_SHUTDOWN_GRACE_SECONDS)
