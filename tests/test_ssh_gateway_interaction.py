import threading
import time
import pytest
from app.ssh_gateway_interaction import GatewayAttempt, GatewayCancelled


@pytest.fixture(autouse=True)
def gateway_enabled(monkeypatch):
    from app import app_settings
    monkeypatch.setattr(app_settings, 'is_ssh_gateway_enabled', lambda: True)


def test_disabling_gateway_blocks_pending_but_preserves_committed_attempt(monkeypatch):
    from app import app_settings
    pending = GatewayAttempt(1, 'sid', 'pending', lambda *args: None)
    committed = GatewayAttempt(1, 'sid', 'connected', lambda *args: None)
    try:
        assert committed.commit_if_active()
        monkeypatch.setattr(app_settings, 'is_ssh_gateway_enabled', lambda: False)
        with pytest.raises(GatewayCancelled):
            pending.check()
        assert not pending.commit_if_active()
        committed.check()
    finally:
        pending.finish()
        committed.finish()


def test_challenge_is_owned_one_shot_and_never_replays():
    sent = []
    attempt = GatewayAttempt("1", "sid", "req", lambda event, data: sent.append((event, data)))
    result = []
    worker = threading.Thread(target=lambda: result.append(attempt.challenge("Title", "", [("OTP", True)])))
    worker.start()
    for _ in range(100):
        if sent: break
        time.sleep(.005)
    prompt = sent[0][1]
    assert not attempt.answer("2", "sid", prompt["challenge_id"], ["secret"])
    assert not attempt.answer("1", "other", prompt["challenge_id"], ["secret"])
    assert attempt.answer("1", "sid", prompt["challenge_id"], ["123456"])
    assert not attempt.answer("1", "sid", prompt["challenge_id"], ["replay"])
    worker.join(1)
    assert result == [["123456"]]
    attempt.finish()


def test_cancel_closes_resources_and_wakes_prompt():
    sent = []
    attempt = GatewayAttempt("1", "sid", "req", lambda *args: sent.append(args))
    closed = threading.Event()
    class Resource:
        def close(self): closed.set()
    attempt.own(Resource())
    errors = []
    def wait():
        try: attempt.challenge("", "", [("OTP", False)])
        except GatewayCancelled: errors.append(True)
    worker = threading.Thread(target=wait); worker.start()
    attempt.cancel()
    worker.join(1)
    assert closed.is_set() and errors == [True]
    attempt.finish()


def test_limits_reject_before_emitting_unbounded_remote_data():
    attempt = GatewayAttempt("1", "sid", "req", lambda *args: pytest.fail())
    with pytest.raises(ValueError):
        attempt.challenge("x"*16385, "", [])
    with pytest.raises(ValueError):
        attempt.challenge("", "", [("x", False)]*9)
    attempt.finish()


def test_handoff_prevents_late_cleanup_from_closing_owned_session():
    attempt = GatewayAttempt("1", "sid", "req", lambda *args: None)
    class Resource:
        def close(self): pytest.fail("closed after handoff")
    resource = Resource()
    attempt.own(resource)
    attempt.handoff(resource)
    attempt.finish()

def test_cancel_retains_admission_until_job_finishes():
    released = []
    class Reservation:
        def release(self): released.append(True)
    attempt = GatewayAttempt(1, "socket", "req", lambda *args: None, reservation=Reservation())
    attempt.cancel()
    assert released == []
    attempt.finish()
    attempt.finish()
    assert released == [True]


def test_output_has_a_four_frame_window_and_exact_acknowledgements():
    sent = []
    attempt = GatewayAttempt(1, "socket", "req", lambda *args: sent.append(args))
    try:
        for _ in range(4): attempt.output(b"x")
        assert len(attempt.unacked) == 4
        assert not attempt.ack(True)
        assert not attempt.ack(5)
        assert attempt.ack(1)
        assert not attempt.ack(1)
        attempt.output(b"next")
        assert len(attempt.unacked) == 4
        assert len(sent) == 5
    finally: attempt.finish()


def test_setup_input_cannot_escape_phase_or_byte_limits():
    attempt = GatewayAttempt(1, "socket", "req", lambda *args: None)
    try:
        assert not attempt.input("y")
        attempt.start_setup()
        assert not attempt.input("x"*1025)
        for _ in range(8): assert attempt.input("x"*1024)
        assert not attempt.input("y")
        attempt.cancel()
        assert not attempt.input("y")
    finally: attempt.finish()


def test_resource_registered_after_cancel_is_closed_immediately():
    closed = []
    attempt = GatewayAttempt(1, "socket", "req", lambda *args: None)
    class Resource:
        def close(self): closed.append(True)
    attempt.cancel()
    with pytest.raises(GatewayCancelled):
        attempt.own(Resource())
    assert closed == [True]
    attempt.finish()


@pytest.mark.parametrize("winner", ["timeout", "commit"])
def test_gateway_timeout_is_atomic_with_terminal_commit(winner):
    gateway = GatewayAttempt(1, "sid", "req", lambda *args: None)
    cancellation = gateway
    try:
        if winner == "timeout":
            gateway.cancel(reason="timeout")
            assert not cancellation.commit_if_active()
            assert cancellation.is_set()
            assert not gateway.committed
        else:
            assert cancellation.commit_if_active()
            assert not gateway.cancel(reason="timeout")
            assert not cancellation.is_set()
            assert gateway.committed
    finally:
        gateway.finish()


def test_timeout_wins_while_commit_is_waiting_on_gateway_condition():
    gateway = GatewayAttempt(1, "sid", "race", lambda *args: None)
    result = []
    entered = threading.Event()
    cancellation = gateway
    def commit():
        entered.set()
        result.append(cancellation.commit_if_active())
    worker = threading.Thread(target=commit)
    try:
        with gateway.condition:
            worker.start()
            assert entered.wait(1)
            gateway.cancel(reason="timeout")
        worker.join(1)
        assert not worker.is_alive()
        assert result == [False]
        assert not gateway.committed
    finally:
        gateway.finish()


def test_ordinary_mfa_does_not_require_gateway_setting(monkeypatch):
    from app import app_settings
    monkeypatch.setattr(app_settings, 'is_ssh_gateway_enabled', lambda: False)
    sent = []
    attempt = GatewayAttempt(1, 'sid', 'pam', lambda event, data: sent.append((event, data)), require_gateway=False)
    try:
        attempt.check()
        assert attempt.commit_if_active()
    finally:
        attempt.finish()
