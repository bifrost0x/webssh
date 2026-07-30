import inspect

import pytest

from scripts import run_integration_tests
from tests.integration import test_paramiko5_openssh
from tests.integration import test_paramiko5_socketio


def test_runner_main_has_the_documented_int_result():
    assert inspect.signature(run_integration_tests.main).return_annotation is int


def test_runner_always_requests_compose_teardown(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "scripts.run_integration_tests.run",
        lambda args, **kw: calls.append(args) or 0,
    )

    assert run_integration_tests.main() == 0
    assert calls[-1][-2:] == ["down", "-v"]


def test_runner_always_removes_generated_key_runtime(monkeypatch):
    cleanup_calls = []
    monkeypatch.setattr(
        "scripts.run_integration_tests.run",
        lambda _args, **_kwargs: 0,
    )
    monkeypatch.setattr(
        "scripts.run_integration_tests.cleanup_runtime",
        lambda: cleanup_calls.append(True),
    )

    assert run_integration_tests.main() == 0
    assert cleanup_calls == [True]


def test_runtime_cleanup_refuses_directory_symlink(monkeypatch, tmp_path):
    project_root = tmp_path / "project"
    fixture_dir = project_root / "tests/integration/paramiko5"
    victim = fixture_dir / "victim"
    victim.mkdir(parents=True)
    marker = victim / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    runtime = fixture_dir / "runtime"
    runtime.symlink_to(victim, target_is_directory=True)
    monkeypatch.setattr(run_integration_tests, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(run_integration_tests, "RUNTIME_DIR", runtime)

    with pytest.raises(RuntimeError, match="symlink or reparse point"):
        run_integration_tests.cleanup_runtime()

    assert marker.read_text(encoding="utf-8") == "keep"


def test_runner_starts_compose_and_runs_both_integration_modules(monkeypatch):
    calls = []

    def record_call(args, **kwargs):
        calls.append((args, kwargs))
        return 0

    monkeypatch.setattr("scripts.run_integration_tests.run", record_call)

    assert run_integration_tests.main() == 0

    generator_args, generator_kwargs = calls[0]
    assert generator_args == [
        run_integration_tests.sys.executable,
        "tests/integration/paramiko5/generate_keys.py",
    ]
    assert generator_kwargs["cwd"] == run_integration_tests.PROJECT_ROOT

    startup_args, _startup_kwargs = calls[1]
    assert startup_args[-4:] == ["up", "-d", "--build", "--wait"]
    pytest_args, pytest_kwargs = calls[2]
    assert pytest_args[-2:] == [
        "tests/integration/test_paramiko5_openssh.py",
        "tests/integration/test_paramiko5_socketio.py",
    ]
    assert pytest_kwargs["env"]["PARAMIKO5_INTEGRATION"] == "1"


def test_runner_targets_the_compose_ports_exposed_to_the_host(monkeypatch):
    calls = []

    def record_call(args, **kwargs):
        calls.append((args, kwargs))
        return 0

    monkeypatch.setattr("scripts.run_integration_tests.run", record_call)

    assert run_integration_tests.main() == 0

    environment = calls[2][1]["env"]
    assert environment["PARAMIKO5_TARGET_HOST"] == "127.0.0.1"
    assert environment["PARAMIKO5_TARGET_PORT"] == "2223"
    assert environment["PARAMIKO5_BASTION_HOST"] == "127.0.0.1"
    assert environment["PARAMIKO5_BASTION_PORT"] == "2222"
    assert environment["PARAMIKO5_CHANGED_HOST"] == "127.0.0.1"
    assert environment["PARAMIKO5_CHANGED_PORT"] == "2224"


def test_runner_targets_the_compose_service_from_inside_the_bastion(monkeypatch):
    calls = []

    def record_call(args, **kwargs):
        calls.append((args, kwargs))
        return 0

    monkeypatch.setattr("scripts.run_integration_tests.run", record_call)

    assert run_integration_tests.main() == 0

    environment = calls[2][1]["env"]
    assert environment["PARAMIKO5_PROXY_TARGET_HOST"] == "target"
    assert environment["PARAMIKO5_PROXY_TARGET_PORT"] == "22"
    assert environment["PROXY_JUMP_REMOTE_DNS_ALLOWLIST"] == "target"


def test_direct_layer_proxy_uses_the_bastion_visible_target(monkeypatch):
    captured = {}

    def create_ssh_connection(**kwargs):
        captured.update(kwargs)
        return "session-id", None

    monkeypatch.setattr(
        test_paramiko5_openssh.ssh_manager,
        "create_ssh_connection",
        create_ssh_connection,
    )
    monkeypatch.setattr(
        test_paramiko5_openssh,
        "PROXY_TARGET_HOST",
        "compose-target",
        raising=False,
    )
    monkeypatch.setattr(
        test_paramiko5_openssh,
        "PROXY_TARGET_PORT",
        2200,
        raising=False,
    )

    test_paramiko5_openssh.connect_terminal(
        proxy_jump_host="compose-bastion",
    )

    assert captured["host"] == "compose-target"
    assert captured["port"] == 2200


def test_socket_layer_proxy_uses_the_bastion_visible_target(monkeypatch):
    class FakeSocket:
        def emit(self, event_name, payload):
            assert event_name == "ssh_connect"
            self.payload = payload

    socket_client = FakeSocket()
    monkeypatch.setattr(
        test_paramiko5_socketio,
        "PROXY_TARGET_HOST",
        "compose-target",
        raising=False,
    )
    monkeypatch.setattr(
        test_paramiko5_socketio,
        "PROXY_TARGET_PORT",
        2200,
        raising=False,
    )
    monkeypatch.setattr(
        test_paramiko5_socketio,
        "wait_for_event",
        lambda _client, _event: {
            "host": "compose-target",
            "port": 2200,
            "username": test_paramiko5_socketio.USERNAME,
            "client_request_id": "integration-request",
            "session_id": "session-id",
        },
    )

    test_paramiko5_socketio.emit_ssh_connect(
        socket_client,
        proxy_jump={"host": "compose-bastion"},
    )

    assert socket_client.payload["host"] == "compose-target"
    assert socket_client.payload["port"] == 2200


def test_windows_skips_only_the_posix_mode_bit_assertion():
    class PathWithoutPortableModeBits:
        def stat(self):
            raise AssertionError("Windows mode bits must not be inspected")

    test_paramiko5_openssh.assert_private_file_mode(
        PathWithoutPortableModeBits(),
        os_name="nt",
    )


def test_posix_keeps_the_private_mode_bit_assertion():
    class Stat:
        st_mode = 0o100600

    class PrivatePath:
        @staticmethod
        def stat():
            return Stat()

    test_paramiko5_openssh.assert_private_file_mode(
        PrivatePath(),
        os_name="posix",
    )


def test_posix_rejects_an_insecure_host_key_mode():
    class Stat:
        st_mode = 0o100644

    class PublicPath:
        @staticmethod
        def stat():
            return Stat()

    with pytest.raises(AssertionError):
        test_paramiko5_openssh.assert_private_file_mode(
            PublicPath(),
            os_name="posix",
        )


def test_host_key_lookup_name_keeps_the_default_port_unqualified():
    assert (
        test_paramiko5_openssh.host_key_lookup_name("example.test", 22)
        == "example.test"
    )


def test_host_key_lookup_name_qualifies_a_nondefault_port():
    assert (
        test_paramiko5_openssh.host_key_lookup_name("127.0.0.1", 2223)
        == "[127.0.0.1]:2223"
    )


def test_runner_stops_before_compose_when_key_generation_fails(monkeypatch):
    calls = []

    def fail_generator(args, **kwargs):
        calls.append((args, kwargs))
        return 23

    monkeypatch.setattr("scripts.run_integration_tests.run", fail_generator)

    assert run_integration_tests.main() == 23
    assert calls == [
        (
            [
                run_integration_tests.sys.executable,
                "tests/integration/paramiko5/generate_keys.py",
            ],
            {"cwd": run_integration_tests.PROJECT_ROOT},
        )
    ]


def test_runner_tears_down_compose_when_startup_fails_after_key_generation(
    monkeypatch,
):
    calls = []

    def fail_startup(args, **kwargs):
        calls.append((args, kwargs))
        return 17 if "up" in args else 0

    monkeypatch.setattr("scripts.run_integration_tests.run", fail_startup)

    assert run_integration_tests.main() == 17
    assert calls[0][0][1] == "tests/integration/paramiko5/generate_keys.py"
    assert calls[1][0][-4:] == ["up", "-d", "--build", "--wait"]
    assert calls[2][0][-2:] == ["down", "-v"]
