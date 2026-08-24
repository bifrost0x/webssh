import json
from pathlib import Path


def container_smoke_workflow():
    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    return workflow.split("  container-threading-smoke:\n", 1)[1]


def test_native_runtime_keeps_the_reviewed_gunicorn_and_worker_contract():
    """More workers would split process-local SSH and quota state."""
    requirements = Path("requirements.in").read_text(encoding="utf-8").splitlines()
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8").splitlines()

    assert "gunicorn>=26.1.0,<27" in requirements
    assert all("eventlet" not in requirement.casefold() for requirement in requirements)
    assert all("greenlet" not in requirement.casefold() for requirement in requirements)
    assert "simple-websocket>=1.1,<2" in requirements

    command = json.loads(next(line[4:] for line in dockerfile if line.startswith("CMD [")))
    assert command == [
        "sh",
        "-c",
        "exec gunicorn --worker-class gthread --workers 1 --threads \"${GUNICORN_THREADS}\" --bind 0.0.0.0:5000 start:app",
    ]


def test_container_ci_run_is_labeled_with_the_workflow_attempt_identity():
    workflow = container_smoke_workflow()

    assert 'ownership_label="webssh.ci-run=${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"' in workflow
    assert '--label "$ownership_label"' in workflow


def test_container_ci_image_is_bound_to_the_tested_revision():
    workflow = container_smoke_workflow()

    assert 'docker build --build-arg VCS_REF="${GITHUB_SHA}"' in workflow
    assert 'org.opencontainers.image.revision' in workflow
    assert 'if [ "$image_revision" != "$GITHUB_SHA" ]; then' in workflow


def test_container_ci_start_failure_trap_removes_only_its_labeled_container():
    workflow = container_smoke_workflow()
    start_step = workflow.split("      - name: Verify gthread worker and readiness", 1)[0]

    assert "trap cleanup_start_failure EXIT" in start_step
    assert 'if [ "$status" -ne 0 ] && docker container inspect "$container_name"' in start_step
    assert 'docker container inspect --format' in start_step
    assert 'if [ "$actual_label" = "$ownership_value" ]; then' in start_step
    assert "trap - EXIT" in start_step


def test_container_ci_normal_cleanup_rechecks_ownership_before_removal():
    workflow = container_smoke_workflow()
    cleanup_step = workflow.split("      - name: Clean up created container", 1)[1]

    assert 'docker container inspect "$WEBSSH_CI_CONTAINER"' in cleanup_step
    assert 'if [ "$actual_label" != "$WEBSSH_CI_CONTAINER_LABEL_VALUE" ]; then' in cleanup_step
    assert 'docker rm --force "$WEBSSH_CI_CONTAINER"' in cleanup_step


def test_container_ci_readiness_accepts_only_http_200():
    workflow = container_smoke_workflow()

    assert "--write-out '%{http_code}'" in workflow
    assert '[ "$ready_status" = "200" ]' in workflow


def test_container_ci_checks_graceful_shutdown_after_readiness():
    """A clean stop proves the lifecycle signal gate still runs under gthread."""
    workflow = container_smoke_workflow()
    shutdown_step = workflow.split("      - name: Verify graceful gthread shutdown", 1)[1].split(
        "      - name: Clean up created container", 1
    )[0]

    assert 'actual_label="$(docker inspect --format' in shutdown_step
    assert 'if [ "$actual_label" != "$WEBSSH_CI_CONTAINER_LABEL_VALUE" ]; then' in shutdown_step
    assert 'docker stop --time 35 "$WEBSSH_CI_CONTAINER"' in workflow
    assert 'docker inspect --format' in workflow
