import os
import subprocess
import sys
import threading

import pytest

from app.quota_manager import (
    QuotaExceeded,
    QuotaKind,
    QuotaManager,
    release_reservation,
)


def _limits(global_limit=3, per_user_limit=2):
    return {
        kind: {
            'global': global_limit,
            'per_user': per_user_limit,
        }
        for kind in QuotaKind
    }


def test_release_reservation_is_null_safe_and_idempotent():
    manager = QuotaManager(_limits())
    reservation = manager.reserve(QuotaKind.SSH_SESSION, user_id=1)

    release_reservation(None)
    release_reservation(reservation)
    release_reservation(reservation)

    replacement = manager.reserve(QuotaKind.SSH_SESSION, user_id=1)
    replacement.release()


def test_per_user_limit_preserves_global_capacity_for_another_user():
    manager = QuotaManager(_limits(global_limit=3, per_user_limit=2))
    first = manager.reserve(QuotaKind.SSH_SESSION, user_id=1)
    second = manager.reserve(QuotaKind.SSH_SESSION, user_id=1)

    with pytest.raises(QuotaExceeded) as exc_info:
        manager.reserve(QuotaKind.SSH_SESSION, user_id=1)

    assert exc_info.value.kind is QuotaKind.SSH_SESSION
    assert exc_info.value.limit == 2
    assert exc_info.value.scope == 'per_user'
    assert '1' not in str(exc_info.value)

    other_user = manager.reserve(QuotaKind.SSH_SESSION, user_id=2)
    with pytest.raises(QuotaExceeded) as global_exc:
        manager.reserve(QuotaKind.SSH_SESSION, user_id=3)
    assert global_exc.value.scope == 'global'

    first.release()
    second.release()
    other_user.release()


def test_concurrent_reservations_never_exceed_limits():
    manager = QuotaManager(_limits(global_limit=6, per_user_limit=3))
    barrier = threading.Barrier(12)
    reservations = []
    failures = []
    result_lock = threading.Lock()

    def reserve(user_id):
        barrier.wait()
        try:
            reservation = manager.reserve(
                QuotaKind.QUICK_CONNECTION, user_id=user_id
            )
        except QuotaExceeded as exc:
            with result_lock:
                failures.append(exc)
        else:
            with result_lock:
                reservations.append(reservation)

    threads = [
        threading.Thread(target=reserve, args=(1,))
        for _ in range(9)
    ] + [
        threading.Thread(target=reserve, args=(2,))
        for _ in range(3)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)

    assert all(not thread.is_alive() for thread in threads)
    assert len(reservations) == 6
    assert len(failures) == 6
    assert sum(r.user_id == '1' for r in reservations) == 3
    assert sum(r.user_id == '2' for r in reservations) == 3

    for reservation in reservations:
        reservation.release()


def test_weighted_reservation_checks_global_and_per_user_amounts():
    manager = QuotaManager(_limits(global_limit=10, per_user_limit=6))

    reservation = manager.reserve(
        QuotaKind.TEMP_BYTES, user_id='7', amount=6
    )

    with pytest.raises(QuotaExceeded) as exc_info:
        manager.reserve(QuotaKind.TEMP_BYTES, user_id=7, amount=1)
    assert exc_info.value.scope == 'per_user'
    reservation.release()


def test_reservation_release_is_idempotent_and_context_compatible():
    limits = _limits(global_limit=2, per_user_limit=1)
    limits[QuotaKind.BACKGROUND_JOB] = {'global': 1, 'per_user': 1}
    manager = QuotaManager(limits)

    with manager.reserve(QuotaKind.BACKGROUND_JOB, user_id=1) as reservation:
        assert reservation.released is False
        with pytest.raises(QuotaExceeded):
            manager.reserve(QuotaKind.BACKGROUND_JOB, user_id=1)

    assert reservation.released is True
    reservation.release()
    replacement = manager.reserve(QuotaKind.BACKGROUND_JOB, user_id=1)
    replacement.release()


@pytest.mark.parametrize('value', [True, False, 0, -1, 1.5, '1', None])
def test_limits_must_be_positive_integers(value):
    limits = _limits()
    limits[QuotaKind.TRANSFER] = {'global': value, 'per_user': 1}

    with pytest.raises(ValueError):
        QuotaManager(limits)


@pytest.mark.parametrize('amount', [True, False, 0, -1, 1.5, '1', None])
def test_reservation_amount_must_be_a_positive_integer(amount):
    manager = QuotaManager(_limits())

    with pytest.raises(ValueError):
        manager.reserve(QuotaKind.TEMP_BYTES, user_id=1, amount=amount)


def test_all_planned_quota_kinds_are_configured():
    assert set(QuotaKind) == {
        QuotaKind.SSH_SESSION,
        QuotaKind.QUICK_CONNECTION,
        QuotaKind.TRANSFER,
        QuotaKind.TEMP_BYTES,
        QuotaKind.BACKGROUND_JOB,
    }


@pytest.mark.parametrize(
    'kind',
    [
        QuotaKind.SSH_SESSION,
        QuotaKind.QUICK_CONNECTION,
        QuotaKind.TRANSFER,
    ],
)
def test_fair_slot_quotas_require_per_user_limit_below_global(kind):
    limits = _limits()
    limits[kind] = {'global': 2, 'per_user': 2}

    with pytest.raises(ValueError):
        QuotaManager(limits)


@pytest.mark.parametrize(
    'kind', [QuotaKind.TEMP_BYTES, QuotaKind.BACKGROUND_JOB]
)
def test_non_slot_quotas_allow_equal_global_and_per_user_limits(kind):
    limits = _limits()
    limits[kind] = {'global': 1, 'per_user': 1}

    QuotaManager(limits)


@pytest.mark.parametrize('value', ['true', '0', '-1', '1.5', ''])
def test_quota_environment_values_fail_closed(value):
    env = os.environ.copy()
    env['SECRET_KEY'] = 'quota-test-secret'
    env['QUOTA_TRANSFER_GLOBAL'] = value

    result = subprocess.run(
        [sys.executable, '-c', 'import config'],
        cwd=os.getcwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert 'QUOTA_TRANSFER_GLOBAL must be a positive integer' in (
        result.stdout + result.stderr
    )


def test_quota_environment_rejects_unfair_slot_limits():
    env = os.environ.copy()
    env['SECRET_KEY'] = 'quota-test-secret'
    env['QUOTA_SSH_SESSION_GLOBAL'] = '2'
    env['QUOTA_SSH_SESSION_PER_USER'] = '2'

    result = subprocess.run(
        [sys.executable, '-c', 'import config'],
        cwd=os.getcwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert 'QUOTA_SSH_SESSION_PER_USER must be below' in (
        result.stdout + result.stderr
    )


def test_max_sessions_remains_alias_for_global_ssh_quota():
    env = os.environ.copy()
    env['SECRET_KEY'] = 'quota-test-secret'
    env['QUOTA_SSH_SESSION_GLOBAL'] = '17'
    command = (
        'import config; '
        'assert config.MAX_SESSIONS == 17; '
        'assert config.QUOTA_SSH_SESSION_GLOBAL == 17'
    )

    result = subprocess.run(
        [sys.executable, '-c', command],
        cwd=os.getcwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
