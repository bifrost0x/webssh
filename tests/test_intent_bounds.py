"""Short-lived intents are bounded without letting accounts block each other."""
import pytest

from app.automation_store import AutomationError, INTENTS_GLOBAL, INTENTS_PER_USER, remember_intent


def payload(user_id, expires):
    return dict(user_id=user_id, expires=expires)


def test_a_user_at_the_bound_replaces_their_oldest_intent():
    intents = {}
    for index in range(INTENTS_PER_USER + 3):
        intents = remember_intent(intents, f'key-{index}', payload(1, 100 + index), now=0)
    assert len(intents) == INTENTS_PER_USER
    assert 'key-0' not in intents and f'key-{INTENTS_PER_USER + 2}' in intents


def test_other_users_are_not_affected_by_one_busy_account():
    intents = {}
    for index in range(INTENTS_PER_USER * 4):
        intents = remember_intent(intents, f'a-{index}', payload(1, 100 + index), now=0)
    intents = remember_intent(intents, 'b-0', payload(2, 100), now=0)
    assert 'b-0' in intents


def test_expired_intents_are_dropped_first():
    intents = {'old': payload(1, 5)}
    intents = remember_intent(intents, 'new', payload(1, 400), now=10)
    assert set(intents) == {'new'}


def test_global_bound_limits_memory():
    intents = {f'u{user}': payload(user, 100) for user in range(INTENTS_GLOBAL)}
    with pytest.raises(AutomationError, match='busy'):
        remember_intent(intents, 'extra', payload(INTENTS_GLOBAL + 1, 100), now=0)
