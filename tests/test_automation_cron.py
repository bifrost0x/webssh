from datetime import datetime, timezone

import pytest

from app.automation_store import AutomationError


def test_cron_ranges_steps_and_sunday_alias():
    from app.automation_cron import next_due
    now = datetime(2026, 11, 3, 12, 7, tzinfo=timezone.utc)
    assert next_due('*/15 12-14 * * 1-5', 'UTC', now).isoformat() == '2026-11-03T12:15:00+00:00'
    assert next_due('0 0 * * 7', 'UTC', now).weekday() == 6


@pytest.mark.parametrize('value', ['* * * *', '60 * * * *', '*/0 * * * *', '* * * * * *', '@reboot', '0 2 31 2 *', '0 0 * * 9'])
def test_invalid_cron_is_rejected(value):
    from app.automation_cron import next_due
    with pytest.raises(AutomationError):
        next_due(value, 'UTC', datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_nonexistent_dst_time_skipped_and_repeated_time_fires_once():
    from app.automation_cron import next_due
    spring = datetime(2026, 3, 28, 3, tzinfo=timezone.utc)
    assert next_due('30 2 * * *', 'Europe/Berlin', spring).isoformat() == '2026-03-30T00:30:00+00:00'
    first_fall_occurrence = datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
    assert next_due('30 2 * * *', 'Europe/Berlin', first_fall_occurrence).isoformat() == '2026-10-26T01:30:00+00:00'


def test_day_of_month_and_weekday_use_cron_or_semantics():
    from app.automation_cron import next_due
    assert next_due('0 9 15 * 1', 'UTC', datetime(2026, 11, 3, tzinfo=timezone.utc)).day == 9


def test_zone_and_aware_clock_required():
    from app.automation_cron import next_due
    with pytest.raises(AutomationError):
        next_due('* * * * *', 'not/a-zone', datetime.now(timezone.utc))
    with pytest.raises(AutomationError):
        next_due('* * * * *', 'UTC', datetime(2026, 1, 1))
