"""Bounded five-field cron evaluation in an explicit IANA time zone.

Spring gaps are skipped; autumn folds run only at the first occurrence.
No clock or process state is hidden inside the evaluator.
"""
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .automation_store import AutomationError


def _field(value, low, high):
    result = set()
    for part in value.split(','):
        interval = part.split('/')
        if len(interval) > 2:
            raise ValueError()
        base = interval[0]
        step = int(interval[1]) if len(interval) == 2 else 1
        if step < 1 or step > high - low + 1:
            raise ValueError()
        if base == '*':
            start, stop = low, high
        elif '-' in base:
            start, stop = map(int, base.split('-'))
        else:
            start = int(base)
            stop = high if len(interval) == 2 else start
        if not low <= start <= stop <= high:
            raise ValueError()
        result.update(range(start, stop + 1, step))
    return result


def parse(expression, zone):
    if not isinstance(expression, str) or len(expression) > 128 or not isinstance(zone, str) or len(zone) > 128:
        raise AutomationError('invalid_schedule')
    try:
        fields = expression.split()
        if len(fields) != 5 or any(not all(c in '0123456789*/,-' for c in f) for f in fields):
            raise ValueError()
        minute, hour, day, month, weekday = [
            _field(value, low, high)
            for value, (low, high) in zip(fields, [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)])
        ]
        weekday = {v % 7 for v in weekday}
        return minute, hour, day, month, weekday, fields[2].startswith('*'), fields[4].startswith('*'), ZoneInfo(zone)
    except (ValueError, ZoneInfoNotFoundError) as error:
        raise AutomationError('invalid_schedule') from error


def next_due(expression, zone, after):
    """Next strictly later UTC instant, within five years, without DST duplicates."""
    if not isinstance(after, datetime) or after.tzinfo is None or after.utcoffset() is None:
        raise AutomationError('invalid_schedule')
    minutes, hours, days, months, weekdays, any_day, any_weekday, tz = parse(expression, zone)
    after = after.astimezone(timezone.utc)
    first_day = after.astimezone(tz).date()
    for offset in range(366 * 5 + 1):
        date = first_day + timedelta(days=offset)
        if date.month not in months:
            continue
        day_match, week_match = date.day in days, (date.weekday() + 1) % 7 in weekdays
        if not (day_match and week_match if any_day or any_weekday else day_match or week_match):
            continue
        for hour in sorted(hours):
            for minute in sorted(minutes):
                local = datetime(date.year, date.month, date.day, hour, minute, tzinfo=tz, fold=0)
                utc = local.astimezone(timezone.utc)
                if utc > after and utc.astimezone(tz).replace(tzinfo=None) == local.replace(tzinfo=None):
                    return utc
    raise AutomationError('invalid_schedule')
