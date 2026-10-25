"""Local days (Europe/Berlin) as UTC intervals: a day is 23, 24 or 25 hours long."""

import datetime
from zoneinfo import ZoneInfo

UTC = datetime.timezone.utc


def bounds(day, tz):
    """(start, end) of a local date as Unix seconds: [local midnight, next local midnight)."""
    zone = ZoneInfo(tz) if isinstance(tz, str) else tz
    start = datetime.datetime.combine(day, datetime.time(0), tzinfo=zone)
    end = datetime.datetime.combine(day + datetime.timedelta(days=1), datetime.time(0), tzinfo=zone)
    return int(start.astimezone(UTC).timestamp()), int(end.astimezone(UTC).timestamp())


def local_day(unix, tz):
    """The local date of a Unix time."""
    zone = ZoneInfo(tz) if isinstance(tz, str) else tz
    return datetime.datetime.fromtimestamp(unix, UTC).astimezone(zone).date()
