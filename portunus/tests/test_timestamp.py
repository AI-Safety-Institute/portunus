"""Audit timestamps use UTC and truncate to milliseconds across date boundaries."""

import pytest
from freezegun import freeze_time

from portunus.util import generate_iso_timestamp


@pytest.mark.parametrize(
    "instant, expected",
    [
        ("2024-02-29 23:59:59.999999+00:00", "2024-02-29T23:59:59.999Z"),
        ("2025-01-01 00:00:00+00:00", "2025-01-01T00:00:00.000Z"),
        ("2025-01-01 01:00:00.000999+01:00", "2025-01-01T00:00:00.000Z"),
        ("2025-09-22 12:34:56.123999+00:00", "2025-09-22T12:34:56.123Z"),
    ],
)
def test_timestamp_uses_utc_milliseconds_without_rounding(instant, expected):
    with freeze_time(instant):
        assert generate_iso_timestamp() == expected
