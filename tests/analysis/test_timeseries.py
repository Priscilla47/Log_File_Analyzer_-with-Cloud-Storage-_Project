"""Tests for time bucketing and the busiest window. Expected values are worked out by hand."""

import importlib.util
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.analysis.timeseries import (
    MAX_BUCKETS,
    TimeBucket,
    Window,
    busiest_window,
    requests_per_bucket,
)
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_line

UTC = timezone.utc
T0 = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate_logs.py"


def make(when, status=200):
    return LogEntry(
        ip="192.0.2.1",
        time=when,
        method="GET",
        path="/",
        query="",
        protocol="HTTP/1.1",
        status=status,
        size=0,
        request="GET / HTTP/1.1",
    )


def at(minutes=0, seconds=0, hours=0, days=0):
    return T0 + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


def counts(buckets):
    return [(b.start, b.requests) for b in buckets]


# --- buckets: basics ------------------------------------------------------------------


def test_three_requests_in_one_minute_and_one_in_the_next_give_two_buckets():
    entries = [make(at(0, 10)), make(at(0, 20)), make(at(0, 59)), make(at(1, 0))]
    assert counts(requests_per_bucket(entries, "minute")) == [(at(0), 3), (at(1), 1)]


def test_the_default_bucket_is_an_hour():
    entries = [make(at(0)), make(at(59)), make(at(60))]
    assert counts(requests_per_bucket(entries)) == [(at(0), 2), (at(60), 1)]


def test_a_gap_of_two_empty_hours_appears_as_two_zero_buckets():
    entries = [make(at(30)), make(at(hours=3, minutes=15))]
    buckets = requests_per_bucket(entries, "hour")
    assert counts(buckets) == [
        (at(0), 1),
        (at(hours=1), 0),
        (at(hours=2), 0),
        (at(hours=3), 1),
    ]


def test_a_gap_is_zero_filled_for_minute_buckets_too():
    buckets = requests_per_bucket([make(at(0)), make(at(3))], "minute")
    assert counts(buckets) == [(at(0), 1), (at(1), 0), (at(2), 0), (at(3), 1)]


def test_a_single_entry_gives_a_single_bucket():
    assert counts(requests_per_bucket([make(at(0, 30))], "hour")) == [(at(0), 1)]


def test_empty_input_gives_no_buckets():
    assert requests_per_bucket([], "minute") == []
    assert requests_per_bucket([], "hour") == []


def test_every_bucket_starts_on_a_boundary_in_utc():
    buckets = requests_per_bucket([make(at(7, 33)), make(at(hours=2, minutes=5))], "hour")
    for bucket in buckets:
        assert (bucket.start.minute, bucket.start.second, bucket.start.microsecond) == (0, 0, 0)
        assert bucket.start.utcoffset() == timedelta(0)


def test_microseconds_are_dropped_when_bucketing():
    entry = make(T0.replace(second=59, microsecond=999_999))
    assert counts(requests_per_bucket([entry], "minute")) == [(at(0), 1)]


# --- bucket boundaries ----------------------------------------------------------------


def test_the_last_second_of_an_hour_and_the_first_of_the_next_are_in_different_buckets():
    entries = [
        make(datetime(2025, 6, 1, 10, 59, 59, tzinfo=UTC)),
        make(datetime(2025, 6, 1, 11, 0, 0, tzinfo=UTC)),
    ]
    buckets = requests_per_bucket(entries, "hour")
    assert [(b.start.hour, b.requests) for b in buckets] == [(10, 1), (11, 1)]


def test_the_last_second_of_a_minute_and_the_first_of_the_next_are_in_different_buckets():
    entries = [make(at(4, 59)), make(at(5, 0))]
    assert counts(requests_per_bucket(entries, "minute")) == [(at(4), 1), (at(5), 1)]


def test_buckets_cross_midnight_and_month_ends():
    entries = [
        make(datetime(2025, 1, 31, 23, 30, tzinfo=UTC)),
        make(datetime(2025, 2, 1, 0, 30, tzinfo=UTC)),
    ]
    buckets = requests_per_bucket(entries, "hour")
    assert [b.start for b in buckets] == [
        datetime(2025, 1, 31, 23, tzinfo=UTC),
        datetime(2025, 2, 1, 0, tzinfo=UTC),
    ]


# --- time zones -----------------------------------------------------------------------


def test_different_offsets_that_are_the_same_utc_hour_share_a_bucket():
    # 10:30 at -07:00 is 17:30 UTC, 17:45 UTC is itself, 23:15 at +05:30 is 17:45 UTC.
    entries = [
        make(datetime(2025, 6, 1, 10, 30, tzinfo=timezone(timedelta(hours=-7)))),
        make(datetime(2025, 6, 1, 17, 45, tzinfo=UTC)),
        make(datetime(2025, 6, 1, 23, 15, tzinfo=timezone(timedelta(hours=5, minutes=30)))),
    ]
    buckets = requests_per_bucket(entries, "hour")
    assert counts(buckets) == [(datetime(2025, 6, 1, 17, tzinfo=UTC), 3)]


def test_the_same_local_clock_time_at_different_offsets_lands_in_different_hours():
    entries = [
        make(datetime(2025, 6, 1, 10, 0, tzinfo=timezone(timedelta(hours=-7)))),  # 17:00 UTC
        make(datetime(2025, 6, 1, 10, 0, tzinfo=timezone(timedelta(hours=2)))),  # 08:00 UTC
    ]
    starts = [b.start.hour for b in requests_per_bucket(entries, "hour") if b.requests]
    assert starts == [8, 17]


def test_a_naive_timestamp_is_taken_to_be_utc():
    naive = datetime(2025, 6, 1, 12, 30)
    assert counts(requests_per_bucket([make(naive)], "hour")) == [(at(0), 1)]


def test_a_daylight_saving_change_is_handled_by_real_instants_not_clock_times():
    zoneinfo = pytest.importorskip("zoneinfo")
    try:
        zone = zoneinfo.ZoneInfo("America/Los_Angeles")
    except zoneinfo.ZoneInfoNotFoundError:
        pytest.skip("no time zone database on this machine")
    # 1:30 happens twice on 2 Nov 2025 in Los Angeles: first at -07:00, then at -08:00.
    first = datetime(2025, 11, 2, 1, 30, tzinfo=zone, fold=0)  # 08:30 UTC
    second = datetime(2025, 11, 2, 1, 30, tzinfo=zone, fold=1)  # 09:30 UTC
    buckets = requests_per_bucket([make(first), make(second)], "hour")
    assert counts(buckets) == [
        (datetime(2025, 11, 2, 8, tzinfo=UTC), 1),
        (datetime(2025, 11, 2, 9, tzinfo=UTC), 1),
    ]


# --- errors ---------------------------------------------------------------------------


def test_errors_are_status_400_to_599():
    statuses = [200, 301, 399, 400, 404, 499, 500, 503, 599]
    entries = [make(at(0, i), status) for i, status in enumerate(statuses)]
    (bucket,) = requests_per_bucket(entries, "hour")
    assert bucket.requests == 9
    assert bucket.errors == 6  # 400, 404, 499, 500, 503 and 599


@pytest.mark.parametrize("status", [0, 99, 600, 700, 999])
def test_statuses_outside_100_to_599_are_not_errors(status):
    # Same rule as summarize(): such numbers are neither a success nor an error.
    (bucket,) = requests_per_bucket([make(at(0), status)], "hour")
    assert (bucket.requests, bucket.errors) == (1, 0)


@pytest.mark.parametrize(("status", "is_error"), [(399, 0), (400, 1), (599, 1), (600, 0)])
def test_the_error_range_boundaries(status, is_error):
    (bucket,) = requests_per_bucket([make(at(0), status)], "hour")
    assert bucket.errors == is_error


def test_the_error_count_agrees_with_summarize_for_every_possible_status():
    # Both modules must call the same responses errors. Skipped until summarize() is merged.
    summary = pytest.importorskip("loginsight.analysis.summary")
    for status in range(0, 1000):
        entries = [make(at(0), status)]
        (bucket,) = requests_per_bucket(entries, "hour")
        assert bucket.errors == round(summary.summarize(entries).error_rate), status


def test_error_rate_per_bucket():
    entries = [make(at(0), 200), make(at(0, 5), 500), make(at(1), 404), make(at(1, 5), 404)]
    first, second = requests_per_bucket(entries, "minute")
    assert first.error_rate == pytest.approx(0.5)
    assert second.error_rate == 1.0


def test_an_empty_bucket_has_an_error_rate_of_zero():
    gap = requests_per_bucket([make(at(0)), make(at(2))], "minute")[1]
    assert (gap.requests, gap.errors, gap.error_rate) == (0, 0, 0.0)


def test_a_bucket_with_no_errors_has_an_error_rate_of_zero():
    (bucket,) = requests_per_bucket([make(at(0), 200), make(at(0, 1), 304)], "hour")
    assert bucket.error_rate == 0.0


# --- validation and limits ------------------------------------------------------------


@pytest.mark.parametrize("bucket", ["day", "second", "", "Hour", "minutes", None, 60])
def test_an_unknown_bucket_size_is_rejected(bucket):
    with pytest.raises(ValueError):
        requests_per_bucket([make(at(0))], bucket)


def test_an_unknown_bucket_size_is_rejected_even_for_empty_input():
    with pytest.raises(ValueError):
        requests_per_bucket([], "day")


def test_exactly_the_maximum_number_of_buckets_is_allowed():
    assert MAX_BUCKETS == 100_000
    entries = [make(at(0)), make(at(minutes=MAX_BUCKETS - 1))]
    buckets = requests_per_bucket(entries, "minute")
    assert len(buckets) == MAX_BUCKETS
    assert sum(b.requests for b in buckets) == 2


def test_one_bucket_more_than_the_maximum_is_rejected():
    entries = [make(at(0)), make(at(minutes=MAX_BUCKETS))]
    with pytest.raises(ValueError, match="time range too large"):
        requests_per_bucket(entries, "minute")


def test_a_stray_1970_timestamp_cannot_exhaust_memory():
    entries = [make(at(0)), make(datetime(1970, 1, 1, tzinfo=UTC))]
    with pytest.raises(ValueError, match="time range too large"):
        requests_per_bucket(entries, "minute")


def test_the_same_span_is_fine_with_hour_buckets():
    entries = [make(at(0)), make(at(days=365))]
    buckets = requests_per_bucket(entries, "hour")
    assert len(buckets) == 365 * 24 + 1


# --- timestamps that cannot be converted ----------------------------------------------

# Converting the very first or last instant that datetime can hold to UTC overflows when the
# offset points outwards. The parser accepts such a line, so the aggregation has to refuse it
# with a clear ValueError instead of a raw OverflowError.
FIRST_INSTANT = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5)))
LAST_INSTANT = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone(timedelta(hours=-5)))


@pytest.mark.parametrize("when", [FIRST_INSTANT, LAST_INSTANT], ids=["year 1", "year 9999"])
def test_a_timestamp_that_cannot_be_converted_to_utc_is_a_value_error(when):
    with pytest.raises(ValueError, match="out of range"):
        requests_per_bucket([make(at(0)), make(when)], "hour")


@pytest.mark.parametrize("when", [FIRST_INSTANT, LAST_INSTANT], ids=["year 1", "year 9999"])
def test_the_busiest_window_also_refuses_them(when):
    with pytest.raises(ValueError, match="out of range"):
        busiest_window([make(at(0)), make(when)])


def test_the_extremes_that_can_be_converted_are_still_refused_by_the_range_limit():
    entries = [make(at(0)), make(datetime(9999, 12, 31, 23, tzinfo=UTC))]
    with pytest.raises(ValueError, match="time range too large"):
        requests_per_bucket(entries, "hour")


# --- ordering, input handling ---------------------------------------------------------


def test_shuffled_input_gives_the_same_result_as_sorted_input():
    rng = random.Random(3)
    entries = [
        make(at(rng.randint(0, 600), rng.randint(0, 59)), rng.choice([200, 404]))
        for _ in range(300)
    ]
    shuffled = list(entries)
    rng.shuffle(shuffled)
    for size in ("minute", "hour"):
        assert requests_per_bucket(shuffled, size) == requests_per_bucket(
            sorted(entries, key=lambda e: e.time), size
        )


def test_buckets_are_sorted_by_time():
    entries = [make(at(hours=5)), make(at(0)), make(at(hours=2))]
    starts = [b.start for b in requests_per_bucket(entries, "hour")]
    assert starts == sorted(starts)


@pytest.mark.parametrize("source", [list, tuple, iter])
def test_any_iterable_is_accepted(source):
    entries = [make(at(0)), make(at(5))]
    assert requests_per_bucket(source(entries), "minute") == requests_per_bucket(entries, "minute")


def test_the_input_is_not_modified():
    entries = [make(at(5)), make(at(0))]
    before = [e.time for e in entries]
    requests_per_bucket(entries, "minute")
    assert [e.time for e in entries] == before


def test_a_time_bucket_is_immutable():
    bucket = TimeBucket(start=T0, requests=1, errors=0)
    with pytest.raises(AttributeError):
        bucket.requests = 5  # type: ignore[misc]


# --- generated logs -------------------------------------------------------------------


@pytest.fixture(scope="module")
def generated():
    spec = importlib.util.spec_from_file_location("generate_logs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    lines, _ = module.generate(seed=42, lines=2000, attack_ratio=0.1)
    return [parse_line(line) for line in lines]


@pytest.mark.parametrize("size", ["minute", "hour"])
def test_bucket_totals_add_up_on_a_generated_log(generated, size):
    buckets = requests_per_bucket(generated, size)
    assert sum(b.requests for b in buckets) == 2000
    assert sum(b.errors for b in buckets) == sum(e.status >= 400 for e in generated)
    assert all(b.errors <= b.requests for b in buckets)


def test_a_generated_log_has_no_gaps_between_its_minute_buckets(generated):
    buckets = requests_per_bucket(generated, "minute")
    steps = {(b.start - a.start) for a, b in zip(buckets, buckets[1:], strict=False)}
    assert steps == {timedelta(minutes=1)}


# --- busiest window -------------------------------------------------------------------


def test_the_busiest_window_is_found():
    quiet = [make(at(0)), make(at(1)), make(at(2))]  # 3 inside five minutes
    busy = [make(at(30, s)) for s in (0, 10, 20, 30, 40)]  # 5 inside half a minute
    window = busiest_window(quiet + busy, minutes=5)
    assert window == Window(start=at(30), end=at(35), requests=5)


def test_a_tie_goes_to_the_earliest_window():
    first = [make(at(0)), make(at(1))]
    second = [make(at(60)), make(at(61))]
    window = busiest_window(second + first, minutes=5)
    assert (window.start, window.requests) == (at(0), 2)


def test_a_window_is_half_open_so_a_request_exactly_one_window_later_is_outside():
    entries = [make(at(0)), make(at(5))]
    assert busiest_window(entries, minutes=5).requests == 1
    assert busiest_window(entries, minutes=6).requests == 2


def test_the_default_window_is_five_minutes():
    entries = [make(at(0)), make(at(4, 59)), make(at(5))]
    window = busiest_window(entries)
    assert (window.requests, window.end - window.start) == (2, timedelta(minutes=5))


def test_requests_with_the_same_timestamp_all_count():
    window = busiest_window([make(at(0)) for _ in range(4)] + [make(at(10))], minutes=1)
    assert (window.start, window.requests) == (at(0), 4)


def test_one_entry_gives_a_window_with_one_request():
    window = busiest_window([make(at(3))], minutes=2)
    assert window == Window(start=at(3), end=at(5), requests=1)


def test_no_entries_gives_none():
    assert busiest_window([]) is None


@pytest.mark.parametrize("minutes", [0, -1, -5, 0.5])
def test_a_window_shorter_than_a_minute_is_rejected(minutes):
    with pytest.raises(ValueError):
        busiest_window([make(at(0))], minutes=minutes)


@pytest.mark.parametrize("minutes", [float("nan"), float("inf"), 10**12, 1e300])
def test_a_window_length_that_is_not_a_sensible_number_is_a_value_error(minutes):
    with pytest.raises(ValueError):
        busiest_window([make(at(0))], minutes=minutes)


def test_a_nan_window_length_gets_the_clear_message():
    with pytest.raises(ValueError, match="at least 1"):
        busiest_window([make(at(0))], minutes=float("nan"))


def test_a_request_in_the_last_moments_of_year_9999_is_a_value_error_not_an_overflow():
    last = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)
    with pytest.raises(ValueError, match="last date"):
        busiest_window([make(last)], minutes=5)


def test_the_window_length_is_checked_even_for_empty_input():
    with pytest.raises(ValueError):
        busiest_window([], minutes=0)


def test_the_busiest_window_ignores_the_input_order_and_time_zones():
    seven_behind = timezone(timedelta(hours=-7))
    entries = [
        make(datetime(2025, 6, 1, 5, 2, tzinfo=seven_behind)),  # 12:02 UTC
        make(datetime(2025, 6, 1, 12, 0, tzinfo=UTC)),
        make(datetime(2025, 6, 1, 14, 1, tzinfo=timezone(timedelta(hours=2)))),  # 12:01 UTC
        make(at(hours=3)),
    ]
    window = busiest_window(entries, minutes=5)
    assert (window.start, window.requests) == (at(0), 3)
    assert window.start.utcoffset() == timedelta(0)


def test_the_busiest_window_matches_a_brute_force_search_on_a_generated_log(generated):
    subset = generated[:500]
    window = busiest_window(subset, minutes=5)
    length = timedelta(minutes=5)
    best = max(sum(a.time <= e.time < a.time + length for e in subset) for a in subset)
    earliest = min(
        a.time for a in subset if sum(a.time <= e.time < a.time + length for e in subset) == best
    )
    assert window.requests == best
    assert window.start == earliest
    assert sum(window.start <= e.time < window.end for e in subset) == best


@pytest.mark.parametrize("seed", range(6))
def test_the_busiest_window_matches_brute_force_on_random_data(seed):
    rng = random.Random(seed)
    entries = [
        make(T0 + timedelta(seconds=rng.randint(0, 1800))) for _ in range(rng.randint(1, 80))
    ]
    minutes = rng.choice([1, 2, 5, 10])
    window = busiest_window(entries, minutes=minutes)
    length = timedelta(minutes=minutes)
    counts_ = {a.time: sum(a.time <= e.time < a.time + length for e in entries) for a in entries}
    best = max(counts_.values())
    assert window.requests == best
    assert window.start == min(start for start, n in counts_.items() if n == best)


def test_the_busiest_window_is_fast_on_100_000_entries():
    import time

    rng = random.Random(1)
    entries = [make(T0 + timedelta(seconds=rng.randint(0, 86_400))) for _ in range(100_000)]
    started = time.perf_counter()
    window = busiest_window(entries, minutes=5)
    elapsed = time.perf_counter() - started
    assert window.requests > 0
    assert elapsed < 2.0


def test_the_input_is_not_modified_by_busiest_window():
    entries = [make(at(5)), make(at(0))]
    busiest_window(entries)
    assert [e.time for e in entries] == [at(5), at(0)]
