"""What the page does with Streamlit, tested with a fake one that records every call."""

import inspect

import pytest

from loginsight.dashboard import data
from loginsight.dashboard.render import show_page

GOOD = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /a HTTP/1.1" 200 1500 "-" "x"\n'
ERR = '203.0.113.6 - - [10/Oct/2026:10:00:02 +0000] "GET /b HTTP/1.1" 500 10 "-" "x"\n'


class Upload:
    """Looks like the file Streamlit's uploader returns."""

    def __init__(self, raw: bytes, name: str = "access.log"):
        self.raw, self.name = raw, name
        self.file_id = "a1b2c3"  # Streamlit gives each chosen file an id of its own

    def getvalue(self) -> bytes:
        return self.raw


class Column:
    """A column of the page: ``metric`` is recorded as its own call, the rest like the page's."""

    def __init__(self, fake):
        self.fake = fake
        self.calls = fake.calls

    def metric(self, label, value, **kwargs):
        self.calls.append(("column.metric", label, value, kwargs.get("help")))

    def __getattr__(self, name):
        return getattr(self.fake, name)


class FakeStreamlit:
    def __init__(self, upload=None, bucket="hour", **choices):
        self.upload = upload
        self.bucket = bucket
        self.choices = choices  # what the person picked: Severity, Class, filter_ip, address, time
        self.calls = []

    def _record(self, name, *args, **kwargs):
        self.calls.append((name, *args))

    def set_page_config(self, **kwargs):
        self.calls.append(("set_page_config", kwargs["page_title"], kwargs["layout"]))

    def title(self, text):
        self.calls.append(("title", text))

    def file_uploader(self, label, **kwargs):
        self.calls.append(("file_uploader", label, kwargs.get("key"), kwargs.get("help")))
        return self.upload

    def info(self, text):
        self.calls.append(("info", text))

    def warning(self, text):
        self.calls.append(("warning", text))

    def error(self, text):
        self.calls.append(("error", text))

    def text(self, text):
        self.calls.append(("text", text))

    def radio(self, label, options, **kwargs):
        self.calls.append(("radio", label, tuple(options), kwargs.get("index"), kwargs.get("key")))
        return self.bucket

    def subheader(self, text):
        self.calls.append(("subheader", text))

    def caption(self, text):
        self.calls.append(("caption", text))

    def bar_chart(self, table, **kwargs):
        self.calls.append(("bar_chart", table, kwargs))

    def line_chart(self, table, **kwargs):
        self.calls.append(("line_chart", table, kwargs))

    def columns(self, count):
        self.calls.append(("columns", count))
        return [Column(self) for _ in range(count)]

    def success(self, text):
        self.calls.append(("success", text))

    def multiselect(self, label, options, **kwargs):
        options = list(options)
        shown = tuple(kwargs["format_func"](option) for option in options)
        self.calls.append(("multiselect", label, shown, kwargs["key"]))
        return self.choices.get(label, [])

    def selectbox(self, label, options, **kwargs):
        options = list(options)
        shown = tuple(kwargs["format_func"](o) for o in options) if "format_func" in kwargs else ()
        self.calls.append(("selectbox", label, tuple(options), shown, kwargs["key"]))
        return self.choices.get(kwargs["key"].split(":")[0])  # "filter_ip" or "address"

    def slider(self, label, **kwargs):
        self.calls.append(
            ("slider", label, kwargs["min_value"], kwargs["max_value"], kwargs["step"])
        )
        return self.choices.get("time", kwargs["value"])

    def dataframe(self, table, **kwargs):
        self.calls.append(("dataframe", table))

    def names(self):
        return [call[0] for call in self.calls]

    def of(self, name):
        return [call[1:] for call in self.calls if call[0] == name]


try:
    import streamlit as real_streamlit
except ImportError:  # the tests that need the real thing are skipped, the others still run
    real_streamlit = None


class Checked:
    """Hands every call to ``target`` after checking it fits the call of the same name in the
    real Streamlit: the fake accepts any argument, so without this a page could pass a keyword
    that the installed Streamlit does not have and every test would still be green."""

    def __init__(self, target, real):
        self.target, self.real = target, real

    def __getattr__(self, name):
        method = getattr(self.target, name)
        if not callable(method):
            return method
        signature = inspect.signature(getattr(self.real, name))  # no such call: AttributeError

        def call(*args, **kwargs):
            signature.bind(*args, **kwargs)  # TypeError for an argument Streamlit does not take
            result = method(*args, **kwargs)
            if name == "columns":  # the columns take the same calls as the page
                return [Checked(column, self.real) for column in result]
            return result

        return call


def run(upload, bucket="hour", **choices):
    fake = FakeStreamlit(upload, bucket, **choices)
    show_page(fake if real_streamlit is None else Checked(fake, real_streamlit))
    return fake


class TestBeforeAFileIsChosen:
    def test_it_sets_up_the_page_then_shows_the_title_and_the_chooser(self):
        fake = run(None)
        assert fake.names()[:3] == ["set_page_config", "title", "file_uploader"]
        assert fake.of("set_page_config") == [(data.APP_TITLE, "wide")]
        assert fake.of("title") == [(data.APP_TITLE,)]

    def test_the_chooser_names_the_limit(self):
        ((label, key, help_text),) = run(None).of("file_uploader")
        assert (label, key) == ("Access log", "log_file")
        assert f"{data.UPLOAD_LIMIT_MB} MB" in help_text

    def test_it_invites_the_user_to_choose_a_file_and_shows_nothing_else(self):
        fake = run(None)
        assert fake.of("info") == [(data.EMPTY_MESSAGE,)]
        assert not {"column.metric", "error", "warning", "text", "columns"} & set(fake.names())


class TestWithAGoodLog:
    @pytest.fixture
    def fake(self):
        return run(Upload((GOOD + ERR).encode(), "dir/access.log"))

    def test_one_card_per_headline_number_in_columns(self, fake):
        assert fake.of("columns") == [(5,)]
        metrics = fake.of("column.metric")
        assert [m[0] for m in metrics] == [
            "Requests", "Unique IPs", "Error rate", "Data sent", "Skipped lines",
        ]  # fmt: skip
        assert [m[1] for m in metrics] == ["2", "2", "50.0%", "1.5 KiB", "0"]

    def test_each_card_carries_its_explanation(self, fake):
        assert [m[2] for m in fake.of("column.metric")] == [
            "Lines of the log that were read as a request.",
            "Different client addresses that sent a request.",
            "Share of requests answered with an error (4xx and 5xx).",
            "Total size of the responses, as the server logged it.",
            "Lines that could not be read, out of 2 lines in the file.",
        ]

    def test_the_facts_are_shown_as_plain_text_not_markdown(self, fake):
        assert [t[0] for t in fake.of("text")] == [
            "File: access.log",
            "Format: apache",
            "Lines: 2 read, 2 parsed, 0 skipped (100.0% parsed)",
        ]

    def test_no_error_warning_or_invitation(self, fake):
        assert not {"error", "warning", "info"} & set(fake.names())

    def test_the_chooser_comes_before_the_numbers(self, fake):
        assert fake.names().index("file_uploader") < fake.names().index("columns")


class TestProblems:
    def test_a_warning_is_shown_above_the_numbers(self):
        fake = run(Upload((GOOD * 8 + "junk\n" * 2).encode()))
        assert fake.of("warning") == [("2 of 10 lines (20%) could not be read",)]
        assert fake.names().index("warning") < fake.names().index("columns")
        assert fake.of("column.metric")  # the numbers are still shown

    def test_an_unreadable_file_shows_one_error_and_no_numbers(self):
        fake = run(Upload(b"not a log\n" * 3))
        (message,) = [m[0] for m in fake.of("error")]
        assert message.startswith("None of the 3 lines could be read")
        assert not {"column.metric", "columns", "text"} & set(fake.names())

    def test_a_file_over_the_limit_shows_the_message_and_no_numbers(self, monkeypatch):
        monkeypatch.setattr(data, "UPLOAD_LIMIT_BYTES", 10)
        fake = run(Upload(GOOD.encode()))
        (message,) = [m[0] for m in fake.of("error")]
        assert "the dashboard takes files up to" in message
        assert "column.metric" not in fake.names()

    def test_an_empty_file_shows_the_notice_with_zeros(self):
        fake = run(Upload(b""))
        assert fake.of("info") == [("The file has no requests in it.",)]
        assert fake.of("column.metric")[0][:2] == ("Requests", "0")

    def test_a_hostile_name_is_shown_as_escaped_plain_text_and_nowhere_else(self):
        fake = run(Upload(GOOD.encode(), "**bold** [x](evil)\x1b[2J<b>.log"))
        assert ("text", "File: **bold** [x](evil)\\x1b[2J<b>.log") in fake.calls
        assert all("evil" not in str(call) for call in fake.calls if call[0] != "text")
        assert not {"markdown", "write", "html"} & set(fake.names())

    def test_a_newline_in_the_name_cannot_forge_another_line_of_facts(self):
        fake = run(Upload(GOOD.encode(), "a\nFormat: nginx.log"))
        texts = [t[0] for t in fake.of("text")]
        assert texts[0] == "File: a\\x0aFormat: nginx.log"
        assert [t for t in texts if t.startswith("Format:")] == ["Format: apache"]

    def test_nothing_raises_for_any_kind_of_upload(self):
        for raw in (b"", b"\n", bytes(range(256)) * 50, b"\xef\xbb\xbf", GOOD.encode() * 100):
            run(Upload(raw))


class TestCharts:
    @pytest.fixture
    def fake(self):
        return run(Upload((GOOD * 3 + ERR).encode()))

    def test_three_charts_each_after_its_own_title(self, fake):
        names = fake.names()
        positions = [i for i, n in enumerate(names) if n in ("bar_chart", "line_chart")]
        assert [names[i] for i in positions] == ["bar_chart", "line_chart", "bar_chart"]
        assert [names[i - 1] for i in positions] == ["subheader"] * 3  # no chart without a title
        assert [t[0] for t in fake.of("subheader")][:3] == [
            "Responses by status class",
            "Traffic over time",
            "Most requested paths",
        ]

    def test_the_status_chart_draws_the_status_table(self, fake):
        _, table, options = [c for c in fake.calls if c[0] == "bar_chart"][0]
        assert table == {"Status class": ["2xx", "3xx", "4xx", "5xx"], "Requests": [3, 0, 0, 1]}
        assert options["x"] == "Status class" and options["y"] == "Requests"
        assert options["x_label"] == "Status class" and options["y_label"] == "Requests"
        assert options["color"] == data.COLOUR_MAIN

    def test_the_traffic_chart_draws_requests_and_errors_in_two_colours(self, fake):
        _, table, options = [c for c in fake.calls if c[0] == "line_chart"][0]
        assert list(table) == ["Time (UTC)", "Requests", "Errors"]
        assert options["x"] == "Time (UTC)" and options["y"] == ["Requests", "Errors"]
        assert options["color"] == [data.COLOUR_MAIN, data.COLOUR_ERRORS]
        assert options["x_label"] == "Time (UTC)" and options["y_label"] == "Requests"

    def test_the_paths_chart_is_horizontal_busiest_first(self, fake):
        _, table, options = [c for c in fake.calls if c[0] == "bar_chart"][1]
        assert table == {"Path": ["/a", "/b"], "Requests": [3, 1]}
        assert options["horizontal"] is True and options["sort"] == "-Requests"
        assert options["x"] == "Path" and options["y"] == "Requests"
        # the labels name what the axes show: Streamlit turns the chart on its side by itself
        assert options["x_label"] == "Path" and options["y_label"] == "Requests"

    def test_the_chart_data_equals_the_numbers_on_the_cards(self, fake):
        status = [c for c in fake.calls if c[0] == "bar_chart"][0][1]
        cards = {m[0]: m[1] for m in fake.of("column.metric")}
        assert str(sum(status["Requests"])) == cards["Requests"]

    def test_the_bucket_choice_comes_right_after_the_chooser_and_before_the_numbers(self, fake):
        names = fake.names()
        assert names.index("file_uploader") < names.index("radio") < names.index("columns")
        ((label, options, index, key),) = fake.of("radio")
        assert label == "Group the traffic by" and key == "bucket"
        assert options == ("minute", "hour", "day") and options[index] == "hour"

    @pytest.mark.parametrize("bucket", ["minute", "hour", "day"])
    def test_the_chosen_bucket_decides_the_traffic_series(self, bucket):
        rows = {"minute": 61, "hour": 2, "day": 1}
        text = GOOD + GOOD.replace("10:00:01", "11:00:01")
        traffic = [c for c in run(Upload(text.encode()), bucket).calls if c[0] == "line_chart"][0][
            1
        ]
        assert len(traffic["Requests"]) == rows[bucket]

    CHART_CALLS = {"bar_chart", "line_chart", "subheader"}

    def test_no_charts_and_no_bucket_choice_before_a_file_is_chosen(self):
        names = run(None).names()
        assert not (self.CHART_CALLS | {"radio"}) & set(names)

    def test_no_charts_for_a_file_that_cannot_be_read(self):
        assert not self.CHART_CALLS & set(run(Upload(b"junk\n" * 3)).names())

    def test_no_charts_for_an_empty_file_but_the_bucket_choice_is_still_offered(self):
        names = run(Upload(b"")).names()
        assert not self.CHART_CALLS & set(names) and "radio" in names

    def test_a_wide_time_range_adds_the_note_under_the_traffic_chart(self):
        text = GOOD + GOOD.replace("2026", "1970")
        fake = run(Upload(text.encode()), "minute")
        names = fake.names()
        note = ("caption", "Quiet periods are not listed because the log covers too long a time.")
        assert fake.of("caption")[0] == note[1:]
        assert (
            names.index("line_chart")
            < names.index("caption")
            < names.index("subheader", names.index("line_chart"))
        )

    def test_a_normal_range_has_no_note(self, fake):
        assert not any("Quiet periods" in c[0] for c in fake.of("caption"))


@pytest.mark.skipif(real_streamlit is None, reason="Streamlit is not installed")
class TestTheCheckAgainstRealStreamlit:
    def test_a_keyword_streamlit_does_not_have_is_refused(self):
        checked = Checked(FakeStreamlit(), real_streamlit)
        with pytest.raises(TypeError):
            checked.bar_chart({}, no_such_option=1)
        with pytest.raises(TypeError):
            checked.radio()  # a required argument missing

    def test_a_call_streamlit_does_not_have_is_refused(self):
        checked = Checked(FakeStreamlit(), real_streamlit)
        with pytest.raises(AttributeError):
            _ = checked.no_such_call

    def test_a_correct_call_goes_through_to_the_fake(self):
        fake = FakeStreamlit()
        Checked(fake, real_streamlit).bar_chart({"a": [1]}, x="a")
        assert fake.names() == ["bar_chart"]

    def test_the_columns_are_checked_too(self):
        fake = FakeStreamlit()
        (column,) = Checked(fake, real_streamlit).columns(1)
        column.metric("Requests", "1", help="x")
        with pytest.raises(TypeError):
            column.metric("Requests", "1", no_such_option=1)
