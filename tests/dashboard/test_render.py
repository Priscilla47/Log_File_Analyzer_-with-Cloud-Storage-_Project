"""What the page does with Streamlit, tested with a fake one that records every call."""

import pytest

from loginsight.dashboard import data
from loginsight.dashboard.render import show_page

GOOD = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /a HTTP/1.1" 200 1500 "-" "x"\n'
ERR = '203.0.113.6 - - [10/Oct/2026:10:00:02 +0000] "GET /b HTTP/1.1" 500 10 "-" "x"\n'


class Upload:
    """Looks like the file Streamlit's uploader returns."""

    def __init__(self, raw: bytes, name: str = "access.log"):
        self.raw, self.name = raw, name

    def getvalue(self) -> bytes:
        return self.raw


class Column:
    def __init__(self, calls):
        self.calls = calls

    def metric(self, label, value, **kwargs):
        self.calls.append(("column.metric", label, value, kwargs.get("help")))


class FakeStreamlit:
    def __init__(self, upload=None):
        self.upload = upload
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

    def columns(self, count):
        self.calls.append(("columns", count))
        return [Column(self.calls) for _ in range(count)]

    def names(self):
        return [call[0] for call in self.calls]

    def of(self, name):
        return [call[1:] for call in self.calls if call[0] == name]


def run(upload):
    fake = FakeStreamlit(upload)
    show_page(fake)
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
        assert all(len(m[2]) > 10 for m in fake.of("column.metric"))

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

    def test_a_hostile_name_is_not_interpreted(self):
        fake = run(Upload(GOOD.encode(), "**bold** [x](http://evil)\x1b.log"))
        assert ("text", "File: **bold** [x](http://evil)\x1b.log") not in fake.calls  # name reduced
        assert all("evil" not in str(call) for call in fake.calls if call[0] != "text")

    def test_nothing_raises_for_any_kind_of_upload(self):
        for raw in (b"", b"\n", bytes(range(256)) * 50, b"\xef\xbb\xbf", GOOD.encode() * 100):
            run(Upload(raw))
