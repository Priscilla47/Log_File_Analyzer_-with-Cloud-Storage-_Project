import matplotlib

matplotlib.use("Agg")  # headless backend: tests must run without a display

import matplotlib.pyplot as plt  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_charts(tmp_path, monkeypatch):
    """Run each test in an empty temp folder and close any pyplot figure afterwards.

    The chart functions only write where they are told to, so running in a temp folder lets
    the tests prove nothing leaks into the current folder. The charts never use pyplot, so
    ``plt`` is only used here to check that no figure was opened behind their back.
    """
    monkeypatch.chdir(tmp_path)
    yield tmp_path
    plt.close("all")
