import matplotlib

matplotlib.use("Agg")  # headless backend: tests must run without a display

import matplotlib.pyplot as plt  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_charts(tmp_path, monkeypatch):
    """Run each test in an empty temp folder and close every figure afterwards.

    The chart functions write fixed file names into the current working directory, so
    changing directory keeps stray PNG files out of the repository.
    """
    monkeypatch.chdir(tmp_path)
    yield tmp_path
    plt.close("all")
