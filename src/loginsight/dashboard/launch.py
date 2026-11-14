"""Starting the dashboard: the command that runs it, and whether it can be run at all.

This module never imports Streamlit, so ``loginsight dashboard`` can say what is missing
instead of failing with an import error.
"""

import importlib.util
import socket
import sys
from pathlib import Path

DEFAULT_PORT = 8501
APP_FILE = Path(__file__).with_name("app.py")
MIN_PORT, MAX_PORT = 1, 65535


def streamlit_available() -> bool:
    """Whether Streamlit is installed in this Python."""
    return importlib.util.find_spec("streamlit") is not None


def dashboard_url(port: int) -> str:
    """The address the dashboard is served at on ``port`` (:class:`ValueError` for a bad port)."""
    _check_port(port)
    return f"http://127.0.0.1:{port}"


def port_is_free(port: int) -> bool:
    """Whether nothing is listening on ``port`` of this computer, so the dashboard can use it.

    Streamlit would only say so itself after the command had printed the address, and then
    exit with a status that means something else. Raises :class:`ValueError` for a bad port.
    """
    _check_port(port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # as the server does
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _check_port(port: int) -> None:
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"port must be between {MIN_PORT} and {MAX_PORT}, not {port}")


def streamlit_command(port: int) -> list[str]:
    """The command that serves the dashboard on ``port``.

    It runs Streamlit with the Python that runs LogInsight, listens on this computer only (a
    log can hold other people's addresses, so it is never offered to the network), does not
    send Streamlit's usage statistics, and runs headless: without that Streamlit asks for an
    e-mail address on its first start and serves nothing until it is answered. Headless also
    means no browser is opened, so the caller shows the address. Raises :class:`ValueError`
    for a port outside 1 to 65535.
    """
    _check_port(port)
    return [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(APP_FILE),
        "--server.port",
        str(port),
        "--server.address",
        "127.0.0.1",
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
    ]
