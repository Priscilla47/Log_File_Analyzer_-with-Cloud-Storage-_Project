"""Starting the dashboard: the command that runs it, and whether it can be run at all.

This module never imports Streamlit, so ``loginsight dashboard`` can say what is missing
instead of failing with an import error.
"""

import importlib.util
import ipaddress
import socket
import sys
from pathlib import Path

from loginsight.dashboard.data import UPLOAD_LIMIT_MB

DEFAULT_PORT = 8501
# The dashboard listens on this computer only, unless it is told otherwise (see check_address).
DEFAULT_ADDRESS = "127.0.0.1"
APP_FILE = Path(__file__).with_name("app.py")
MIN_PORT, MAX_PORT = 1, 65535


def streamlit_available() -> bool:
    """Whether Streamlit is installed in this Python."""
    return importlib.util.find_spec("streamlit") is not None


def check_address(address: str) -> str:
    """``address`` if it is an IP address the dashboard can listen on, otherwise
    :class:`ValueError`. A name is refused: listening is by address, and anything that is not
    an address has no business reaching the command that starts the server."""
    try:
        ipaddress.ip_address(address)
    except ValueError:
        raise ValueError(f"address {address!r} is not an IPv4 or IPv6 address") from None
    return address


def is_loopback(address: str) -> bool:
    """Whether ``address`` can only be reached from this computer."""
    return ipaddress.ip_address(check_address(address)).is_loopback


def dashboard_url(port: int) -> str:
    """The address the dashboard is served at on ``port`` (:class:`ValueError` for a bad port)."""
    _check_port(port)
    return f"http://127.0.0.1:{port}"


def port_is_free(port: int, address: str = DEFAULT_ADDRESS) -> bool:
    """Whether nothing is listening on ``port`` of ``address``, so the dashboard can use it.

    Streamlit would only say so itself after the command had printed the address, and then
    exit with a status that means something else. Raises :class:`ValueError` for a bad port.
    """
    _check_port(port)
    family = (
        socket.AF_INET6
        if ipaddress.ip_address(check_address(address)).version == 6
        else socket.AF_INET
    )
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # as the server does
        try:
            probe.bind((address, port))
        except OSError:
            return False
    return True


def _check_port(port: int) -> None:
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"port must be between {MIN_PORT} and {MAX_PORT}, not {port}")


def streamlit_command(port: int, address: str = DEFAULT_ADDRESS) -> list[str]:
    """The command that serves the dashboard on ``port``.

    It runs Streamlit with the Python that runs LogInsight, listens on this computer only unless
    ``address`` says otherwise (a log can hold other people's addresses, so it is never offered
    to the network by default; a container needs ``0.0.0.0``, see ``docs/USAGE.md``), does not
    send Streamlit's usage statistics, and runs headless: without that Streamlit asks for an
    e-mail address on its first start and serves nothing until it is answered. Headless also
    means no browser is opened, so the caller shows the address. Uploads are limited to
    ``UPLOAD_LIMIT_MB`` by Streamlit itself, so a bigger file is refused before it arrives.
    Raises :class:`ValueError` for a port outside 1 to 65535 or an ``address`` that is not an IP
    address.
    """
    _check_port(port)
    check_address(address)
    return [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(APP_FILE),
        "--server.port",
        str(port),
        "--server.address",
        address,
        "--server.headless",
        "true",
        "--server.maxUploadSize",
        str(UPLOAD_LIMIT_MB),
        "--browser.gatherUsageStats",
        "false",
    ]
