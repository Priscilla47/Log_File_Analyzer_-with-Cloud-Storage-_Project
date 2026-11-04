"""Start the real dashboard in a new process, as a user would, and check that it serves.

It takes a few seconds, so it is in the ``e2e`` group (``pytest -m e2e``). Skipped without
Streamlit. It uses a temporary home folder so Streamlit's first-run behaviour is the real one
and nothing is written to the developer's own configuration.
"""

import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

pytest.importorskip("streamlit")

pytestmark = pytest.mark.e2e


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def dashboard(tmp_path):
    port = free_port()
    environment = {**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
    process = subprocess.Popen(
        [sys.executable, "-m", "loginsight", "dashboard", "--port", str(port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
        start_new_session=True,  # its own process group, so Ctrl+C can be sent to all of it
    )
    yield process, port, tmp_path
    if process.poll() is None:  # a test that failed half way: stop everything it started
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()


def get(port, path):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            return urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3)
        except OSError:
            time.sleep(0.5)
    raise AssertionError(f"the dashboard did not answer on port {port}")


def test_it_starts_without_asking_anything_serves_a_page_and_stops_on_ctrl_c(dashboard):
    process, port, home = dashboard
    assert get(port, "/_stcore/health").read() == b"ok"
    assert get(port, "/").status == 200

    os.killpg(process.pid, signal.SIGINT)  # what Ctrl+C does: the whole group gets it
    output, _ = process.communicate(timeout=30)
    assert process.returncode == 0
    assert f"open http://127.0.0.1:{port} in your browser" in output
    assert "Email" not in output and "Traceback" not in output
    assert not (home / ".streamlit").exists()  # no first-run questions answered or saved


def test_being_terminated_does_not_leave_the_server_running(dashboard):
    process, port, _ = dashboard
    get(port, "/_stcore/health")
    process.send_signal(signal.SIGTERM)  # only the loginsight process is told, not Streamlit
    process.communicate(timeout=30)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(1)
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return
        time.sleep(0.3)
    raise AssertionError("the Streamlit server is still listening after the command ended")


def own_network_address():
    """This computer's address on the network, found without any name lookup, or ``None``."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("192.0.2.1", 9))  # a documentation address: nothing is sent
            address = sock.getsockname()[0]
        except OSError:
            return None
    return None if address.startswith("127.") else address


def test_it_is_not_reachable_from_another_address(dashboard):
    address = own_network_address()
    if address is None:
        pytest.skip("this computer has no address other than 127.0.0.1 to try")
    process, port, _ = dashboard
    get(port, "/_stcore/health")  # it is up, on the loopback address
    with socket.socket() as sock:
        sock.settimeout(3)
        assert sock.connect_ex((address, port)) != 0, f"listening on {address}"
