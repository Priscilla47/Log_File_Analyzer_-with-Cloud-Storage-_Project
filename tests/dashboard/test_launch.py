"""The dashboard command: what it runs, and what it says when Streamlit is not installed."""

import subprocess
import sys

import pytest

from loginsight import cli
from loginsight.cli import EXIT_OK, EXIT_PROBLEM, EXIT_USAGE, main
from loginsight.dashboard import launch


class TestStreamlitCommand:
    def test_it_runs_streamlit_with_this_python_on_the_app_file(self):
        command = launch.streamlit_command(8600)
        assert command[:4] == [sys.executable, "-m", "streamlit", "run"]
        assert command[4] == str(launch.APP_FILE)
        assert launch.APP_FILE.name == "app.py" and launch.APP_FILE.is_file()

    def test_the_port_is_passed_as_given(self):
        command = launch.streamlit_command(8600)
        assert command[command.index("--server.port") + 1] == "8600"

    def test_it_listens_on_this_computer_only(self):
        # a log can hold addresses and paths of other people: never offer it to the network
        command = launch.streamlit_command(8501)
        assert command[command.index("--server.address") + 1] == "127.0.0.1"

    def test_it_does_not_send_usage_statistics(self):
        command = launch.streamlit_command(8501)
        assert command[command.index("--browser.gatherUsageStats") + 1] == "false"

    def test_it_never_waits_for_a_first_run_question(self):
        # without this Streamlit asks for an e-mail address on the first start and the page
        # does not appear until it is answered
        command = launch.streamlit_command(8501)
        assert command[command.index("--server.headless") + 1] == "true"

    def test_streamlit_itself_enforces_the_same_upload_limit(self):
        # Streamlit's own default is 200 MB: without this the page would accept more than
        # data.UPLOAD_LIMIT_MB and only refuse after the whole file had arrived
        from loginsight.dashboard.data import UPLOAD_LIMIT_MB

        command = launch.streamlit_command(8501)
        assert command[command.index("--server.maxUploadSize") + 1] == str(UPLOAD_LIMIT_MB)

    def test_the_address_of_the_page(self):
        assert launch.dashboard_url(8600) == "http://127.0.0.1:8600"

    def test_the_address_checks_the_port_too(self):
        with pytest.raises(ValueError, match="port"):
            launch.dashboard_url(0)

    def test_the_default_port(self):
        assert launch.DEFAULT_PORT == 8501

    @pytest.mark.parametrize("port", [0, -1, 65536, 100000])
    def test_a_port_outside_the_range_is_refused(self, port):
        with pytest.raises(ValueError, match="port"):
            launch.streamlit_command(port)

    @pytest.mark.parametrize("port", [1, 80, 65535])
    def test_the_ends_of_the_range_are_accepted(self, port):
        assert str(port) in launch.streamlit_command(port)


class TestPortIsFree:
    def test_a_port_nobody_listens_on_is_free(self):
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        assert launch.port_is_free(port)

    def test_a_port_with_a_listener_is_not(self):
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen()
            assert not launch.port_is_free(sock.getsockname()[1])

    def test_a_port_that_only_has_closed_connections_waiting_is_free(self):
        # right after a dashboard ends its port is in TIME_WAIT: the server can use it again
        # (it sets SO_REUSEADDR), so saying "in use" would be wrong
        import socket

        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            server.listen()
            port = server.getsockname()[1]
            with socket.create_connection(("127.0.0.1", port)) as client:
                connection, _ = server.accept()
                connection.close()  # the side that closes first keeps the port in TIME_WAIT
                client.recv(1)
        assert launch.port_is_free(port)

    def test_the_probe_does_not_keep_the_port(self):
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        assert launch.port_is_free(port) and launch.port_is_free(port)

    @pytest.mark.parametrize("port", [0, -1, 65536])
    def test_a_bad_port_is_refused(self, port):
        with pytest.raises(ValueError):
            launch.port_is_free(port)


class TestIsAvailable:
    def test_true_when_streamlit_can_be_found(self, monkeypatch):
        monkeypatch.setattr(launch.importlib.util, "find_spec", lambda name: object())
        assert launch.streamlit_available() is True

    def test_false_when_it_cannot(self, monkeypatch):
        seen = []
        monkeypatch.setattr(launch.importlib.util, "find_spec", lambda name: seen.append(name))
        assert launch.streamlit_available() is False
        assert seen == ["streamlit"]


class FakeProcess:
    """Stands in for the Streamlit process: records how it was started and how it ended."""

    started = []

    def __init__(self, command, code=0, interrupt=False, slow_to_stop=False, signalled=False):
        self.command, self.code, self.interrupt, self.slow_to_stop = (
            command,
            code,
            interrupt,
            slow_to_stop,
        )
        self.signalled = signalled  # the first wait is cut short by SIGTERM or SIGHUP
        self.killed = False
        self.terminated = False
        self.finished = False
        self.waits = []
        self.events = []  # what happened, in order

    def wait(self, timeout=None):
        self.waits.append(timeout)
        self.events.append(f"wait({timeout})")
        if self.interrupt and len(self.waits) == 1:
            raise KeyboardInterrupt
        if self.signalled and len(self.waits) == 1:
            raise cli._Terminated
        if self.slow_to_stop and timeout is not None and not self.killed:
            raise subprocess.TimeoutExpired(self.command, timeout)
        return self.code

    def poll(self):
        return self.code if self.finished else None

    def terminate(self):
        self.terminated = True
        self.events.append("terminate")

    def kill(self):
        self.killed = True


class Started(list):
    """The fake processes made so far, and the options the next one is made with."""

    def __init__(self):
        super().__init__()
        self.options = {}


@pytest.fixture
def streamlit(monkeypatch):
    """Pretend Streamlit is installed and replace the process that would run it."""
    monkeypatch.setattr(cli, "streamlit_available", lambda: True)
    monkeypatch.setattr(cli, "port_is_free", lambda port, address: True)
    made = Started()

    def popen(command, **kwargs):
        process = FakeProcess(command, **made.options)
        made.append(process)
        return process

    monkeypatch.setattr(cli.subprocess, "Popen", popen)
    return made


class TestCommandLine:
    @pytest.fixture
    def run(self, capsys):
        def go(*argv):
            status = main([str(a) for a in argv])
            out, err = capsys.readouterr()
            return status, out, err

        return go

    def test_a_missing_streamlit_gives_a_clear_message_and_exit_code_2(self, run, monkeypatch):
        monkeypatch.setattr(cli, "streamlit_available", lambda: False)
        called = []
        monkeypatch.setattr(cli.subprocess, "Popen", lambda *a, **k: called.append(a))
        status, out, err = run("dashboard")
        assert (status, out) == (EXIT_USAGE, "")
        assert err == (
            "loginsight: error: the dashboard needs Streamlit, which is not installed. "
            "Install it with:  pip install 'loginsight[dashboard]'\n"
        )
        assert called == []

    def test_it_starts_streamlit_and_shows_the_address(self, run, streamlit):
        status, out, err = run("dashboard")
        assert (status, err) == (EXIT_OK, "")
        assert out == (
            "LogInsight dashboard: open http://127.0.0.1:8501 in your browser "
            "(press Ctrl+C to stop)\n"
        )
        assert [p.command for p in streamlit] == [launch.streamlit_command(launch.DEFAULT_PORT)]

    def test_the_port_option(self, run, streamlit):
        status, out, _ = run("dashboard", "--port", "9000")
        assert status == EXIT_OK and "http://127.0.0.1:9000" in out
        assert [p.command for p in streamlit] == [launch.streamlit_command(9000)]

    @pytest.mark.parametrize("bad", ["0", "70000", "-5", "abc", "80.5", ""])
    def test_a_bad_port_is_a_usage_error(self, run, bad):
        status, out, err = run("dashboard", "--port", bad)
        assert (status, out) == (EXIT_USAGE, "") and "port" in err

    @pytest.mark.parametrize("edge", [1, 65535])
    def test_the_ends_of_the_port_range_are_accepted_by_the_command(self, run, streamlit, edge):
        status, out, _ = run("dashboard", "--port", edge)
        assert status == EXIT_OK and f"http://127.0.0.1:{edge}" in out

    def test_the_usage_error_names_the_range(self, run):
        err = run("dashboard", "--port", "65536")[2]
        assert "between 1 and 65535" in err and "got 65536" in err

    def test_the_exit_status_of_streamlit_is_returned(self, run, streamlit):
        streamlit.options["code"] = 3
        assert run("dashboard")[0] == 3

    def test_ctrl_c_is_the_normal_way_to_stop_it_and_is_not_an_error(self, run, streamlit):
        streamlit.options["interrupt"] = True
        status, out, err = run("dashboard")
        assert (status, err) == (EXIT_OK, "")
        assert out.endswith("(press Ctrl+C to stop)\n")  # nothing about an interruption
        (process,) = streamlit
        assert process.waits == [None, 10] and not process.killed

    def test_a_process_that_does_not_stop_after_ctrl_c_is_killed(self, run, streamlit):
        streamlit.options.update(interrupt=True, slow_to_stop=True)
        assert run("dashboard")[0] == EXIT_OK
        (process,) = streamlit
        assert process.killed and process.waits == [None, 10, None]

    def test_the_process_is_stopped_if_it_is_still_running_when_the_command_ends(
        self, run, streamlit
    ):
        streamlit.options["code"] = 0
        run("dashboard")
        (process,) = streamlit
        assert process.terminated  # it never stays behind, whatever ended the command

    def test_a_process_that_has_finished_is_not_stopped_again(self, run, streamlit, monkeypatch):
        original = FakeProcess.wait

        def finish(self, timeout=None):
            self.finished = True
            return original(self, timeout)

        monkeypatch.setattr(FakeProcess, "wait", finish)
        run("dashboard")
        (process,) = streamlit
        assert not process.terminated

    def test_being_asked_to_terminate_stops_the_process_at_once_and_is_not_an_error(
        self, run, streamlit
    ):
        streamlit.options["signalled"] = True
        status, _, _ = run("dashboard")
        (process,) = streamlit
        assert status == 0
        # nobody else told Streamlit, so it is told now, and given time to finish
        assert process.terminated and process.waits == [None, 10] and not process.killed
        # told to stop BEFORE the wait, not after it has run out: that was a 10 s delay
        assert process.events[:3] == ["wait(None)", "terminate", "wait(10)"]

    def test_a_process_that_ignores_the_termination_is_killed(self, run, streamlit):
        streamlit.options.update(signalled=True, slow_to_stop=True)
        assert run("dashboard")[0] == 0
        (process,) = streamlit
        assert process.terminated and process.killed

    def test_terminate_and_hangup_are_handled_where_the_system_has_them(
        self, run, streamlit, monkeypatch
    ):
        import signal

        installed = []
        real = signal.signal

        def record(number, handler):
            installed.append((number, handler))
            return real(number, handler)

        monkeypatch.setattr(cli.signal, "signal", record)
        run("dashboard")
        wanted = {signal.SIGTERM} | ({signal.SIGHUP} if hasattr(signal, "SIGHUP") else set())
        assert set(cli.STOP_SIGNALS) == wanted
        handlers = [(n, h) for n, h in installed[: len(wanted)]]
        assert {n for n, _ in handlers} == wanted
        for number, handler in handlers:
            with pytest.raises(cli._Terminated):
                handler(number, None)
        assert {n for n, _ in installed[len(wanted) :]} == wanted  # and the old ones put back

    def test_the_previous_handlers_are_put_back(self, run, streamlit):
        import signal

        before = {n: signal.getsignal(n) for n in cli.STOP_SIGNALS}
        run("dashboard")
        assert {n: signal.getsignal(n) for n in cli.STOP_SIGNALS} == before

    def test_a_port_that_is_in_use_is_reported_before_anything_starts(
        self, run, streamlit, monkeypatch
    ):
        monkeypatch.setattr(cli, "port_is_free", lambda port, address: False)
        status, out, err = run("dashboard", "--port", 8123)
        assert status == 1 and out == ""
        assert err == "loginsight: error: port 8123 is already in use; choose another with --port\n"
        assert streamlit == []  # Streamlit was never started

    def test_the_port_is_checked_with_the_one_asked_for(self, run, streamlit, monkeypatch):
        asked = []
        monkeypatch.setattr(cli, "port_is_free", lambda port, address: asked.append(port) or True)
        run("dashboard", "--port", 9001)
        assert asked == [9001]

    def test_the_address_is_printed_after_the_start_and_before_the_wait(self, run, monkeypatch):
        monkeypatch.setattr(cli, "streamlit_available", lambda: True)
        order = []

        class Process:
            def wait(self, timeout=None):
                order.append("wait")
                return 0

            def poll(self):
                return 0

        monkeypatch.setattr(cli, "_print", lambda text: order.append("print"))
        monkeypatch.setattr(
            cli.subprocess, "Popen", lambda *a, **k: order.append("start") or Process()
        )
        main(["dashboard"])
        assert order == ["start", "print", "wait"]

    def test_streamlit_not_starting_is_a_problem_not_a_traceback(self, run, monkeypatch):
        monkeypatch.setattr(cli, "streamlit_available", lambda: True)

        def fail(command, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", command[0])

        monkeypatch.setattr(cli.subprocess, "Popen", fail)
        status, out, err = run("dashboard")
        assert (status, out) == (
            EXIT_PROBLEM,
            "",
        )  # no address is shown for a page that is not there
        assert err.startswith("loginsight: error: cannot start Streamlit: No such file")
        assert "Traceback" not in err

    def test_the_help_lists_the_command(self, run):
        status, out, _ = run("--help")
        assert status == EXIT_OK and "dashboard" in out
        assert "--port" in run("dashboard", "--help")[1]

    def test_the_dashboard_command_takes_no_log_file(self, run):
        status, _, err = run("dashboard", "some.log")
        assert status == EXIT_USAGE and "unrecognized arguments" in err


class TestTheListeningAddress:
    """The dashboard listens on this computer only, unless the person says otherwise."""

    def test_the_default_is_this_computer(self):
        assert launch.DEFAULT_ADDRESS == "127.0.0.1" and launch.is_loopback("127.0.0.1")
        command = launch.streamlit_command(8501)
        assert command == launch.streamlit_command(8501, "127.0.0.1")

    @pytest.mark.parametrize("address", ["0.0.0.0", "192.0.2.7", "::", "::1", "2001:db8::5"])
    def test_an_ip_address_is_passed_to_streamlit_as_given(self, address):
        command = launch.streamlit_command(8501, address)
        assert command[command.index("--server.address") + 1] == address

    @pytest.mark.parametrize(
        "bad",
        ["", "localhost", "example.com", "1.2.3", "256.1.1.1", "0.0.0.0/0", "1.1.1.1 --x y", "-1"],
    )
    def test_anything_that_is_not_an_address_is_refused(self, bad):
        with pytest.raises(ValueError, match="not an IPv4 or IPv6 address"):
            launch.streamlit_command(8501, bad)
        with pytest.raises(ValueError):
            launch.check_address(bad)
        with pytest.raises(ValueError):
            launch.is_loopback(bad)
        with pytest.raises(ValueError):
            launch.port_is_free(8501, bad)

    @pytest.mark.parametrize(
        ("address", "loopback"),
        [("127.0.0.1", True), ("127.0.0.5", True), ("::1", True), ("0.0.0.0", False),
         ("192.0.2.7", False), ("::", False)],
    )  # fmt: skip
    def test_loopback_addresses_are_told_from_the_rest(self, address, loopback):
        assert launch.is_loopback(address) is loopback

    def test_a_port_is_probed_on_the_address_asked_for(self):
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen()
            busy = sock.getsockname()[1]
        assert launch.port_is_free(busy, "127.0.0.1")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen()
            assert not launch.port_is_free(sock.getsockname()[1], "127.0.0.1")

    def test_an_ipv6_address_is_probed_with_an_ipv6_socket(self):
        import socket

        try:
            with socket.socket(socket.AF_INET6) as sock:
                sock.bind(("::1", 0))
                sock.listen()
                busy = sock.getsockname()[1]
                assert not launch.port_is_free(busy, "::1")
        except OSError:
            pytest.skip("no IPv6 on this computer")
        assert launch.port_is_free(busy, "::1")


class TestTheAddressOption:
    @pytest.fixture
    def run(self, capsys):
        def go(*argv):
            status = main([str(a) for a in argv])
            out, err = capsys.readouterr()
            return status, out, err

        return go

    def test_the_default_starts_it_on_this_computer_without_a_warning(self, run, streamlit):
        status, out, err = run("dashboard")
        assert (status, err) == (EXIT_OK, "")
        assert [p.command for p in streamlit] == [launch.streamlit_command(launch.DEFAULT_PORT)]

    def test_an_address_reaches_streamlit_and_a_warning_is_shown(self, run, streamlit):
        status, out, err = run("dashboard", "--address", "0.0.0.0", "--port", 9100)
        assert status == EXIT_OK
        assert [p.command for p in streamlit] == [launch.streamlit_command(9100, "0.0.0.0")]
        assert err.startswith("loginsight: warning: the dashboard is offered on 0.0.0.0")
        assert "publish the port to 127.0.0.1" in err
        assert "http://127.0.0.1:9100" in out  # the address to open stays the local one

    def test_a_loopback_address_gives_no_warning(self, run, streamlit):
        assert run("dashboard", "--address", "127.0.0.2")[2] == ""

    @pytest.mark.parametrize("bad", ["localhost", "", "0.0.0.0/0", "300.1.1.1"])
    def test_a_bad_address_is_a_usage_error(self, run, bad):
        status, out, err = run("dashboard", "--address", bad)
        assert (status, out) == (EXIT_USAGE, "") and "not an IPv4 or IPv6 address" in err

    def test_the_port_is_probed_on_that_address(self, run, streamlit, monkeypatch):
        asked = []
        monkeypatch.setattr(
            cli, "port_is_free", lambda port, address: asked.append((port, address)) or True
        )
        run("dashboard", "--address", "0.0.0.0", "--port", 9101)
        assert asked == [(9101, "0.0.0.0")]

    def test_the_help_says_when_to_use_it(self, capsys):
        assert main(["dashboard", "--help"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "--address IP" in out and "inside a container" in out
