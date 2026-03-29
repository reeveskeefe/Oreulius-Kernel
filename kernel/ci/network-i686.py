#!/usr/bin/env python3
import errno
import os
import pty
import re
import subprocess
import sys
import threading
import time
from pathlib import Path


class HarnessError(RuntimeError):
    pass


class QemuSerialHarness:
    MAX_BUFFER = 256_000

    def __init__(self, argv):
        self._master_fd, slave_fd = pty.openpty()
        self._next_seq = 1
        self.proc = subprocess.Popen(
            argv,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=Path(__file__).resolve().parent.parent,
            bufsize=0,
            close_fds=True,
        )
        os.close(slave_fd)
        self._cv = threading.Condition()
        self._buffer = ""
        self._closed = False
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()

    def _read_stdout(self):
        while True:
            try:
                chunk = os.read(self._master_fd, 4096)
                if not chunk:
                    break
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            text = chunk.decode("utf-8", errors="replace")
            sys.stdout.write(text)
            sys.stdout.flush()
            with self._cv:
                self._buffer += text
                if len(self._buffer) > self.MAX_BUFFER:
                    self._buffer = self._buffer[-self.MAX_BUFFER :]
                self._cv.notify_all()
        with self._cv:
            self._closed = True
            self._cv.notify_all()

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self._reader.join(timeout=5)
        try:
            os.close(self._master_fd)
        except OSError:
            pass

    def wait_for_any(self, patterns, timeout, label):
        deadline = time.monotonic() + timeout
        while True:
            with self._cv:
                for name, regex in patterns:
                    match = regex.search(self._buffer)
                    if match:
                        self._buffer = self._buffer[match.end() :]
                        return name, match
                if self._closed:
                    raise HarnessError(
                        f"{label}: qemu exited unexpectedly\n{self._tail_snapshot()}"
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HarnessError(
                        f"{label}: timeout waiting for expected output\n{self._tail_snapshot()}"
                    )
                self._cv.wait(timeout=remaining)

    def _tail_snapshot(self):
        tail = self._buffer[-4000:]
        return f"[HARNESS] output tail:\n{tail}"

    def next_seq(self):
        seq = self._next_seq
        self._next_seq += 1
        return seq

    def send_command_frame(self, seq, cmd):
        payload = cmd.encode("ascii")
        frame = f"~C{seq:08X}:{len(payload):04X}:{payload.hex().upper()}\r\n".encode("ascii")
        time.sleep(0.40)
        for byte in frame:
            os.write(self._master_fd, bytes([byte]))
            time.sleep(0.05)
        return seq


PROMPT_RE = re.compile(r"\[CI-SHELL\] PROMPT")
READY_RE = re.compile(r"\[CI-SHELL\] READY")
COMMIT_ANY_RE = re.compile(r"\[CI-SHELL\] COMMIT seq=(\d+) len=(\d+) hex=([0-9A-F]*)")
DONE_ANY_RE = re.compile(r"\[CI-SHELL\] DONE seq=(\d+) len=(\d+) status=ok hex=([0-9A-F]*)")
STATUS_READY_RE = re.compile(r"Status: READY")
STATUS_NOT_READY_RE = re.compile(r"Status: NOT READY")
NONZERO_IP_RE = re.compile(r"My IP: (?!0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}")
ZERO_IP_RE = re.compile(r"My IP: 0\.0\.0\.0")
LINK_UP_RE = re.compile(r"Link Status: UP")
DNS_SUCCESS_RE = re.compile(r"Success! IP: (?:\d{1,3}\.){3}\d{1,3}")
HTTP_STATUS_RE = re.compile(r"Status: [23]\d\d")
HTTP_TOTAL_RE = re.compile(r"Total: [1-9]\d* bytes")
HTTPS_FAIL_RE = re.compile(
    r"Request failed: HTTPS blocked: strict certificate validation is not implemented"
)
REQUEST_FAILED_RE = re.compile(r"Request failed: (.+)")
RESOLUTION_FAILED_RE = re.compile(r"Resolution failed: (.+)")
ERROR_RE = re.compile(r"Error: (.+)")
UNKNOWN_CMD_RE = re.compile(r"Unknown command: (.+)")


def commit_re(seq, cmd):
    hex_cmd = cmd.encode("ascii").hex().upper()
    return re.compile(
        rf"\[CI-SHELL\] COMMIT seq={seq} len={len(cmd)} hex={hex_cmd}"
    )


def done_re(seq, cmd):
    hex_cmd = cmd.encode("ascii").hex().upper()
    return re.compile(
        rf"\[CI-SHELL\] DONE seq={seq} len={len(cmd)} status=ok hex={hex_cmd}"
    )


def wait_for_prompt(h, timeout=60):
    h.wait_for_any([("prompt", PROMPT_RE)], timeout, "waiting for CI prompt")


def settle_shell(h):
    h.wait_for_any([("ready", READY_RE)], 120, "waiting for CI shell ready")
    wait_for_prompt(h, timeout=60)
    time.sleep(0.50)


def send_committed(h, label, cmd):
    seq = h.next_seq()
    for attempt in range(5):
        h.send_command_frame(seq, cmd)
        try:
            name, match = h.wait_for_any(
                [
                    ("commit_exact", commit_re(seq, cmd)),
                    ("commit_other", COMMIT_ANY_RE),
                    ("unknown", UNKNOWN_CMD_RE),
                ],
                6,
                f"{label}: waiting for command commit",
            )
        except HarnessError:
            if attempt == 4:
                raise
            continue
        if name == "commit_exact":
            return seq
        if name == "commit_other":
            committed_seq = match.group(1)
            committed_hex = match.group(3)
            try:
                committed = bytes.fromhex(committed_hex).decode("ascii", errors="replace")
            except ValueError:
                committed = committed_hex
            raise HarnessError(
                f"{label}: saw mismatched commit seq={committed_seq} line={committed!r}"
            )
        raise HarnessError(f"{label}: unknown command {match.group(1)}")
    raise HarnessError(f"{label}: failed to get exact commit for {cmd!r}")


def ensure_no_failure(label, name, match):
    if name == "resolution_failed":
        raise HarnessError(f"{label}: {match.group(1)}")
    if name == "request_failed":
        raise HarnessError(f"{label}: {match.group(1)}")
    if name == "error":
        raise HarnessError(f"{label}: {match.group(1)}")
    if name == "unknown":
        raise HarnessError(f"{label}: unknown command {match.group(1)}")


def expect_ready_phase(h):
    for attempt in range(6):
        seq = send_committed(h, "netstack-info", "netstack-info")
        name, match = h.wait_for_any(
            [
                ("ready", STATUS_READY_RE),
                ("not_ready", STATUS_NOT_READY_RE),
                ("error", ERROR_RE),
            ],
            30,
            "netstack-info: waiting for readiness status",
        )
        ensure_no_failure("netstack-info", name, match)
        if name == "ready":
            ip_name, ip_match = h.wait_for_any(
                [
                    ("nonzero_ip", NONZERO_IP_RE),
                    ("zero_ip", ZERO_IP_RE),
                    ("error", ERROR_RE),
                ],
                30,
                "netstack-info: waiting for configured IP",
            )
            ensure_no_failure("netstack-info", ip_name, ip_match)
            h.wait_for_any(
                [("done", done_re(seq, "netstack-info"))],
                30,
                "netstack-info: waiting for completion marker",
            )
            wait_for_prompt(h)
            if ip_name == "nonzero_ip":
                return
            time.sleep(1.2)
            continue
        h.wait_for_any(
            [("done", done_re(seq, "netstack-info"))],
            30,
            "netstack-info: waiting for completion marker",
        )
        wait_for_prompt(h)
        time.sleep(1.2)
    raise HarnessError("network never became ready on i686")


def run_simple_phase(h, label, cmd, success_regex):
    seq = send_committed(h, label, cmd)
    name, match = h.wait_for_any(
        [
            ("success", success_regex),
            ("resolution_failed", RESOLUTION_FAILED_RE),
            ("request_failed", REQUEST_FAILED_RE),
            ("error", ERROR_RE),
            ("unknown", UNKNOWN_CMD_RE),
        ],
        60,
        f"{label}: waiting for success output",
    )
    ensure_no_failure(label, name, match)
    h.wait_for_any(
        [("done", done_re(seq, cmd))], 60, f"{label}: waiting for completion marker"
    )
    wait_for_prompt(h)


def run_http_phase(h):
    label = "plain HTTP"
    cmd = "http-get http://example.com/"
    seq = send_committed(h, label, cmd)
    name, match = h.wait_for_any(
        [
            ("status", HTTP_STATUS_RE),
            ("request_failed", REQUEST_FAILED_RE),
            ("error", ERROR_RE),
            ("unknown", UNKNOWN_CMD_RE),
        ],
        120,
        f"{label}: waiting for HTTP status",
    )
    ensure_no_failure(label, name, match)
    name, match = h.wait_for_any(
        [
            ("total", HTTP_TOTAL_RE),
            ("request_failed", REQUEST_FAILED_RE),
            ("error", ERROR_RE),
            ("unknown", UNKNOWN_CMD_RE),
        ],
        120,
        f"{label}: waiting for HTTP body length",
    )
    ensure_no_failure(label, name, match)
    h.wait_for_any(
        [("done", done_re(seq, cmd))], 60, f"{label}: waiting for completion marker"
    )
    wait_for_prompt(h)


def run_https_phase(h):
    label = "HTTPS fail-closed"
    cmd = "http-get https://example.com/"
    seq = send_committed(h, label, cmd)
    name, match = h.wait_for_any(
        [
            ("fail_closed", HTTPS_FAIL_RE),
            ("request_failed", REQUEST_FAILED_RE),
            ("error", ERROR_RE),
            ("unknown", UNKNOWN_CMD_RE),
        ],
        60,
        f"{label}: waiting for fail-closed result",
    )
    if name == "request_failed":
        if "strict certificate validation is not implemented" in match.group(1):
            name = "fail_closed"
        else:
            ensure_no_failure(label, name, match)
    else:
        ensure_no_failure(label, name, match)
    h.wait_for_any(
        [("done", done_re(seq, cmd))], 60, f"{label}: waiting for completion marker"
    )
    wait_for_prompt(h)


def main():
    kernel_dir = Path(__file__).resolve().parent.parent
    iso_path = kernel_dir / "oreulia.iso"
    argv = [
        "qemu-system-i386",
        "-cdrom",
        str(iso_path.name),
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-display",
        "none",
        "-no-reboot",
        "-no-shutdown",
        "-m",
        "512M",
        "-netdev",
        "user,id=n0",
        "-device",
        "e1000,netdev=n0",
    ]

    harness = QemuSerialHarness(argv)
    try:
        settle_shell(harness)
        expect_ready_phase(harness)
        run_simple_phase(harness, "eth-status", "eth-status", LINK_UP_RE)
        time.sleep(1.5)
        run_simple_phase(
            harness, "first dns-resolve", "dns-resolve example.com", DNS_SUCCESS_RE
        )
        run_simple_phase(
            harness, "second dns-resolve", "dns-resolve example.com", DNS_SUCCESS_RE
        )
        run_http_phase(harness)
        run_https_phase(harness)
    except HarnessError as exc:
        print(f"[HARNESS] FAIL: {exc}", flush=True)
        harness.close()
        return 1
    harness.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
