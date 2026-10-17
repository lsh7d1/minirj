"""Explicit network configuration ownership; never manage external leases."""

import math
import os
import signal
import subprocess
import time


class NetworkConfig:
    def __init__(self, backend="external", script=None, timeout=30.0,
                 monotonic=time.monotonic):
        if backend not in ("external", "script"):
            raise ValueError("unknown network backend")
        if backend == "script" and not script:
            raise ValueError("script backend requires --dhcp-script")
        if backend == "external" and script:
            raise ValueError("--dhcp-script requires --network-backend script")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("script timeout must be finite and positive")
        self.backend, self.script, self.timeout = backend, script, timeout
        self.clock = monotonic
        self.process = None
        self.deadline = None
        self.result = None
        self.started = False
        self.terminating = False
        self.killed = False
        self.failed = False
        self.exit_code = None

    def reset(self, report=None):
        """Reset network operation state for a new session or retry attempt.

        Safely closes and reaps any existing child process group before resetting
        flags to avoid concurrent activation or stale late-arriving results.
        """
        if self.process is not None:
            if report is None:
                report = lambda _: None
            self.close(report)
        self.process = None
        self.deadline = None
        self.result = None
        self.started = False
        self.terminating = False
        self.killed = False
        self.failed = False
        self.exit_code = None

    def start(self, interface, report):
        if self.started:
            return
        self.started = True
        if self.backend == "external":
            self.result = "external: network configuration left to external owner"
            report(self.result)
            return
        try:
            self.process = subprocess.Popen(
                [self.script, interface], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, start_new_session=True,
            )
        except OSError:
            self.failed = True
            self.result = "script launch failed"
            report(self.result)
            return
        self.deadline = self.clock() + self.timeout
        report("network script started")

    def _signal_group(self, sig):
        try:
            os.killpg(self.process.pid, sig)
        except ProcessLookupError:
            pass

    def _exited(self):
        # Keep the leader unreaped until its group is cleaned: its PID cannot be reused.
        return os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    def poll(self, report):
        if self.process is None:
            return
        now = self.clock()
        if now >= self.deadline and not self.terminating:
            self.failed = True
            self.result = "network script completion not observed before deadline"
            report(self.result)
            self._signal_group(signal.SIGTERM)
            self.terminating = True
            self.deadline = now + 0.2
        if self._exited():
            self._signal_group(signal.SIGKILL)
            code = self.process.wait()
            self.exit_code = code
            self.failed = self.failed or code != 0
            self.result = f"network script exited with code {code}"
            report(self.result)
            self.process = None
        elif self.terminating and now >= self.deadline and not self.killed:
            self._signal_group(signal.SIGKILL)
            self.killed = True

    def close(self, report):
        """Keep the caller's interface lock until our child has been reaped."""
        if self.process is None:
            return
        self._signal_group(signal.SIGTERM)
        deadline = time.monotonic() + 0.2
        while not self._exited() and time.monotonic() < deadline:
            time.sleep(0.01)
        self._signal_group(signal.SIGKILL)
        # An uninterruptible child may delay shutdown; do not report clean exit early.
        code = self.process.wait()
        report(f"owned network script cleanup: exit code {code}")
        self.process = None
