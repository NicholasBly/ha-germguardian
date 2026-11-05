"""tools/pi-bluetooth-watchdog/bt-watchdog.sh against fake docker/systemctl/modprobe and a fake /sys."""
import os
import pathlib
import subprocess

import pytest

SCRIPT = pathlib.Path(__file__).parent.parent / "tools" / "pi-bluetooth-watchdog" / "bt-watchdog.sh"
STUCK = ("2026-11-05 16:42:14.292 ERROR (MainThread) [habluetooth.scanner] "
         "hci0 (B8:27:EB:58:4B:1E): Failed to restart Bluetooth scanner")
NOW = 1_000_000


class Pi:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        self.state = root / "state"
        self.calls = root / "calls"
        self.log = root / "ha.log"            # lines: "<epoch>|<text>"
        self.lsmod = root / "lsmod"
        self.calls.write_text("")
        self.log.write_text("")
        self.lsmod.write_text("")
        self._stub("docker", r'''
if [ "$1" = logs ]; then
    since="$3"
    while IFS='|' read -r t text; do
        [ -n "$t" ] && [ "$t" -ge "$since" ] && echo "$text"
    done < "$FAKE_LOG"
    exit 0
fi
echo "docker $*" >> "$FAKE_CALLS"''')
        self._stub("systemctl", 'echo "systemctl $*" >> "$FAKE_CALLS"')
        self._stub("modprobe", 'echo "modprobe $*" >> "$FAKE_CALLS"')
        self._stub("lsmod", 'cat "$FAKE_LSMOD"')
        self._stub("sleep", "true")

    def _stub(self, name, body):
        p = self.bin / name
        p.write_text("#!/usr/bin/env bash\n" + body + "\n")
        p.chmod(0o755)

    def add_driver(self):
        d = self.root / "sys/bus/serial/drivers/hci_uart_bcm"
        d.mkdir(parents=True)
        (d / "serial0-0").mkdir()
        (d / "bind").write_text("")
        (d / "unbind").write_text("")
        return d

    def failures(self, *times):
        with self.log.open("a") as f:
            for t in times:
                f.write(f"{t}|{STUCK}\n")

    def run(self, now=NOW, **env):
        e = dict(os.environ)
        e.update(
            PATH=f"{self.bin}:{e['PATH']}", FAKE_LOG=str(self.log), FAKE_CALLS=str(self.calls),
            FAKE_LSMOD=str(self.lsmod), BTW_STATE_DIR=str(self.state),
            BTW_SYSFS=str(self.root / "sys"), BTW_NOW=str(now),
        )
        e.update({k: str(v) for k, v in env.items()})
        r = subprocess.run(["bash", str(SCRIPT), "check"], env=e, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return r.stdout

    def called(self):
        return [line for line in self.calls.read_text().splitlines() if line]

    def st(self, name):
        p = self.state / name
        return int(p.read_text()) if p.exists() else None


@pytest.fixture
def pi(tmp_path):
    return Pi(tmp_path)


def test_a_healthy_home_assistant_is_left_alone(pi):
    pi.add_driver()
    assert pi.run() == "" and pi.called() == []


def test_one_failure_is_not_enough(pi):
    pi.add_driver()
    pi.failures(NOW - 30)
    pi.run()
    assert pi.called() == []


def test_old_failures_outside_the_window_do_not_count(pi):
    pi.add_driver()
    pi.failures(NOW - 900, NOW - 840)
    pi.run()
    assert pi.called() == []


def test_first_time_stuck_reloads_the_driver_then_restarts_home_assistant(pi):
    drv = pi.add_driver()
    pi.failures(NOW - 120, NOW - 60)
    out = pi.run()
    assert "unbind/bind serial0-0" in out
    assert (drv / "unbind").read_text() == "serial0-0" and (drv / "bind").read_text() == "serial0-0"
    assert pi.called() == ["docker restart homeassistant"]
    assert pi.st("last_fix") == NOW and pi.st("stuck_since") == NOW


def test_after_a_fix_it_waits_before_judging_again(pi):
    pi.add_driver()
    pi.failures(NOW - 120, NOW - 60)
    pi.run()
    pi.failures(NOW + 30, NOW + 90)                     # old errors still scrolling in the log
    pi.run(now=NOW + 120)
    assert pi.called() == ["docker restart homeassistant"]          # nothing new


def test_still_stuck_after_the_driver_reload_means_a_reboot(pi):
    pi.add_driver()
    pi.failures(NOW - 120, NOW - 60)
    pi.run()
    pi.failures(NOW + 300, NOW + 360)                   # after the grace period: the fix did not work
    out = pi.run(now=NOW + 400)
    assert "rebooting" in out
    assert pi.called()[-1] == "systemctl reboot"
    assert pi.st("last_reboot") == NOW + 400 and pi.st("stuck_since") is None


def test_errors_from_before_the_fix_do_not_cause_a_reboot(pi):
    pi.add_driver()
    pi.failures(NOW - 120, NOW - 60, NOW + 60, NOW + 120)      # all inside the grace period
    pi.run()
    out = pi.run(now=NOW + 400)
    assert "working again" in out
    assert "systemctl reboot" not in pi.called() and pi.st("stuck_since") is None


def test_reboots_are_limited_to_one_per_six_hours(pi):
    pi.add_driver()
    pi.state.mkdir()
    (pi.state / "last_reboot").write_text(str(NOW - 3600))      # rebooted an hour ago
    pi.failures(NOW - 120, NOW - 60)
    pi.run()                                                    # driver reload
    pi.failures(NOW + 300, NOW + 360)
    out = pi.run(now=NOW + 400)
    assert "systemctl reboot" not in pi.called() and "waiting" in out
    pi.failures(NOW + 1800, NOW + 1860)
    out = pi.run(now=NOW + 1900)                                # 30 min later: reload again
    assert "reloading the driver again" in out
    assert pi.called().count("docker restart homeassistant") == 2


def test_no_reboot_option_never_reboots(pi):
    pi.add_driver()
    pi.failures(NOW - 120, NOW - 60)
    pi.run(BTW_ALLOW_REBOOT=0)
    pi.failures(NOW + 300, NOW + 360)
    pi.run(now=NOW + 400, BTW_ALLOW_REBOOT=0)
    assert "systemctl reboot" not in pi.called()


def test_without_the_serial_driver_it_reloads_the_hci_uart_module(pi):
    pi.lsmod.write_text("hci_uart              49152  0\nbtbcm   24576  1 hci_uart\n")
    pi.failures(NOW - 120, NOW - 60)
    pi.run()
    assert pi.called() == ["modprobe -r hci_uart", "modprobe hci_uart", "docker restart homeassistant"]


def test_with_nothing_to_reload_it_restarts_the_bluetooth_service(pi):
    pi.failures(NOW - 120, NOW - 60)
    pi.run()
    assert pi.called() == ["systemctl restart bluetooth", "docker restart homeassistant"]


def test_another_container_name(pi):
    pi.add_driver()
    pi.failures(NOW - 120, NOW - 60)
    pi.run(BTW_CONTAINER="ha")
    assert pi.called() == ["docker restart ha"]


def test_dry_run_changes_nothing(pi):
    drv = pi.add_driver()
    pi.failures(NOW - 120, NOW - 60)
    out = pi.run(BTW_DRY_RUN=1)
    assert "dry run" in out
    assert pi.called() == [] and (drv / "unbind").read_text() == "" and pi.st("last_fix") is None
