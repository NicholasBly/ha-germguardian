#!/usr/bin/env bash
# Recover a frozen built-in Bluetooth adapter for Home Assistant running in Docker.
#
# Why: the Raspberry Pi's built-in Bluetooth chip sits on a serial (UART) line, not USB.
# When it freezes, Home Assistant's own recovery can only power-cycle it, and that times out
# ("Could not cycle the Bluetooth adapter ... Operation timed out"). Home Assistant then logs
# "Failed to restart Bluetooth scanner" every minute until the Pi is rebooted.
#
# What this does, checked every 2 minutes by a systemd timer:
#   1. Looks for "Failed to restart Bluetooth scanner" in Home Assistant's recent log.
#   2. First time in an episode: reloads the Bluetooth driver (unbind/bind the serial
#      Bluetooth device, or reload the hci_uart module), then restarts Home Assistant.
#   3. Still failing after that: reboots the Pi - at most once every 6 hours.
#   Everything it does is logged: journalctl -u bt-watchdog
#
# Install:    sudo bash bt-watchdog.sh install [--container NAME] [--no-reboot]
# Uninstall:  sudo bash bt-watchdog.sh uninstall
# Status:     bash bt-watchdog.sh status
set -uo pipefail

CONTAINER="${BTW_CONTAINER:-homeassistant}"
STATE_DIR="${BTW_STATE_DIR:-/var/lib/bt-watchdog}"
SYSFS="${BTW_SYSFS:-/sys}"
LOOKBACK="${BTW_LOOKBACK:-300}"        # seconds of log to look at
MIN_FAILURES="${BTW_MIN_FAILURES:-2}"  # failures in that window that count as "stuck"
GRACE="${BTW_GRACE:-240}"              # seconds after a fix before judging again
RETRY_FIX="${BTW_RETRY_FIX:-1800}"     # repeat the driver reload at most this often
REBOOT_GAP="${BTW_REBOOT_GAP:-21600}"  # at most one reboot per 6 hours
ALLOW_REBOOT="${BTW_ALLOW_REBOOT:-1}"
RESTART_HA="${BTW_RESTART_HA:-1}"
DRY_RUN="${BTW_DRY_RUN:-0}"
NOW="${BTW_NOW:-$(date +%s)}"
SETTLE="${BTW_SETTLE:-3}"              # seconds to wait between driver steps

STUCK_TEXT="Failed to restart Bluetooth scanner"
BT_DRIVER_DIRS=(bus/serial/drivers/hci_uart_bcm)

say() { echo "bt-watchdog: $*"; }

run() {
    if [ "$DRY_RUN" = 1 ]; then
        say "(dry run) would run: $*"
        return 0
    fi
    "$@"
}

state_get() { cat "$STATE_DIR/$1" 2>/dev/null || echo 0; }
state_set() { [ "$DRY_RUN" = 1 ] || echo "$2" > "$STATE_DIR/$1"; }
state_clear() { [ "$DRY_RUN" = 1 ] || rm -f "$STATE_DIR/$1"; }

failures_since() {
    docker logs --since "$1" "$CONTAINER" 2>&1 | grep -c -F "$STUCK_TEXT"
}

reload_driver() {
    local dir name found=0
    for dir in "${BT_DRIVER_DIRS[@]}"; do
        dir="$SYSFS/$dir"
        [ -d "$dir" ] || continue
        for name in "$dir"/serial*; do
            [ -e "$name" ] || continue
            name="$(basename "$name")"
            found=1
            if [ "$DRY_RUN" = 1 ]; then
                say "(dry run) would reload Bluetooth driver: unbind/bind $name"
            else
                say "reloading Bluetooth driver: unbind/bind $name"
                echo -n "$name" > "$dir/unbind"
                sleep "$SETTLE"
                echo -n "$name" > "$dir/bind"
            fi
        done
    done
    if [ "$found" = 0 ]; then
        if lsmod 2>/dev/null | grep -q '^hci_uart '; then
            say "reloading Bluetooth driver: hci_uart module"
            run modprobe -r hci_uart
            [ "$DRY_RUN" = 1 ] || sleep "$SETTLE"
            run modprobe hci_uart
        else
            say "no built-in Bluetooth driver to reload; restarting the bluetooth service instead"
            run systemctl restart bluetooth
        fi
    fi
    [ "$DRY_RUN" = 1 ] || sleep $((SETTLE * 3))
    if [ "$RESTART_HA" = 1 ]; then
        say "restarting Home Assistant ($CONTAINER) so it picks the adapter up again"
        run docker restart "$CONTAINER"
    fi
}

check() {
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    local last_fix last_reboot stuck_since since count
    last_fix="$(state_get last_fix)"
    last_reboot="$(state_get last_reboot)"
    stuck_since="$(state_get stuck_since)"

    if [ $((NOW - last_fix)) -lt "$GRACE" ]; then
        exit 0                                   # give the last fix time to work
    fi
    since=$((NOW - LOOKBACK))
    [ $((last_fix + GRACE)) -gt "$since" ] && since=$((last_fix + GRACE))
    count="$(failures_since "$since")"

    if [ "${count:-0}" -lt "$MIN_FAILURES" ]; then
        if [ "$stuck_since" != 0 ]; then
            say "Home Assistant's Bluetooth is working again"
            state_clear stuck_since
        fi
        exit 0
    fi

    say "Home Assistant cannot restart its Bluetooth scanner ($count failures in the last $((NOW - since)) s)"
    if [ "$stuck_since" = 0 ]; then
        stuck_since="$NOW"
        state_set stuck_since "$NOW"
    fi

    if [ "$last_fix" -lt "$stuck_since" ]; then
        state_set last_fix "$NOW"
        reload_driver
    elif [ "$ALLOW_REBOOT" = 1 ] && [ $((NOW - last_reboot)) -ge "$REBOOT_GAP" ]; then
        say "the driver reload did not help; rebooting the Pi"
        state_set last_reboot "$NOW"
        state_clear stuck_since
        run systemctl reboot
    elif [ $((NOW - last_fix)) -ge "$RETRY_FIX" ]; then
        say "still stuck (reboot not allowed right now); reloading the driver again"
        state_set last_fix "$NOW"
        reload_driver
    else
        say "still stuck; waiting (next driver reload in $((RETRY_FIX - (NOW - last_fix))) s)"
    fi
}

do_install() {
    [ "$(id -u)" = 0 ] || { echo "please run with sudo"; exit 1; }
    local container="$CONTAINER" reboot=1
    while [ $# -gt 0 ]; do
        case "$1" in
            --container) container="$2"; shift 2 ;;
            --no-reboot) reboot=0; shift ;;
            *) echo "unknown option: $1"; exit 1 ;;
        esac
    done
    if ! docker inspect "$container" > /dev/null 2>&1; then
        echo "warning: no Docker container called '$container' (use --container NAME)"
    fi
    install -m 755 "$0" /usr/local/sbin/bt-watchdog
    cat > /etc/systemd/system/bt-watchdog.service <<EOF
[Unit]
Description=Recover a frozen Bluetooth adapter for Home Assistant
After=docker.service

[Service]
Type=oneshot
Environment=BTW_CONTAINER=$container
Environment=BTW_ALLOW_REBOOT=$reboot
ExecStart=/usr/local/sbin/bt-watchdog check
EOF
    cat > /etc/systemd/system/bt-watchdog.timer <<'EOF'
[Unit]
Description=Check Home Assistant's Bluetooth every 2 minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now bt-watchdog.timer
    echo "installed: checks every 2 minutes (container: $container, reboot allowed: $reboot)"
    echo "see what it did:  journalctl -u bt-watchdog"
}

do_uninstall() {
    [ "$(id -u)" = 0 ] || { echo "please run with sudo"; exit 1; }
    systemctl disable --now bt-watchdog.timer 2>/dev/null || true
    rm -f /etc/systemd/system/bt-watchdog.timer /etc/systemd/system/bt-watchdog.service \
          /usr/local/sbin/bt-watchdog
    rm -rf "$STATE_DIR"
    systemctl daemon-reload
    echo "removed"
}

do_status() {
    systemctl list-timers bt-watchdog.timer --no-pager 2>/dev/null || true
    journalctl -u bt-watchdog --no-pager -n 20 2>/dev/null || true
}

case "${1:-check}" in
    check) check ;;
    install) shift; do_install "$@" ;;
    uninstall) do_uninstall ;;
    status) do_status ;;
    *) echo "usage: $0 [check|install [--container NAME] [--no-reboot]|uninstall|status]"; exit 1 ;;
esac
