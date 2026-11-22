#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
switch_webhook=0
import_state=''
while (($#)); do
    case "$1" in
        --switch-webhook) switch_webhook=1; shift ;;
        --state) (($# >= 2)) || fail '--state requires the path to state.json.'; import_state="$2"; shift 2 ;;
        -h|--help) printf '%s\n' 'Usage: sudo bash install.sh [--switch-webhook] [--state /path/to/state.json]'; exit ;;
        *) fail "Unknown argument: $1" ;;
    esac
done
[[ "$EUID" == 0 ]] || fail 'Run with sudo.'
[[ -f /etc/os-release ]] || fail 'Ubuntu 24.04 is required.'
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || fail 'Ubuntu 24.04 is required.'
[[ "$(cat /proc/1/comm)" == systemd ]] || fail 'Run this on the Ubuntu host with systemd.'
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ -f "$source_dir/src/app.php" && -f "$source_dir/deploy/monitor-bot.cron" ]] || fail 'Run install.sh from the extracted source checkout.'

app_dir=/opt/monitor-bot
config_dir=/etc/monitor-bot
data_dir=/var/lib/monitor-bot
cron_file=/etc/cron.d/monitor-bot
unit_file=/etc/systemd/system/monitor-bot-poll.service
for path in "$app_dir" "$config_dir" "$data_dir" "$cron_file" "$unit_file"; do
    [[ ! -L "$path" ]] || fail "Refusing to replace symlink $path."
done
if [[ -n "$import_state" ]]; then
    [[ -f "$import_state" && -r "$import_state" ]] || fail 'State file is not readable.'
    [[ ! -e "$data_dir/state.json" ]] || fail 'State already exists on Ubuntu; keeping it.'
fi

if ! [[ -x /usr/bin/php && -x /usr/sbin/cron ]] || ! /usr/bin/php -r 'exit(PHP_VERSION_ID >= 80100 && extension_loaded("curl") ? 0 : 1);'; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends php-cli php-curl cron ca-certificates
fi
/usr/bin/php -r 'exit(PHP_VERSION_ID >= 80100 && extension_loaded("curl") ? 0 : 1);' || fail 'PHP CLI with cURL is required.'

if ! getent passwd monitorbot >/dev/null; then
    useradd --system --user-group --home-dir "$data_dir" --shell /usr/sbin/nologin monitorbot
fi
[[ "$(id -gn monitorbot)" == monitorbot && "$(id -u monitorbot)" != 0 ]] || fail 'Existing monitorbot account is incompatible.'
install -d -m 0755 "$app_dir" "$app_dir/src" "$app_dir/bin" "$app_dir/deploy"
install -d -m 0750 -o root -g monitorbot "$config_dir"
install -d -m 0750 -o monitorbot -g monitorbot "$data_dir"

if [[ ! -e "$config_dir/config.php" ]]; then
    [[ -r /dev/tty ]] || fail 'First install needs an interactive terminal.'
    printf '%s\n' 'Initial settings. Secret input is hidden and stays on this server.'
    read -r -s -p 'Monitoring Status URL: ' status_url </dev/tty; printf '\n'
    read -r -s -p 'Telegram bot token: ' bot_token </dev/tty; printf '\n'
    read -r -p 'Telegram admin numeric user ID: ' admin_id </dev/tty
    read -r -p 'Cloudflare zone ID: ' zone_id </dev/tty
    read -r -s -p 'Cloudflare DNS token: ' cf_token </dev/tty; printf '\n'
    read -r -s -p 'Full VLESS test template: ' template </dev/tty; printf '\n'
    read -r -s -p 'Optional monitor-only SOCKS5 URL (Enter for direct): ' socks </dev/tty; printf '\n'
    printf '%s\0%s\0%s\0%s\0%s\0%s\0%s' "$status_url" "$bot_token" "$admin_id" "$zone_id" "$cf_token" "$template" "$socks" |
        /usr/bin/php "$source_dir/deploy/configure.php" new "$config_dir/config.php"
    unset status_url bot_token admin_id zone_id cf_token template socks
fi
[[ -f "$config_dir/config.php" && ! -L "$config_dir/config.php" ]] || fail 'Invalid private config path.'
chown root:monitorbot "$config_dir/config.php"
chmod 0640 "$config_dir/config.php"

run_check() {
    runuser -u monitorbot -- env MONITOR_BOT_CONFIG="$config_dir/config.php" /usr/bin/php "$1" "$2"
}

# Let the service user validate even when the checkout is under /root.
stage=$(mktemp -d /tmp/monitor-bot.XXXXXXXX)
cleanup() {
    rm -f -- "$stage/deploy/server-check.php" "$stage"/src/*.php
    rmdir -- "$stage/deploy" "$stage/src" "$stage" 2>/dev/null || true
}
trap cleanup EXIT
chmod 0755 "$stage"
install -d -m 0755 "$stage/src" "$stage/deploy"
install -m 0644 "$source_dir"/src/*.php "$stage/src/"
install -m 0644 "$source_dir/deploy/server-check.php" "$stage/deploy/"

check_status=0
run_check "$stage/deploy/server-check.php" check || check_status=$?
if ((check_status == 12)); then
    ((switch_webhook == 1)) || exit 12
elif ((check_status != 0)); then
    exit "$check_status"
fi

if [[ -n "$import_state" ]]; then
    /usr/bin/php "$source_dir/deploy/configure.php" import-state "$import_state" "$data_dir/state.json"
    chown monitorbot:monitorbot "$data_dir/state.json"
fi

install -m 0644 "$source_dir"/src/*.php "$app_dir/src/"
install -m 0644 "$source_dir/bin/poll.php" "$source_dir/bin/cron.php" "$app_dir/bin/"
install -m 0644 "$source_dir/deploy/server-check.php" "$app_dir/deploy/"
install -m 0644 "$source_dir/deploy/monitor-bot-poll.service" "$unit_file"
systemctl daemon-reload
systemctl enable --now cron.service
systemctl enable monitor-bot-poll.service
if ((check_status == 12)); then run_check "$app_dir/deploy/server-check.php" switch; fi
systemctl restart monitor-bot-poll.service
systemctl is-active --quiet monitor-bot-poll.service || fail 'Polling service did not start. Check journalctl -u monitor-bot-poll.'
install -m 0644 "$source_dir/deploy/monitor-bot.cron" "$cron_file"
printf '%s\n' 'Monitor Bot is installed. Send /start in Telegram.' \
    'Polling logs: sudo journalctl -u monitor-bot-poll -n 50' \
    'Cron logs: sudo journalctl -t monitor-bot-cron -n 50'
