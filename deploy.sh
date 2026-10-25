#!/usr/bin/env bash
# Offline deployment / maintenance only. Never called by the running service.
set +x
set -Eeuo pipefail
umask 077
ulimit -c 0
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
unset PYTHONPATH PYTHONHOME LD_LIBRARY_PATH LD_PRELOAD

# Non-secret defaults; prefer command options so the delivered checksum stays valid.
INTERFACE=""                         # Required on first install: --interface enp1s0
PROBE_URL="https://www.baidu.com/"     # Override with --probe-url https://example.com/
ENABLE_ON_INSTALL=yes                 # --no-enable: start/observe, but do not enable

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
INSTALL_DIR=/opt/minirj
CONFIG_DIR=/etc/minirj
UNIT=minirj.service
UNIT_FILE=/etc/systemd/system/minirj.service
POLKIT_RULE=/etc/polkit-1/rules.d/50-minirj.rules
DISPATCHER_SCRIPT=/etc/NetworkManager/dispatcher.d/90-minirj-dhcp-policy
UNIT_DROPIN=/etc/systemd/system/minirj.service.d/10-root-fallback.conf
LOCK_FILE=/run/minirj-deploy.lock
PYTHON=/usr/bin/python3
SERVICE_USER=minirj
STOP_ON_FAILURE=0
UNDO_ENABLE=0
NEW_PROFILE=""
TEMP_DIR=""
TEMP_CONFIG=""
URL_GIVEN=0
INTERFACE_GIVEN=0
NO_ENABLE_GIVEN=0
DNS_MODE=""                          # Only explicit install/configure options change profile DNS.
DNS_SERVERS=""
IPV6_DISABLED=0

usage() {
    printf '%s\n' '用法: sudo bash deploy.sh <动作> [选项]
  install      离线从源码安装、配置、交互输入凭据、启动观察 70 秒，成功后启用自启
  upgrade      从源码重新安装配套文件，保留连接与凭据，再启动观察（也用于回退）
  configure    停服后修改接口/HTTPS URL/DNS，再启动观察；原专用连接保留为非活动状态
  credentials  停服后交互更新账号和密码，再启动观察
  start        使用现有安装/配置启动并观察（不安装、不运行测试）
  restart      停服后重新启动并观察
  stop         手动停服，不会被 Restart=always 拉起
  enable       启动观察通过后启用自启（不重装）
  disable      取消开机启动并立即停服
  status       查看状态、PID、重启次数
  logs         查看最近 50 条服务日志
  test         可选的已安装包单元自检（无认证，不需要 root）

选项（不接受账号/密码参数）:
  --interface IFACE   专用认证网卡；首次安装必须显式指定
  --probe-url URL     无内嵌账号密码的 HTTPS HEAD 地址
  --no-enable        仅用于 install，不主动启用开机自启
  --dns SERVERS      仅 install/configure；1..3 个不同的单播 IPv4，可用校园私网或公共开放 DNS
                     逗号或空格分隔，含空格时加引号；如 --dns "114.114.114.114,223.5.5.5"
                     忽略 DHCP DNS，设置 timeout:1,attempts:2；不修改全局解析器
  --external-dns SERVERS  同 --dns，指定外部开放 DNS 解析服务器
  --dns-auto         仅 install/configure；清空手动 DNS/选项并恢复 DHCP 自动 DNS
                     与 --dns 互斥，两个选项都不可重复
  -h, --help         显示帮助

未指定 DNS 选项时不修改已有专用 profile 的 DNS；install/upgrade/start/restart 均保留它。
configure 更换接口会新建默认 DHCP DNS 的 profile；需要手动 DNS 时须重新显式指定 --dns。
脚本不会提前激活 DHCP，仍由服务在 EAP phase 1 之后激活。
需事先离线准备 Python>=3.10、systemd>=247、NM internal DHCP 和 polkit。
先自行处理同网卡的其他认证客户端、激活 socket 和自动连接；脚本不会关闭它们。'
}
fail() { printf '错误：%s\n' "$*" >&2; exit 1; }
nm() { nmcli --wait 15 "$@"; }
cleanup() {
    local result=$?
    trap - EXIT
    if ((result != 0 && STOP_ON_FAILURE)); then
        systemctl stop "$UNIT" >/dev/null 2>&1 || printf '警告：停服失败，请立即手动检查。\n' >&2
        if ((UNDO_ENABLE)); then systemctl disable "$UNIT" >/dev/null 2>&1 || true; fi
        printf '操作失败，已请求停服；修复后可重新执行。未自动回退配置或已有 profile 的 DNS。\n' >&2
    fi
    [[ -z $TEMP_DIR ]] || rm -rf -- "$TEMP_DIR"
    [[ -z $TEMP_CONFIG ]] || rm -f -- "$TEMP_CONFIG"
    # Only undo a profile created by this invocation before config was committed.
    [[ -z $NEW_PROFILE ]] || nm connection delete uuid "$NEW_PROFILE" >/dev/null 2>&1 || true
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ACTION=${1:-help}
(($# == 0)) || shift
case "$ACTION" in help|-h|--help) usage; exit 0;; esac
while (($#)); do
    case "$1" in
        --interface|--probe-url)
            (($# >= 2)) || fail "$1 缺少值"
            case "$1" in
                --interface) INTERFACE=$2; INTERFACE_GIVEN=1;;
                --probe-url) PROBE_URL=$2; URL_GIVEN=1;;
            esac
            shift 2;;
        --no-enable) ENABLE_ON_INSTALL=no; NO_ENABLE_GIVEN=1; shift;;
        --no-ipv6) IPV6_DISABLED=1; shift;;
        --dns|--external-dns)
            (($# >= 2)) || fail "$1 缺少值"
            [[ -z $DNS_MODE ]] || fail '--dns/--dns-auto 互斥且不可重复'
            DNS_MODE=manual; DNS_SERVERS=$2; shift 2;;
        --dns-replace)
            DNS_POLICY=replace; shift;;
        --dns-append)
            DNS_POLICY=append; shift;;
        --dns-auto)
            [[ -z $DNS_MODE ]] || fail '--dns/--dns-auto 互斥且不可重复'
            DNS_MODE=auto; shift;;
        -h|--help) usage; exit 0;;
        *) fail "未知选项；运行 bash deploy.sh --help";;
    esac
done
case "$ACTION" in
    install|upgrade|configure|credentials|start|restart|stop|enable|disable|status|logs|test) ;;
    *) fail '未知动作；运行 bash deploy.sh --help';;
esac
((!INTERFACE_GIVEN)) || [[ $ACTION == install || $ACTION == configure ]] || fail '--interface 只用于 install/configure'
((!URL_GIVEN)) || [[ $ACTION == install || $ACTION == configure ]] || fail '--probe-url 只用于 install/configure'
((!NO_ENABLE_GIVEN)) || [[ $ACTION == install ]] || fail '--no-enable 只用于 install'
[[ -z $DNS_MODE || $ACTION == install || $ACTION == configure ]] || fail '--dns/--dns-auto 只用于 install/configure'
if [[ $DNS_MODE == manual ]]; then
    # Validate and canonicalize before locks, service stops, or any NM changes.
    # is_global would wrongly exclude campus/private resolvers; reject only non-unicast ranges.
    DNS_SERVERS=$(python3 -I -c '
import ipaddress,sys
try:
 parts=sys.argv[1].split(",")
 if any(not part.strip() for part in parts): raise ValueError()
 addresses=[ipaddress.IPv4Address(value) for part in parts for value in part.split()]
 if not 1 <= len(addresses) <= 3 or len(set(addresses)) != len(addresses): raise ValueError()
 zero_net=ipaddress.IPv4Network("0.0.0.0/8")
 if any(a in zero_net or a.is_unspecified or a.is_loopback or a.is_link_local
        or a.is_multicast or a.is_reserved for a in addresses): raise ValueError()
except ValueError:
 sys.exit(1)
print(" ".join(map(str,addresses)))
' "$DNS_SERVERS") || fail '--dns 必须是 1..3 个不同的单播 IPv4（逗号或空格分隔；不允许未指定、零网、环回、链路本地、组播、保留或广播地址）'
fi

if [[ $ACTION == test ]]; then
    [[ -x $PYTHON && -f $INSTALL_DIR/minirj.pyz && -d $ROOT/tests ]] || fail '需要已安装的 minirj.pyz 和配套 tests/；自检不是部署前置条件'
    TEMP_DIR=$(mktemp -d)
    "$PYTHON" -I -m zipfile -e "$INSTALL_DIR/minirj.pyz" "$TEMP_DIR"
    cd -- "$TEMP_DIR"
    "$PYTHON" -m unittest discover -s "$ROOT/tests"
    exit 0
fi
[[ $(id -u) == 0 ]] || fail '请使用 sudo bash deploy.sh ...'
command -v systemctl >/dev/null || fail '缺少 systemd；请提前提供离线系统依赖'
case "$ACTION" in
    status) systemctl show "$UNIT" -p MainPID -p NRestarts -p Result; systemctl status "$UNIT" --no-pager; exit $?;;
    logs) journalctl -u "$UNIT" -n 50 --no-pager; exit 0;;
esac
command -v flock >/dev/null || fail '缺少 flock（util-linux），请离线准备'
[[ ! -L $LOCK_FILE ]] || fail '部署锁不能是符号链接'
exec 9>>"$LOCK_FILE"
flock -n 9 || fail '已有部署/维护操作在进行'
case "$ACTION" in
    stop) systemctl stop "$UNIT"; exit 0;;
    disable) systemctl disable --now "$UNIT"; exit 0;;
esac

need_runtime() {
    local cmd version fragment dropins
    for cmd in python3 nmcli ip systemd-analyze systemd-ask-password sha256sum install mktemp useradd id; do
        command -v "$cmd" >/dev/null || fail "缺少系统组件 $cmd；请离线准备，不会自动下载"
    done
    "$PYTHON" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || fail '需要 Python>=3.10'
    version=$(systemctl --version); version=${version#systemd }; version=${version%% *}
    [[ $version =~ ^[0-9]+$ ]] && ((version >= 247)) || fail '需要 systemd>=247'
    POLKIT_AVAILABLE=0
    [[ -d /etc/polkit-1/rules.d ]] && POLKIT_AVAILABLE=1
    systemctl is-active --quiet NetworkManager.service || fail 'NetworkManager 未运行；不要盲目重启管理网络'
    # The generated config never contains commands and is never sourced as shell.
    fragment=$(systemctl show "$UNIT" -p FragmentPath --value)
    [[ -z $fragment || $fragment == "$UNIT_FILE" ]] || fail '同名 unit 来自其他位置，拒绝覆盖'
    dropins=$(systemctl show "$UNIT" -p DropInPaths --value)
    [[ -z $dropins || $dropins == "$UNIT_DROPIN" ]] || fail '同名 unit 有额外 drop-in，请先人工审查'
}
protected_directory() {
    [[ ! -L $CONFIG_DIR ]] || fail '配置目录不能是符号链接'
    if [[ -e $CONFIG_DIR ]]; then
        [[ -d $CONFIG_DIR && $(stat -c '%u:%a' "$CONFIG_DIR") == 0:700 ]] || fail '配置目录须由 root 拥有且权限为 700'
    fi
}
load_config() {
    local line key value
    local -A seen=()
    [[ -f $CONFIG_DIR/service.conf && ! -L $CONFIG_DIR/service.conf ]] || fail '缺少配置；先执行 install'
    OLD_INTERFACE= OLD_UUID= OLD_URL= OLD_DNS=
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -n $line && $line != \#* ]] || continue
        [[ $line == *=* ]] || fail '配置格式错误；不要在 service.conf 中写 shell 命令'
        key=${line%%=*}; value=${line#*=}
        case "$key" in
            MINIRJ_INTERFACE) OLD_INTERFACE=$value;;
            MINIRJ_NM_UUID) OLD_UUID=$value;;
            MINIRJ_PROBE_URL) OLD_URL=$value;;
            MINIRJ_EXTERNAL_DNS) OLD_DNS=$value;;
            *) fail '配置含未知字段；应只有 MINIRJ_INTERFACE/MINIRJ_NM_UUID/MINIRJ_PROBE_URL/MINIRJ_EXTERNAL_DNS';;
        esac
        [[ -z ${seen[$key]:-} ]] || fail '配置含重复字段'
        seen[$key]=1
    done < "$CONFIG_DIR/service.conf"
    [[ -n $OLD_INTERFACE && -n $OLD_UUID && -n $OLD_URL ]] || fail '配置缺项'
    validate_settings "$OLD_INTERFACE" "$OLD_URL"
    python3 -I -c 'import sys,uuid; uuid.UUID(sys.argv[1])' "$OLD_UUID" 2>/dev/null || fail '配置 UUID 无效'
}
validate_settings() {
    # Restrict to plain EnvironmentFile values; no shell sourcing/escaping needed.
    [[ $1 =~ ^[a-zA-Z0-9_.:-]+$ && ${#1} -lt 16 && $1 != lo ]] || fail '认证接口名称无效'
    python3 -I -c '
import sys
from urllib.parse import urlsplit
s=sys.argv[1]
try:
 p=urlsplit(s)
 ok=(p.scheme=="https" and bool(p.hostname) and p.username is None and p.password is None
     and not any(c.isspace() or c in "\x00\x27\x22\\" for c in s))
except ValueError: ok=False
sys.exit(0 if ok else 1)
' "$2" || fail '探测 URL 必须是无账号密码、空白、引号或反斜杠的 HTTPS 地址'
}
check_interface() {
    local iface=$1 uuid=${2:-} active route peer
    [[ $(nm -g GENERAL.NM-MANAGED device show "$iface") == yes ]] || fail '接口不存在或不由 NetworkManager 管理'
    peer=${SSH_CONNECTION:-${SSH_CLIENT:-}}; peer=${peer%% *}
    if [[ -n $peer ]]; then
        route=$(ip -j route get "$peer")
        python3 -I -c 'import json,sys; sys.exit(1 if any(r.get("dev")==sys.argv[1] for r in json.load(sys.stdin)) else 0)' "$iface" <<<"$route" || fail '该接口承载当前 SSH 管理路径，拒绝操作'
    fi
    active=$(nm -g GENERAL.CON-UUID device show "$iface")
    [[ -z $active || $active == -- || ( -n $uuid && $active == "$uuid" ) ]] || fail '其他 NM 连接正在占用该接口；脚本不会替你断开'
    if [[ -z $active || $active == -- ]]; then
        ip -j addr show dev "$iface" | python3 -I -c '
import json,sys
sys.exit(1 if any(a.get("scope")=="global" for d in json.load(sys.stdin) for a in d.get("addr_info",[])) else 0)
' || fail '无所属连接但接口已有全局地址，拒绝接管'
    fi
}
check_profile() {
    local properties
    properties=$(nm -g connection.interface-name,connection.autoconnect,ipv4.method connection show uuid "$2")
    [[ $properties == "$1"$'\nno\nauto' ]] || fail '必须复用接口匹配、autoconnect=no、ipv4.method=auto 的专用 profile'
    check_interface "$1" "$2"
}
stop_before_change() {
    STOP_ON_FAILURE=1
    if [[ $(systemctl show "$UNIT" -p LoadState --value) != not-found ]]; then
        systemctl stop "$UNIT"  # Stop hooks must still see the OLD config/UUID.
    fi
}
verify_source() {
    [[ -d $ROOT/minirj && -f $ROOT/minirj/main.py ]] || fail '未找到源码目录 minirj'
    [[ -f $ROOT/deploy/build_zipapp.py && -f $ROOT/deploy/zipapp_main.py ]] || fail '缺少 zipapp 构建文件'
    [[ -f $ROOT/deploy/systemd/$UNIT && -f $ROOT/deploy/systemd/50-minirj.rules ]] || fail '缺少配套 deploy/systemd/ 文件'
    [[ -f $ROOT/deploy/network-manager/90-minirj-dhcp-policy ]] || fail '缺少 deploy/network-manager/90-minirj-dhcp-policy'
    printf '使用源码目录：%s\n' "$ROOT"
}
install_files() {
    [[ ! -L $INSTALL_DIR ]] || fail '安装目录不能是符号链接'
    [[ ! -L $INSTALL_DIR/minirj.pyz ]] || fail '安装目标不能是符号链接'
    id -u "$SERVICE_USER" >/dev/null 2>&1 \
        || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    install -d -m 755 "$INSTALL_DIR"
    "$PYTHON" -I "$ROOT/deploy/build_zipapp.py" \
        --source "$ROOT/minirj" --entry "$ROOT/deploy/zipapp_main.py" \
        --output "$INSTALL_DIR/minirj.pyz"
    chmod 755 "$INSTALL_DIR/minirj.pyz"
    install -m 644 "$ROOT/deploy/systemd/$UNIT" "$UNIT_FILE"
    install -D -m 755 "$ROOT/deploy/network-manager/90-minirj-dhcp-policy" "$DISPATCHER_SCRIPT"
    if ((POLKIT_AVAILABLE)); then
        install -m 644 "$ROOT/deploy/systemd/50-minirj.rules" "$POLKIT_RULE"
        rm -f "$UNIT_DROPIN"
        rmdir --ignore-fail-on-non-empty /etc/systemd/system/minirj.service.d 2>/dev/null || true
    else
        install -d -m 755 /etc/systemd/system/minirj.service.d
        printf '[Service]\nUser=root\nGroup=root\nCapabilityBoundingSet=CAP_NET_RAW CAP_SYS_PTRACE\nAmbientCapabilities=CAP_NET_RAW CAP_SYS_PTRACE\n' > "$UNIT_DROPIN"
        chmod 644 "$UNIT_DROPIN"
    fi
    "$PYTHON" -I "$INSTALL_DIR/minirj.pyz" --version
}
write_config() {
    install -d -m 700 "$CONFIG_DIR"
    TEMP_CONFIG=$(mktemp "$CONFIG_DIR/.service.conf.XXXXXXXX")
    printf 'MINIRJ_INTERFACE=%s\nMINIRJ_NM_UUID=%s\nMINIRJ_PROBE_URL=%s\n' "$INTERFACE" "$UUID" "$PROBE_URL" > "$TEMP_CONFIG"
    local TARGET_DNS=""
    if [[ $DNS_MODE == manual && -n $DNS_SERVERS ]]; then
        TARGET_DNS=$DNS_SERVERS
    elif [[ $DNS_MODE == auto ]]; then
        TARGET_DNS=""
    elif [[ -n ${OLD_DNS:-} ]]; then
        TARGET_DNS=$OLD_DNS
    fi
    if [[ -n $TARGET_DNS ]]; then
        printf 'MINIRJ_EXTERNAL_DNS=%s\n' "$TARGET_DNS" >> "$TEMP_CONFIG"
    fi
    chmod 600 "$TEMP_CONFIG"
    mv -f -- "$TEMP_CONFIG" "$CONFIG_DIR/service.conf"
    TEMP_CONFIG= NEW_PROFILE=
}
create_profile() {
    UUID=$(python3 -I -c 'import uuid; print(uuid.uuid4())')
    NEW_PROFILE=$UUID
    local V6_METHOD="auto"
    if ((IPV6_DISABLED)); then
        V6_METHOD="disabled"
    fi
    nm connection add type ethernet ifname "$INTERFACE" con-name minirj \
        connection.uuid "$UUID" connection.autoconnect no \
        connection.permissions "user:$SERVICE_USER" \
        802-3-ethernet.cloned-mac-address preserve ipv4.method auto \
        ipv4.dhcp-client-id mac ipv4.dhcp-send-release yes ipv4.route-metric 600 ipv6.method "$V6_METHOD" >/dev/null
    # No connection up here: only the service activates DHCP after EAP phase 1.
}
ensure_permissions() {
    nm connection modify uuid "$1" connection.permissions "user:$SERVICE_USER"
}
apply_dns() {
    [[ -n $DNS_MODE ]] || return 0  # Preserve existing DNS unless explicitly requested.
    # Revalidate our selected UUID after stopping the OLD config and, if needed, creating it.
    check_profile "$INTERFACE" "$UUID"
    case "$DNS_MODE" in
        manual)
            local IGNORE="yes"
            if [[ ${DNS_POLICY:-} == append ]]; then
                IGNORE="no"
            fi
            nm connection modify uuid "$UUID" ipv4.ignore-auto-dns "$IGNORE" \
                ipv4.dns "$DNS_SERVERS" ipv4.dns-options 'timeout:1,attempts:2';;
        auto)
            nm connection modify uuid "$UUID" ipv4.ignore-auto-dns no \
                ipv4.dns "" ipv4.dns-options "";;
    esac
}
validate_credentials() {
    python3 -I -c '
from pathlib import Path
import sys
try:
 for name in ("username","password"):
  v=(Path(sys.argv[1])/name).read_text(encoding="utf-8")
  v=v[:-2] if v.endswith("\r\n") else v.removesuffix("\n")
  if not v or any(c in v for c in "\r\n\0"): raise ValueError()
except (OSError,UnicodeError,ValueError):
 raise SystemExit("凭据必须是非空 UTF-8 单行文本；内容不予输出")
' "$1"
}
ask_credentials() {
    install -d -m 700 "$CONFIG_DIR"
    TEMP_DIR=$(mktemp -d "$CONFIG_DIR/.credentials.XXXXXXXX")
    systemd-ask-password 'Campus username:' > "$TEMP_DIR/username"
    systemd-ask-password 'Campus password:' > "$TEMP_DIR/password"
    validate_credentials "$TEMP_DIR"
    chmod 600 "$TEMP_DIR/username" "$TEMP_DIR/password"
    mv -f -- "$TEMP_DIR/username" "$CONFIG_DIR/username"
    mv -f -- "$TEMP_DIR/password" "$CONFIG_DIR/password"
    rmdir -- "$TEMP_DIR"; TEMP_DIR=
}
check_credentials() {
    local name
    for name in username password; do
        [[ -f $CONFIG_DIR/$name && ! -L $CONFIG_DIR/$name && $(stat -c '%u:%a' "$CONFIG_DIR/$name") == 0:600 ]] || fail '凭据文件须为 root:600 的普通文件；用 credentials 更新'
    done
    validate_credentials "$CONFIG_DIR"
}
start_checked() {
    load_config
    check_profile "$OLD_INTERFACE" "$OLD_UUID"
    check_credentials
    [[ -x $PYTHON && -f $INSTALL_DIR/minirj.pyz && -f $UNIT_FILE ]] || fail '尚未完整安装'
    STOP_ON_FAILURE=1
    systemctl daemon-reload
    systemd-analyze verify "$UNIT_FILE"
    systemctl start "$UNIT"
    local invocation
    invocation=$(systemctl show "$UNIT" -p InvocationID --value)
    [[ -n $invocation && $(systemctl show "$UNIT" -p StatusText --value) == 'Online; bound HTTPS check passed' ]] || fail '未收到认证和绑定 HTTPS 检查的就绪状态'
    printf '已就绪；观察 70 秒，失败会停服……\n'
    sleep 70
    systemctl is-active --quiet "$UNIT"
    [[ $invocation == "$(systemctl show "$UNIT" -p InvocationID --value)" ]] || fail '观察期间发生了重启'
    journalctl "_SYSTEMD_INVOCATION_ID=$invocation" -n 30 --no-pager
    if [[ $ACTION == enable || ( $ACTION == install && $ENABLE_ON_INSTALL == yes ) ]]; then
        if ! systemctl is-enabled --quiet "$UNIT"; then UNDO_ENABLE=1; fi
        systemctl enable "$UNIT"
        systemctl is-enabled --quiet "$UNIT"
        UNDO_ENABLE=0
    fi
    STOP_ON_FAILURE=0
    printf '启动观察通过。手动停服用：sudo bash deploy.sh stop\n'
}

need_runtime
protected_directory
case "$ACTION" in
    install|upgrade)
        if [[ $ACTION == upgrade ]]; then INTERFACE=; fi
        verify_source  # Hash/path failures must not stop an existing healthy service.
        if [[ -e $CONFIG_DIR/service.conf ]]; then
            load_config
            [[ -z $INTERFACE || $INTERFACE == "$OLD_INTERFACE" ]] || fail '修改网卡请使用 configure；install 不重复创建连接'
            INTERFACE=$OLD_INTERFACE; UUID=$OLD_UUID
            ((URL_GIVEN)) || PROBE_URL=$OLD_URL
            check_profile "$INTERFACE" "$UUID"
        else
            [[ $ACTION == install && -n $INTERFACE ]] || fail '首次安装必须用 install --interface 专用网卡'
            UUID=
            validate_settings "$INTERFACE" "$PROBE_URL"
            check_interface "$INTERFACE"
        fi
        validate_settings "$INTERFACE" "$PROBE_URL"
        stop_before_change
        install_files
        if [[ -z $UUID ]]; then create_profile; fi
        ensure_permissions "$UUID"
        apply_dns
        write_config
        if [[ ! -f $CONFIG_DIR/username || ! -f $CONFIG_DIR/password ]]; then ask_credentials; fi
        start_checked;;
    configure)
        load_config
        check_profile "$OLD_INTERFACE" "$OLD_UUID"
        INTERFACE=${INTERFACE:-$OLD_INTERFACE}
        ((URL_GIVEN)) || PROBE_URL=$OLD_URL
        validate_settings "$INTERFACE" "$PROBE_URL"
        UUID=$OLD_UUID
        if [[ $INTERFACE != "$OLD_INTERFACE" ]]; then check_interface "$INTERFACE"; UUID=; fi
        stop_before_change
        if [[ -z $UUID ]]; then create_profile; fi
        ensure_permissions "$UUID"
        apply_dns
        write_config
        start_checked;;
    credentials)
        load_config; check_profile "$OLD_INTERFACE" "$OLD_UUID"
        stop_before_change
        ask_credentials
        start_checked;;
    restart)
        load_config; check_profile "$OLD_INTERFACE" "$OLD_UUID"
        stop_before_change
        start_checked;;
    start|enable) start_checked;;
esac
