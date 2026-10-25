# systemd 部署说明

部署、启动、自启和维护使用根目录的 [deploy.sh](../../deploy.sh)，命令见 [README](../../README.md)。

本目录包含 `minirj.service`、polkit 规则和非敏感配置示例。
`deploy.sh` 用于人工安装/维护。运行依赖 NetworkManager、polkit 和 nftables
（dispatcher 阻断规则，见 [deploy/network-manager](../network-manager/README.md)）。
服务以用户 `minirj` 运行，仅保留 `CAP_NET_RAW`；无权限读取的其他用户进程在竞品扫描中跳过。
主机没有 polkit 时，`deploy.sh` 会安装 `10-root-fallback.conf` drop-in，
以 root 运行（`CAP_NET_RAW` + `CAP_SYS_PTRACE`）并保持其余加固项。

## 恢复策略

- 一个认证会话；认证失败、程序异常或健康检查失败时退出，systemd 30 秒后重启。
- 成功后等待 30 秒再做 HTTPS HEAD：绑定认证接口和源 IPv4，校验证书，要求 2xx/3xx。
- DNS 与 TCP 连接各限制 6 秒，探测总时限 8 秒；瞬态失败等待 1 秒后最多复核 1 次。
- 已认证会话遇到 `WAIT_MD5_REQ` / `WAIT_RESULT` 最多等待 15 秒，新请求不延长；
  等待期间不喂 watchdog。
- 健康周期预算 37 秒；加 30 秒间隔小于 90 秒 watchdog。
- 第二轮认证和健康检查成功后发 READY；启动 75 秒未就绪由 systemd 终止。
- 收包循环停止推进或健康线程失效时停止喂 watchdog；`WatchdogSec=90s` 兜底，
  停止阶段超时 20 秒。
- 启动前和停止后只关闭指定 NM profile；重启重新认证、重新获取 DHCP。
- `Restart=always`；手动 stop 不重启。

## 文件

| 位置 | 用途 |
| --- | --- |
| `/opt/minirj/minirj.pyz` | 运行入口（源码与资产） |
| `/etc/systemd/system/minirj.service` | 自定义 unit |
| `/etc/polkit-1/rules.d/50-minirj.rules` | 允许 `minirj` 激活/停用 NM profile |
| `/etc/NetworkManager/dispatcher.d/90-minirj-dhcp-policy` | 公网租约下阻断 T1 DHCP 单播续租 |
| `/etc/minirj/service.conf` | 接口、NM UUID、HTTPS 探测 URL |
| `/etc/minirj/username`、`password` | 凭据，通过 `LoadCredential` 读取 |

只操作接口匹配、`autoconnect=no`、`ipv4.method=auto`、`connection.permissions=user:minirj`
的专用 profile。第一轮 Success 后调用 `nmcli connection up`，由 NM internal DHCP 管理租约。
修改 UUID/接口前先停服务。

凭据不进入 argv 或 EnvironmentFile。
日志包含固定错误类别、HTTP/TLS 数值和分阶段耗时。
详见 [健康检查与 DNS](../../docs/HEALTH_AND_DNS.md)。
