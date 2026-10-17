# 健康检查与 DNS

运行一个 systemd service。健康失败按固定类别记录，并按统一策略重试或退出。

## 故障类别

查看：`sudo bash ./deploy.sh logs` 或 `journalctl -u minirj.service -n 50 --no-pager`。

| reason | 含义 |
| --- | --- |
| `dns_failure` / `dns_timeout` | 域名解析失败 / 解析超时 |
| `connection_failed` / `connection_timeout` | TCP 建连失败 / 连接阶段超时 |
| `tls_timeout` / `tls_failed` / `tls_verification_failed` | TLS 握手超时 / 握手失败 / 证书或信任材料错误 |
| `transfer_timeout` / `transfer_failed` / `http_status` | 传输超时 / 传输失败 / HTTP 非 2xx、3xx |
| `source_mismatch` / `address_changed` / `address_unavailable` | 探测源地址不符 / 地址改变 / 地址或网关不可用 |
| `auth_stalled` / `auth_unavailable` / `phase2_unavailable` | 收包循环未推进 / 认证状态不可用 / 第二阶段不完整 |
| `reauth_timeout` / `reauth_probe_stale` | 重认证宽限用尽 / 探测被重认证暂态打断 |
| `health_cycle_timeout` | 健康周期预算耗尽 |
| `probe_execution` / `notify_failed` / `internal_error` | 探测执行错误 / systemd 通知错误 / 未分类异常 |

示例（合成数据，`192.0.2.53` 不可用于生产）：

```text
health retry: reason=dns_timeout stage=dns http=0 dns_s=0.000 tcp_s=0.000 tls_s=0.000 total_s=6.002 resolver_source=resolv.conf dns_servers=192.0.2.53 attempt=1; one retry pending
health failed: reason=dns_timeout stage=dns http=0 dns_s=0.000 tcp_s=0.000 tls_s=0.000 total_s=6.002 resolver_source=resolv.conf dns_servers=192.0.2.53 attempt=2; exiting for systemd restart
```

`dns_servers` 是 `/etc/resolv.conf` 中最多三个经地址校验的 nameserver。
`dns_s`、`tcp_s`、`tls_s`、`total_s` 是从请求开始累计的耗时。

手动 stop 不会触发 `Restart=always`。

## 重试策略

成功探测后等待 30 秒；DNS 与 TCP 连接各限制 6 秒，探测总时限 8 秒。
DNS、连接、握手超时和传输瞬态错误在等待 1 秒后复核一次；
复核成功才发 READY 或更新 watchdog，失败则退出，由 systemd 30 秒后重启。

其他错误直接退出：证书/信任错误、TLS 握手错误、HTTP 非 2xx/3xx、源地址错误、
认证或接口异常。复核前后重新检查认证状态、收包进度、地址和网关。

已完成双阶段认证并通过 HTTPS 的会话，遇到 `WAIT_MD5_REQ` / `WAIT_RESULT` 最多等待 15 秒。
等待期间不探测、不喂 watchdog；恢复 ONLINE 后重新探测。

健康周期预算 37 秒；加正常间隔共 67 秒，小于 90 秒 watchdog。
启动 75 秒、停止 20 秒的 systemd 时限。

## 配置 DNS

默认使用 DHCP DNS。指定外部 DNS：

```bash
sudo bash ./deploy.sh configure --dns "119.29.29.29,223.6.6.6"
```

`--dns` 接受 1–3 个不同的 IPv4 地址，逗号或空格分隔，允许私有校园地址。
该选项仅用于 `install` / `configure`，与 `--dns-auto` 互斥。
它先停服，再修改专用 NM UUID：`ipv4.ignore-auto-dns=yes`、手工 DNS 列表、
`ipv4.dns-options=timeout:1,attempts:2`。

恢复 DHCP DNS：

```bash
sudo bash ./deploy.sh configure --dns-auto
```

清空手工 DNS 与解析选项，恢复 `ipv4.ignore-auto-dns=no`。

未传 DNS 选项时，重装、升级、启动、重启和同接口配置保留已有 DNS。
`service.conf` 包含接口、UUID、HTTPS URL，以及可选的 `MINIRJ_EXTERNAL_DNS`。

参考：[resolv.conf](https://man7.org/linux/man-pages/man5/resolv.conf.5.html)、
[NetworkManager IPv4 DNS 配置](https://www.networkmanager.dev/docs/api/latest/settings-ipv4.html)。
