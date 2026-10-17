# MiniRJ

Linux 上的锐捷 802.1X/EAP-MD5 客户端，以单个 systemd service 维持认证会话。

## 工作方式

- `minirj.service` 以专用用户 `minirj` 运行 `/opt/minirj/minirj.pyz`。
- 认证分两阶段：
  1. Ruijie Start → EAP-Identity → EAP-MD5 → EAP-Success。第一阶段成功后激活专用
     NetworkManager profile，由 NM internal DHCP 获取地址。
  2. IP 与网关就绪后重新发起认证，成功后进入 ONLINE。
- ONLINE 后每 30 秒用 Python 标准库绑定认证接口和源 IPv4，执行一次 HTTPS HEAD；
  失败即退出，systemd 30 秒后重启。
- `deploy.sh` 用标准库 `zipapp` 把源码和资产打包为单个 `minirj.pyz`，安装到 `/opt/minirj`。

## 依赖

- Linux、Bash >=4、root/sudo、coreutils、iproute2、util-linux（`flock`）。
- Python >=3.10。
- systemd >=247。
- NetworkManager，使用 internal DHCP。
- polkit（运行用户激活 NM profile）。
- 一块专用认证网卡。

部署期使用 root；运行时仅需 `CAP_NET_RAW`。

## 部署

```bash
sudo bash ./deploy.sh install --interface enp1s0
```

安装流程：

1. 检查系统依赖。
2. 停止旧服务，创建系统用户 `minirj`，构建并安装 `minirj.pyz`。
3. 安装 unit 与 polkit 规则。
4. 创建专用 NM profile（`autoconnect=no`、`ipv4.method=auto`、
   `connection.permissions=user:minirj`），保存 UUID。
5. 交互输入账号密码，保存到 `/etc/minirj/`。
6. 启动并等待双阶段认证、DHCP、绑定 HTTPS 检查就绪，观察 70 秒。
7. 通过后启用开机自启。

参数：

| 参数 | 用途 |
| --- | --- |
| `--probe-url https://example.com/` | HTTPS HEAD 探测地址 |
| `--no-enable` | 不启用开机自启 |
| `--dns, --external-dns "IPv4,IPv4"` | 1–3 个外部 DNS，追加至 DHCP DNS |
| `--dns-replace` | 仅使用指定 DNS |
| `--dns-auto` | 恢复 DHCP DNS |

配置：`/etc/minirj/service.conf`（接口、NM UUID、探测 URL）。
凭据：`/etc/minirj/username`、`/etc/minirj/password`，由 `LoadCredential` 读取。

## 维护

| 操作 | 命令 |
| --- | --- |
| 状态 | `sudo bash ./deploy.sh status` |
| 日志 | `sudo bash ./deploy.sh logs` |
| 启动并观察 70 秒 | `sudo bash ./deploy.sh start` |
| 重启并观察 | `sudo bash ./deploy.sh restart` |
| 停止 | `sudo bash ./deploy.sh stop` |
| 启用自启 | `sudo bash ./deploy.sh enable` |
| 取消自启 | `sudo bash ./deploy.sh disable` |
| 修改凭据 | `sudo bash ./deploy.sh credentials` |
| 修改探测地址 | `sudo bash ./deploy.sh configure --probe-url https://example.com/` |
| 更换网卡 | `sudo bash ./deploy.sh configure --interface enp2s0` |
| 设置 DNS | `sudo bash ./deploy.sh configure --dns "119.29.29.29,223.6.6.6"` |
| 恢复 DHCP DNS | `sudo bash ./deploy.sh configure --dns-auto` |
| 已安装包自检 | `bash ./deploy.sh test` |
| 升级 | `sudo bash ./deploy.sh upgrade` |

CLI：`/usr/bin/python3 /opt/minirj/minirj.pyz --help`；模块入口 `python -m minirj.main`。

健康检查与 DNS：[HEALTH_AND_DNS](docs/HEALTH_AND_DNS.md)。
发布与交付：[RELEASING](docs/RELEASING.md)。
