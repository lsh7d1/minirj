# NetworkManager dispatcher 部署说明

`90-minirj-dhcp-policy` 由根目录 [deploy.sh](../../deploy.sh) 的 install/upgrade
安装为 `/etc/NetworkManager/dispatcher.d/90-minirj-dhcp-policy`（root:root 0755），
是 nft 表 `ip minirj_dhcp_policy` 的唯一写入者。运行依赖 nftables。

## 机制

只在拿到公网 IPv4 租约的接口上生效；RFC 1918、`100.64.0.0/10`、`169.254.0.0/16`、
环回/零网、组播及以上均视为内网，此时删除表、不阻断。生效时：

- 从 `/etc/minirj/service.conf` 读取 `MINIRJ_INTERFACE` / `MINIRJ_NM_UUID`，
  用 `nmcli -g DHCP4.OPTION connection show uuid` 动态解析租约 IP 与 DHCP server-id；
- set `blocked_renew` 只绑定 `(租约 IP . server-id)` 二元组；
- OUTPUT 链仅丢弃 `oifname <接口> udp sport 68 dport 67` 且地址对命中集合、
  DHCP Magic Cookie（`@th,1952,32 0x63825363`，UDP 头后第 244 字节）与
  Option 53 = DHCPREQUEST（`@th,1984,24 0x350103`，选项 53/长度 1/类型 3）的包；
- DHCPRELEASE（Option 53 = 7）和广播 Discover/Rebind 不命中规则，保持放行；
- 表更新为整体 delete+create 的原子替换，不触碰 FORWARD/POSTROUTING，
  也不影响主机上其他 nft 表。

字节偏移假设 NM internal DHCP（n-dhcp4）的标准 BOOTP 布局；NetworkManager 升级后
如行为异常，用 `--clear` 清表并复核偏移。

## 触发时机

- NM dispatcher 事件：`up` / `dhcp4-change` / `reapply` 重读租约并同步表，
  `down` 删除表；其他接口或其他动作直接退出。
- 并发经 `/run/lock/minirj-dhcp-policy.lock` 串行化。
- 手动操作：`sudo /etc/NetworkManager/dispatcher.d/90-minirj-dhcp-policy --sync` 重建，
  `--clear` 删除。回滚只需删表：`nft delete table ip minirj_dhcp_policy`。

背景：校园 DHCP 对 T1 单播续租一律回 NAK 且 NM（connected socket）收不到跨源 NAK，
部分租约会因此被提前吊销。阻断单播 REQUEST 让续租推迟到 T2 广播 Rebind，
由 NM 正常换租约；服务侧在 `service.py` 原地接受新地址并复核。
