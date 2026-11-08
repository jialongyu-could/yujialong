# PVE NIC Shaper（独立管理页面）

独立于 PVE Web UI 的本地网卡流量监控与定时限速页面。左侧导航显示“网卡限速”；本项目**不会修改或注入 PVE 原生侧边栏**。

## 功能

- 展示节点网卡收发实时速率（每 2 秒采样刷新）。
- 按网卡、方向、星期、起止时间和 Mbps 添加限速规则。
- 支持跨午夜时间段；同一网卡/方向同时命中多条规则时取较低速率。
- SQLite 保存规则，服务启动时重新协调限速状态。
- API 只监听 `127.0.0.1:8765`，使用随机 bearer token；远程访问通过 SSH 隧道。
- 上传使用 `tc` HTB；下载使用 ingress policing，超额流量会丢弃。

## 安装

把项目放到 PVE 9.2 节点后，以 root 在项目目录执行：

```bash
bash install.sh
```

安装完成时会打印访问令牌，请妥善保存。页面在节点本机可访问：`http://127.0.0.1:8765`。远程管理电脑建立 SSH 隧道：

```bash
ssh -L 8765:127.0.0.1:8765 root@PVE节点地址
```

随后访问 `http://127.0.0.1:8765` 并输入令牌。查看日志：

```bash
journalctl -u pve-nic-shaper -f
```

## 安全与网络影响

- 本项目是节点级独立管理工具，不是 Proxmox 官方插件，也不会出现在 PVE 原生 UI 侧边栏。
- 需要 root 和 `CAP_NET_ADMIN` 才能配置 `tc`。不要将服务端口代理到公网，也不要关闭访问令牌。
- 上传限速只会创建/修改本项目专用的 HTB 根队列；发现已有根 qdisc 时拒绝覆盖。
- 下载限速通过 ingress policing 丢弃超额流量，可能增加丢包；已有 ingress/流控配置时应先在测试节点验证兼容性。
- 对管理网卡限速可能中断 SSH、Web UI 或集群通信。先使用测试节点或非管理网卡，并准备带外控制台。
- 每个集群节点需要单独安装；规则保存在本机，不会自动跨节点同步。

## 移除

先删除规则并确认限速已解除，再执行：

```bash
systemctl disable --now pve-nic-shaper
rm -f /etc/systemd/system/pve-nic-shaper.service
systemctl daemon-reload
```

数据库和 token 保留在 `/opt/pve-nic-shaper/rules.db`、`/etc/pve-nic-shaper/token`；确认不再需要后再手动删除。
