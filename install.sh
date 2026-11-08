#!/usr/bin/env bash
set -euo pipefail
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="/opt/pve-nic-shaper"

if [[ $EUID -ne 0 ]]; then echo "请使用 root 执行：bash install.sh" >&2; exit 1; fi
for file in backend/app.py frontend/index.html systemd/pve-nic-shaper.service; do
  [[ -f "$SOURCE_DIR/$file" ]] || { echo "缺少文件：$SOURCE_DIR/$file" >&2; exit 1; }
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3-flask iproute2 openssl
install -d -m 0755 "$APP_DIR/backend" "$APP_DIR/frontend"
install -m 0755 "$SOURCE_DIR/backend/app.py" "$APP_DIR/backend/app.py"
install -m 0644 "$SOURCE_DIR/frontend/index.html" "$APP_DIR/frontend/index.html"
install -m 0644 "$SOURCE_DIR/systemd/pve-nic-shaper.service" /etc/systemd/system/pve-nic-shaper.service
install -d -m 0700 /etc/pve-nic-shaper
if [[ ! -s /etc/pve-nic-shaper/token ]]; then umask 077; openssl rand -hex 32 > /etc/pve-nic-shaper/token; fi
chmod 0600 /etc/pve-nic-shaper/token
systemctl daemon-reload
systemctl enable --now pve-nic-shaper

echo
echo "安装完成。请保存下方访问令牌："
cat /etc/pve-nic-shaper/token
echo
echo "服务仅监听 127.0.0.1:8765。远程访问请在管理电脑运行："
echo "  ssh -L 8765:127.0.0.1:8765 root@PVE节点地址"
echo "然后访问 http://127.0.0.1:8765"
echo "日志：journalctl -u pve-nic-shaper -f"
