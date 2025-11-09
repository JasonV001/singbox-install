#!/bin/bash

# SingBox 一键安装脚本 v1.4
# 作者: sd87671067 | 博客: https://dlmn.lol

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

show_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'BANNER'
╔════════════════════════════════════════════════╗
║       SingBox 一键安装脚本 v1.4               ║
║       作者: sd87671067                         ║
║       博客: https://dlmn.lol                   ║
╚════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
}

[[ $EUID -ne 0 ]] && { print_error "需要 root 权限"; exit 1; }

SERVER_IP=$(curl -s4m8 ip.sb 2>/dev/null || curl -s6m8 ip.sb 2>/dev/null)
[ -z "$SERVER_IP" ] && { print_error "无法获取 IP"; exit 1; }

# 安装依赖
if ! command -v sing-box &> /dev/null; then
    print_info "安装 sing-box..."
    apt update -y > /dev/null 2>&1
    apt install -y curl wget tar gzip qrencode openssl > /dev/null 2>&1
    
    ARCH=$(dpkg --print-architecture)
    VER=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d'"' -f4 | sed 's/v//')
    
    wget -q -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${VER}/sing-box-${VER}-linux-${ARCH}.tar.gz"
    tar -xzf /tmp/sb.tar.gz -C /tmp
    cp /tmp/sing-box-${VER}-linux-${ARCH}/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    cat > /etc/systemd/system/sing-box.service << 'SVC'
[Unit]
Description=sing-box
After=network.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
SVC
    systemctl daemon-reload
    rm -rf /tmp/sing-box* /tmp/sb.tar.gz
fi

# Reality
setup_reality() {
    UUID=$(sing-box generate uuid)
    KEYS=$(sing-box generate reality-keypair)
    PRIV=$(echo "$KEYS" | grep PrivateKey | awk '{print $2}')
    PUB=$(echo "$KEYS" | grep PublicKey | awk '{print $2}')
    
    read -p "端口 [443]: " PORT
    PORT=${PORT:-443}
    
    SNI="itunes.apple.com"
    SID=$(openssl rand -hex 8)
    
    mkdir -p /etc/sing-box
    cat > /etc/sing-box/config.json << CONF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "vless",
    "listen": "::",
    "listen_port": ${PORT},
    "users": [{"uuid": "${UUID}", "flow": "xtls-rprx-vision"}],
    "tls": {
      "enabled": true,
      "server_name": "${SNI}",
      "reality": {
        "enabled": true,
        "handshake": {"server": "${SNI}", "server_port": 443},
        "private_key": "${PRIV}",
        "short_id": ["${SID}"]
      }
    }
  }],
  "outbounds": [{"type": "direct"}]
}
CONF
    
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp#Reality|dlmn.lol"
    PROTO="Reality"
}

# Hysteria2
setup_hysteria2() {
    PASS=$(openssl rand -base64 32)
    
    read -p "端口 [443]: " PORT
    PORT=${PORT:-443}
    
    mkdir -p /etc/sing-box/certs
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout /etc/sing-box/certs/key.pem \
        -out /etc/sing-box/certs/cert.pem \
        -subj "/CN=bing.com" -days 36500 > /dev/null 2>&1
    
    cat > /etc/sing-box/config.json << CONF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "hysteria2",
    "listen": "::",
    "listen_port": ${PORT},
    "users": [{"password": "${PASS}"}],
    "tls": {
      "enabled": true,
      "server_name": "bing.com",
      "key_path": "/etc/sing-box/certs/key.pem",
      "certificate_path": "/etc/sing-box/certs/cert.pem"
    }
  }],
  "outbounds": [{"type": "direct"}]
}
CONF
    
    LINK="hysteria2://${PASS}@${SERVER_IP}:${PORT}?sni=bing.com&insecure=1#Hysteria2|dlmn.lol"
    PROTO="Hysteria2"
    INFO="密码: ${PASS}"
}

# ShadowTLS
setup_shadowtls() {
    PASS=$(openssl rand -base64 32)
    
    read -p "端口 [443]: " PORT
    PORT=${PORT:-443}
    
    cat > /etc/sing-box/config.json << CONF
{
  "log": {"level": "info"},
  "inbounds": [
    {
      "type": "shadowtls",
      "listen": "::",
      "listen_port": ${PORT},
      "version": 3,
      "users": [{"password": "${PASS}"}],
      "handshake": {"server": "cloud.tencent.com", "server_port": 443},
      "detour": "ss"
    },
    {
      "type": "shadowsocks",
      "tag": "ss",
      "listen": "127.0.0.1",
      "method": "2022-blake3-aes-128-gcm",
      "password": "${PASS}"
    }
  ],
  "outbounds": [{"type": "direct"}]
}
CONF
    
    B64=$(echo -n "2022-blake3-aes-128-gcm:${PASS}" | base64 -w 0)
    LINK="ss://${B64}@${SERVER_IP}:${PORT}#ShadowTLS|dlmn.lol"
    PROTO="ShadowTLS"
    INFO="密码: ${PASS}"
}

# SOCKS5
setup_socks5() {
    USER="user"
    PASS=$(openssl rand -base64 16)
    
    read -p "端口 [1080]: " PORT
    PORT=${PORT:-1080}
    
    cat > /etc/sing-box/config.json << CONF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "socks",
    "listen": "::",
    "listen_port": ${PORT},
    "users": [{"username": "${USER}", "password": "${PASS}"}]
  }],
  "outbounds": [{"type": "direct"}]
}
CONF
    
    LINK="socks://${USER}:${PASS}@${SERVER_IP}:${PORT}#SOCKS5|dlmn.lol"
    PROTO="SOCKS5"
    INFO="用户: ${USER} | 密码: ${PASS}"
}

# 主程序
show_banner
echo "选择协议:"
echo "  1) Reality"
echo "  2) Hysteria2"
echo "  3) ShadowTLS v3"
echo "  4) SOCKS5"
echo ""
read -p "选择 [1-4]: " choice

case $choice in
    1) setup_reality ;;
    2) setup_hysteria2 ;;
    3) setup_shadowtls ;;
    4) setup_socks5 ;;
    *) print_error "无效选择"; exit 1 ;;
esac

print_success "配置已生成"

systemctl enable sing-box > /dev/null 2>&1
systemctl restart sing-box
sleep 2

if systemctl is-active --quiet sing-box; then
    print_success "服务启动成功"
else
    print_error "启动失败"
    journalctl -u sing-box -n 10 --no-pager
    exit 1
fi

# 防火墙
command -v ufw &> /dev/null && ufw allow ${PORT}/tcp > /dev/null 2>&1
command -v ufw &> /dev/null && ufw allow ${PORT}/udp > /dev/null 2>&1

# 显示结果
clear
echo -e "\n${CYAN}╔═══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   🎉 安装完成 | dlmn.lol          ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}\n"
echo -e "${GREEN}协议: ${PROTO}${NC}"
echo -e "${GREEN}端口: ${PORT}${NC}"
[ -n "$INFO" ] && echo -e "${GREEN}${INFO}${NC}"
echo -e "\n${YELLOW}${LINK}${NC}\n"

command -v qrencode &> /dev/null && qrencode -t ANSIUTF8 -s 1 -m 1 "${LINK}"

echo -e "\n${PURPLE}更多工具: https://dlmn.lol${NC}\n"
