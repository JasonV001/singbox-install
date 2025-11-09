#!/bin/bash

# ==========================================
# SingBox 一键安装配置脚本
# 作者: sd87671067
# 博客: https://dlmn.lol
# ==========================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║       SingBox 一键安装脚本 v1.3               ║"
    echo "║       作者: sd87671067                         ║"
    echo "║       博客: https://dlmn.lol                   ║"
    echo "║                                                ║"
    echo "║  1) Reality      2) Hysteria2                  ║"
    echo "║  3) ShadowTLS    4) Reality+gRPC               ║"
    echo "║  5) SOCKS5                                     ║"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    [[ $EUID -ne 0 ]] && { print_error "需要 root 权限"; exit 1; }
}

detect_os() {
    [ -f /etc/os-release ] && . /etc/os-release || { print_error "无法检测系统"; exit 1; }
    [[ "$ID" != "ubuntu" && "$ID" != "debian" ]] && { print_error "仅支持 Ubuntu/Debian"; exit 1; }
}

install_dependencies() {
    print_info "安装依赖..."
    apt update -y > /dev/null 2>&1
    apt install -y curl wget tar gzip qrencode openssl jq > /dev/null 2>&1

    if command -v sing-box &> /dev/null; then
        print_success "sing-box 已安装"
        return
    fi

    ARCH=$(dpkg --print-architecture)
    LATEST_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    
    [ -z "$LATEST_VERSION" ] && { print_error "无法获取版本"; exit 1; }
    
    print_info "下载 sing-box v${LATEST_VERSION}..."
    wget -q --show-progress -O /tmp/sing-box.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz"
    
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    cp /tmp/sing-box-${LATEST_VERSION}-linux-${ARCH}/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    cat > /etc/systemd/system/sing-box.service <<'SERVICE'
[Unit]
Description=sing-box service
After=network.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
SERVICE
    
    systemctl daemon-reload
    rm -rf /tmp/sing-box*
    print_success "sing-box 安装完成"
}

get_server_ip() {
    SERVER_IP=$(curl -s4m8 ip.sb) || SERVER_IP=$(curl -s6m8 ip.sb)
    [ -z "$SERVER_IP" ] && { print_error "无法获取 IP"; exit 1; }
}

# Reality 配置
setup_reality() {
    clear
    echo -e "${CYAN}═══ Reality 协议配置 ═══${NC}"
    echo ""
    
    UUID=$(sing-box generate uuid)
    KEYPAIR=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "PublicKey" | awk '{print $2}')
    
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    
    echo ""
    echo "伪装域名:"
    echo "  1) itunes.apple.com (推荐)"
    echo "  2) www.microsoft.com"
    echo "  3) 自定义"
    read -p "选择 [1]: " SNI_CHOICE
    
    case ${SNI_CHOICE:-1} in
        1) SNI="itunes.apple.com" ;;
        2) SNI="www.microsoft.com" ;;
        3) read -p "输入域名: " SNI ;;
        *) SNI="itunes.apple.com" ;;
    esac
    
    SHORT_ID=$(openssl rand -hex 8)
    
    INBOUND_JSON='{
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "users": [{"uuid": "'${UUID}'", "flow": "xtls-rprx-vision"}],
            "tls": {
                "enabled": true,
                "server_name": "'${SNI}'",
                "reality": {
                    "enabled": true,
                    "handshake": {"server": "'${SNI}'", "server_port": 443},
                    "private_key": "'${PRIVATE_KEY}'",
                    "short_id": ["'${SHORT_ID}'"]
                }
            }
        }'
    
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#Reality|dlmn.lol"
    
    PROTOCOL_NAME="Reality"
    print_success "Reality 配置完成"
}

# Hysteria2 配置
setup_hysteria2() {
    clear
    echo -e "${CYAN}═══ Hysteria2 协议配置 ═══${NC}"
    echo ""
    
    PASSWORD=$(openssl rand -base64 32)
    
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    
    print_info "生成自签证书..."
    mkdir -p /etc/sing-box/certs
    
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout /etc/sing-box/certs/private.key \
        -out /etc/sing-box/certs/cert.pem \
        -subj "/CN=bing.com" -days 36500 > /dev/null 2>&1
    
    chmod 644 /etc/sing-box/certs/*
    
    INBOUND_JSON='{
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "users": [{"password": "'${PASSWORD}'"}],
            "tls": {
                "enabled": true,
                "server_name": "bing.com",
                "key_path": "/etc/sing-box/certs/private.key",
                "certificate_path": "/etc/sing-box/certs/cert.pem"
            }
        }'
    
    CLIENT_LINK="hysteria2://${PASSWORD}@${SERVER_IP}:${PORT}?sni=bing.com&insecure=1#Hysteria2|dlmn.lol"
    
    PASSWORD_INFO="密码: ${PASSWORD}"
    PROTOCOL_NAME="Hysteria2"
    print_success "Hysteria2 配置完成"
}

# ShadowTLS 配置
setup_shadowtls() {
    clear
    echo -e "${CYAN}═══ ShadowTLS v3 配置 ═══${NC}"
    
    PASSWORD=$(openssl rand -base64 32)
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    
    INBOUND_JSON='{
            "type": "shadowtls",
            "tag": "st-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "version": 3,
            "users": [{"password": "'${PASSWORD}'"}],
            "handshake": {"server": "cloud.tencent.com", "server_port": 443},
            "strict_mode": true,
            "detour": "ss-in"
        },
        {
            "type": "shadowsocks",
            "tag": "ss-in",
            "listen": "127.0.0.1",
            "network": "tcp",
            "method": "2022-blake3-aes-128-gcm",
            "password": "'${PASSWORD}'"
        }'
    
    SS_LINK=$(echo -n "2022-blake3-aes-128-gcm:${PASSWORD}" | base64 -w 0)
    CLIENT_LINK="ss://${SS_LINK}@${SERVER_IP}:${PORT}#ShadowTLS|dlmn.lol"
    
    PASSWORD_INFO="密码: ${PASSWORD}"
    PROTOCOL_NAME="ShadowTLS"
    print_success "ShadowTLS 配置完成"
}

# Reality + gRPC
setup_reality_grpc() {
    clear
    echo -e "${CYAN}═══ Reality + gRPC 配置 ═══${NC}"
    
    UUID=$(sing-box generate uuid)
    KEYPAIR=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "PublicKey" | awk '{print $2}')
    
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    SNI="itunes.apple.com"
    SHORT_ID=$(openssl rand -hex 8)
    GRPC_SERVICE="grpc$(openssl rand -hex 4)"
    
    INBOUND_JSON='{
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "users": [{"uuid": "'${UUID}'", "flow": ""}],
            "tls": {
                "enabled": true,
                "server_name": "'${SNI}'",
                "reality": {
                    "enabled": true,
                    "handshake": {"server": "'${SNI}'", "server_port": 443},
                    "private_key": "'${PRIVATE_KEY}'",
                    "short_id": ["'${SHORT_ID}'"]
                }
            },
            "transport": {"type": "grpc", "service_name": "'${GRPC_SERVICE}'"}
        }'
    
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=grpc&serviceName=${GRPC_SERVICE}#Reality-gRPC|dlmn.lol"
    
    PROTOCOL_NAME="Reality-gRPC"
    print_success "Reality+gRPC 配置完成"
}

# SOCKS5
setup_socks5() {
    clear
    echo -e "${CYAN}═══ SOCKS5 配置 ═══${NC}"
    
    read -p "监听端口 [1080]: " PORT
    PORT=${PORT:-1080}
    
    read -p "启用认证? [Y/n]: " ENABLE_AUTH
    
    if [[ "${ENABLE_AUTH:-Y}" =~ ^[Yy]$ ]]; then
        SOCKS_USER="user"
        SOCKS_PASS=$(openssl rand -base64 16)
        
        INBOUND_JSON='{
            "type": "socks",
            "tag": "socks-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "users": [{"username": "'${SOCKS_USER}'", "password": "'${SOCKS_PASS}'"}]
        }'
        
        AUTH_INFO="用户: ${SOCKS_USER}\n密码: ${SOCKS_PASS}"
        CLIENT_LINK="socks://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${PORT}#SOCKS5|dlmn.lol"
    else
        INBOUND_JSON='{"type": "socks", "tag": "socks-in", "listen": "::", "listen_port": '${PORT}'}'
        AUTH_INFO="无认证"
        CLIENT_LINK="socks://${SERVER_IP}:${PORT}#SOCKS5|dlmn.lol"
    fi
    
    PROTOCOL_NAME="SOCKS5"
    print_success "SOCKS5 配置完成"
}

# 配置中转出站
setup_relay_outbound() {
    echo ""
    echo -e "${CYAN}═══ 中转出站配置 ═══${NC}"
    echo ""
    read -p "是否配置中转? [y/N]: " USE_RELAY
    
    if [[ ! "${USE_RELAY}" =~ ^[Yy]$ ]]; then
        OUTBOUND_JSON='{"type": "direct", "tag": "direct"}'
        OUTBOUND_TAG="direct"
        print_info "使用直连"
        return
    fi
    
    echo ""
    print_info "请粘贴分享链接"
    print_warning "支持: 标准 vless:// 或 Shadowsocket 格式"
    echo ""
    read -p "粘贴链接: " SHARE_LINK
    
    if [ -z "$SHARE_LINK" ]; then
        OUTBOUND_JSON='{"type": "direct", "tag": "direct"}'
        OUTBOUND_TAG="direct"
        return
    fi
    
    # 检测链接格式
    if [[ "$SHARE_LINK" =~ ^vless:// ]]; then
        # 标准 VLESS 格式
        parse_vless_link "$SHARE_LINK"
    elif [[ "$SHARE_LINK" =~ [A-Za-z0-9+/=]{30,}\? ]]; then
        # Shadowsocket Reality 格式 (Base64@IP:PORT?params)
        parse_shadowsocket_link "$SHARE_LINK"
    else
        print_warning "无法识别格式，使用直连"
        OUTBOUND_JSON='{"type": "direct", "tag": "direct"}'
        OUTBOUND_TAG="direct"
    fi
}

# 解析 Shadowsocket 格式
parse_shadowsocket_link() {
    local link="$1"
    
    # 提取 Base64 部分 (UUID)
    local uuid_b64=$(echo "$link" | cut -d'@' -f1)
    local uuid=$(echo "$uuid_b64" | base64 -d 2>/dev/null | cut -d':' -f2)
    
    # 提取服务器和端口
    local server_port=$(echo "$link" | cut -d'@' -f2 | cut -d'?' -f1)
    local server=$(echo "$server_port" | cut -d':' -f1)
    local port=$(echo "$server_port" | cut -d':' -f2)
    
    # 提取参数
    local params=$(echo "$link" | cut -d'?' -f2)
    local sni=$(echo "$params" | grep -oP 'peer=\K[^&]+' || echo "")
    local pbk=$(echo "$params" | grep -oP 'pbk=\K[^&]+' || echo "")
    local sid=$(echo "$params" | grep -oP 'sid=\K[^&]+' || echo "")
    local flow="xtls-rprx-vision"
    
    # 检测是否有 xtls 参数
    if echo "$params" | grep -q "xtls="; then
        flow="xtls-rprx-vision"
    fi
    
    OUTBOUND_TAG="relay"
    OUTBOUND_JSON='{
            "type": "vless",
            "tag": "relay",
            "server": "'${server}'",
            "server_port": '${port}',
            "uuid": "'${uuid}'",
            "flow": "'${flow}'",
            "tls": {
                "enabled": true,
                "server_name": "'${sni}'",
                "utls": {"enabled": true, "fingerprint": "chrome"},
                "reality": {
                    "enabled": true,
                    "public_key": "'${pbk}'",
                    "short_id": "'${sid}'"
                }
            }
        }'
    
    print_success "已解析 Shadowsocket Reality 配置"
}

# 解析标准 VLESS 链接
parse_vless_link() {
    local link="$1"
    local data=$(echo "$link" | sed 's/vless:\/\///')
    
    local uuid=$(echo "$data" | cut -d'@' -f1)
    local rest=$(echo "$data" | cut -d'@' -f2)
    local server=$(echo "$rest" | cut -d':' -f1)
    local port_params=$(echo "$rest" | cut -d':' -f2)
    local port=$(echo "$port_params" | cut -d'?' -f1)
    local params=$(echo "$port_params" | cut -d'?' -f2 | cut -d'#' -f1)
    
    local security=$(echo "$params" | grep -oP 'security=\K[^&]+' || echo "")
    local sni=$(echo "$params" | grep -oP '(sni|peer)=\K[^&]+' || echo "")
    local flow=$(echo "$params" | grep -oP 'flow=\K[^&]+' || echo "")
    local pbk=$(echo "$params" | grep -oP 'pbk=\K[^&]+' || echo "")
    local sid=$(echo "$params" | grep -oP 'sid=\K[^&]+' || echo "")
    
    OUTBOUND_TAG="relay"
    
    if [ "$security" = "reality" ] || [ -n "$pbk" ]; then
        OUTBOUND_JSON='{
            "type": "vless",
            "tag": "relay",
            "server": "'${server}'",
            "server_port": '${port}',
            "uuid": "'${uuid}'",
            "flow": "'${flow}'",
            "tls": {
                "enabled": true,
                "server_name": "'${sni}'",
                "utls": {"enabled": true, "fingerprint": "chrome"},
                "reality": {
                    "enabled": true,
                    "public_key": "'${pbk}'",
                    "short_id": "'${sid}'"
                }
            }
        }'
    else
        OUTBOUND_JSON='{
            "type": "vless",
            "tag": "relay",
            "server": "'${server}'",
            "server_port": '${port}',
            "uuid": "'${uuid}'"
        }'
    fi
    
    print_success "已解析标准 VLESS 配置"
}

# 保存配置
save_config() {
    mkdir -p /etc/sing-box
    
    cat > /etc/sing-box/config.json <<CONF
{
    "log": {"level": "info", "timestamp": true},
    "dns": {"servers": [{"tag": "google", "address": "8.8.8.8"}]},
    "inbounds": [${INBOUND_JSON}],
    "outbounds": [${OUTBOUND_JSON}, {"type": "block", "tag": "block"}],
    "route": {"rules": [], "final": "${OUTBOUND_TAG}"}
}
CONF
    
    print_success "配置已生成"
    
    # 验证配置
    if ! sing-box check -c /etc/sing-box/config.json 2>/dev/null; then
        print_error "配置验证失败"
        cat /etc/sing-box/config.json
        exit 1
    fi
}

# 启动服务
start_service() {
    print_info "启动服务..."
    systemctl enable sing-box > /dev/null 2>&1
    systemctl restart sing-box
    sleep 2
    
    if systemctl is-active --quiet sing-box; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败"
        journalctl -u sing-box -n 20 --no-pager
        exit 1
    fi
}

# 配置防火墙
setup_firewall() {
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "active"; then
        ufw allow ${PORT}/tcp > /dev/null 2>&1
        ufw allow ${PORT}/udp > /dev/null 2>&1
    fi
}

# 显示结果
show_result() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║   🎉 安装完成 | dlmn.lol          ║${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}协议:${NC} ${PROTOCOL_NAME}"
    echo -e "${GREEN}端口:${NC} ${PORT}"
    
    if [ -n "$PASSWORD_INFO" ]; then
        echo -e "${GREEN}${PASSWORD_INFO}${NC}"
    fi
    if [ -n "$AUTH_INFO" ]; then
        echo -e "${GREEN}${AUTH_INFO}${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}${CLIENT_LINK}${NC}"
    echo ""
    
    if command -v qrencode &> /dev/null; then
        qrencode -t ANSIUTF8 -s 1 -m 1 "${CLIENT_LINK}"
    fi
    
    echo ""
    echo -e "${PURPLE}更多工具: https://dlmn.lol${NC}"
    echo ""
}

# 主菜单
main_menu() {
    show_banner
    echo ""
    read -p "选择协议 [1-5]: " choice
    
    case $choice in
        1) setup_reality ;;
        2) setup_hysteria2 ;;
        3) setup_shadowtls ;;
        4) setup_reality_grpc ;;
        5) setup_socks5 ;;
        0) exit 0 ;;
        *) print_error "无效"; sleep 1; main_menu ;;
    esac
}

# 主函数
main() {
    check_root
    detect_os
    get_server_ip
    install_dependencies
    main_menu
    setup_relay_outbound
    save_config
    start_service
    setup_firewall
    show_result
}

main
