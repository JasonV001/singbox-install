#!/bin/bash

# ==========================================
# SingBox 一键安装配置脚本
# 作者: sd87671067
# 博客: https://dlmn.lol
# 支持: Reality / ShadowTLS v3 / Reality+gRPC / Hysteria2 / SOCKS5
# ==========================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 打印函数
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

# 显示 Banner
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║                                                ║"
    echo "║       SingBox 一键安装配置脚本 v1.3           ║"
    echo "║                                                ║"
    echo "║       作者: ${PURPLE}sd87671067${CYAN}                        ║"
    echo "║       博客: ${PURPLE}https://dlmn.lol${CYAN}                 ║"
    echo "║                                                ║"
    echo "║       支持协议:                                ║"
    echo "║       • Reality (最安全)                       ║"
    echo "║       • Hysteria2 (高速)                       ║"
    echo "║       • ShadowTLS v3 (稳定)                    ║"
    echo "║       • Reality + gRPC                         ║"
    echo "║       • SOCKS5 (中转)                          ║"
    echo "║                                                ║"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# 检查 root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "请使用 root 权限运行此脚本"
        exit 1
    fi
}

# 检测系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        print_error "无法检测操作系统"
        exit 1
    fi

    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        print_error "此脚本仅支持 Ubuntu 和 Debian 系统"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    print_info "更新系统软件包..."
    apt update -y > /dev/null 2>&1

    print_info "安装必要依赖..."
    apt install -y curl wget tar gzip qrencode openssl jq > /dev/null 2>&1

    if command -v sing-box &> /dev/null; then
        print_success "sing-box 已安装"
        return
    fi

    print_info "安装 sing-box..."
    
    ARCH=$(dpkg --print-architecture)
    LATEST_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    
    if [ -z "$LATEST_VERSION" ]; then
        print_error "无法获取 sing-box 最新版本"
        exit 1
    fi
    
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz"
    
    print_info "下载 sing-box v${LATEST_VERSION}..."
    wget -q --show-progress -O /tmp/sing-box.tar.gz "$DOWNLOAD_URL"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    
    cp /tmp/sing-box-${LATEST_VERSION}-linux-${ARCH}/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    cat > /etc/systemd/system/sing-box.service <<SERVICE
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
SERVICE
    
    systemctl daemon-reload
    rm -rf /tmp/sing-box*
    
    print_success "sing-box 安装完成"
}

# 获取服务器 IP
get_server_ip() {
    SERVER_IP=$(curl -s4m8 ip.sb) || SERVER_IP=$(curl -s6m8 ip.sb)
    if [ -z "$SERVER_IP" ]; then
        print_error "无法获取服务器 IP 地址"
        exit 1
    fi
}

# Reality 配置
setup_reality() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Reality 协议配置${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Reality 是目前最安全的代理协议"
    echo ""
    
    UUID=$(sing-box generate uuid)
    KEYPAIR=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "PublicKey" | awk '{print $2}')
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 443]: ${NC})" PORT
    PORT=${PORT:-443}
    
    echo ""
    echo -e "${CYAN}═══════════ 选择伪装域名 ═══════════${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}) www.microsoft.com"
    echo -e "  ${GREEN}2${NC}) itunes.apple.com ${CYAN}(推荐)${NC}"
    echo -e "  ${GREEN}3${NC}) www.lovelive-anime.jp"
    echo -e "  ${GREEN}4${NC}) gateway.icloud.com"
    echo -e "  ${GREEN}5${NC}) 自定义"
    echo ""
    read -p "$(echo -e ${YELLOW}请选择 [默认: 2]: ${NC})" SNI_CHOICE
    SNI_CHOICE=${SNI_CHOICE:-2}
    
    case $SNI_CHOICE in
        1) SNI="www.microsoft.com" ;;
        2) SNI="itunes.apple.com" ;;
        3) SNI="www.lovelive-anime.jp" ;;
        4) SNI="gateway.icloud.com" ;;
        5) read -p "$(echo -e ${YELLOW}请输入域名: ${NC})" SNI ;;
        *) SNI="itunes.apple.com" ;;
    esac
    
    SHORT_ID=$(openssl rand -hex 8)
    
    INBOUND_CONFIG='
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "users": [
                {
                    "uuid": "'${UUID}'",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "'${SNI}'",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "'${SNI}'",
                        "server_port": 443
                    },
                    "private_key": "'${PRIVATE_KEY}'",
                    "short_id": ["'${SHORT_ID}'"]
                }
            }
        }'
    
    NODE_NAME="Reality|博客:dlmn.lol"
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${NODE_NAME}"
    
    PROTOCOL_NAME="Reality"
    PROTOCOL_DESC="VLESS + Reality + XTLS-Vision"
    print_success "Reality 配置完成"
}

# Hysteria2 配置
setup_hysteria2() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Hysteria2 协议配置 (自签证书)${NC}                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Hysteria2 是高速传输协议，适合高带宽场景"
    echo ""
    
    PASSWORD=$(openssl rand -base64 32)
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 443]: ${NC})" PORT
    PORT=${PORT:-443}
    
    # 生成自签证书
    print_info "生成自签证书..."
    mkdir -p /etc/sing-box/certs
    
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout /etc/sing-box/certs/private.key \
        -out /etc/sing-box/certs/cert.pem \
        -subj "/CN=bing.com" -days 36500 \
        > /dev/null 2>&1
    
    chmod 644 /etc/sing-box/certs/*
    
    INBOUND_CONFIG='
        {
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "users": [
                {
                    "password": "'${PASSWORD}'"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "bing.com",
                "key_path": "/etc/sing-box/certs/private.key",
                "certificate_path": "/etc/sing-box/certs/cert.pem"
            }
        }'
    
    NODE_NAME="Hysteria2|博客:dlmn.lol"
    CLIENT_LINK="hysteria2://${PASSWORD}@${SERVER_IP}:${PORT}?sni=bing.com&insecure=1#${NODE_NAME}"
    
    PASSWORD_INFO="密码: ${PASSWORD}"
    PROTOCOL_NAME="Hysteria2"
    PROTOCOL_DESC="Hysteria2 + 自签证书 (bing.com)"
    print_success "Hysteria2 配置完成"
}

# ShadowTLS v3 配置
setup_shadowtls() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}ShadowTLS v3 协议配置${NC}                         ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    
    PASSWORD=$(openssl rand -base64 32)
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 443]: ${NC})" PORT
    PORT=${PORT:-443}
    
    read -p "$(echo -e ${YELLOW}请输入伪装域名 [默认: cloud.tencent.com]: ${NC})" HANDSHAKE_SERVER
    HANDSHAKE_SERVER=${HANDSHAKE_SERVER:-cloud.tencent.com}
    
    INBOUND_CONFIG='
        {
            "type": "shadowtls",
            "tag": "st-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "version": 3,
            "users": [
                {
                    "password": "'${PASSWORD}'"
                }
            ],
            "handshake": {
                "server": "'${HANDSHAKE_SERVER}'",
                "server_port": 443
            },
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
    
    NODE_NAME="ShadowTLS|博客:dlmn.lol"
    SS_LINK=$(echo -n "2022-blake3-aes-128-gcm:${PASSWORD}" | base64 -w 0)
    CLIENT_LINK="ss://${SS_LINK}@${SERVER_IP}:${PORT}?plugin=shadow-tls;version=3;host=${HANDSHAKE_SERVER}#${NODE_NAME}"
    
    PASSWORD_INFO="密码: ${PASSWORD}"
    PROTOCOL_NAME="ShadowTLS v3"
    PROTOCOL_DESC="Shadowsocks + ShadowTLS v3"
    print_success "ShadowTLS v3 配置完成"
}

# Reality + gRPC 配置
setup_reality_grpc() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Reality + gRPC 协议配置${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    
    UUID=$(sing-box generate uuid)
    KEYPAIR=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "PublicKey" | awk '{print $2}')
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 443]: ${NC})" PORT
    PORT=${PORT:-443}
    
    echo ""
    echo -e "${CYAN}═══════════ 选择伪装域名 ═══════════${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}) www.microsoft.com"
    echo -e "  ${GREEN}2${NC}) itunes.apple.com ${CYAN}(推荐)${NC}"
    echo -e "  ${GREEN}3${NC}) www.lovelive-anime.jp"
    echo -e "  ${GREEN}4${NC}) gateway.icloud.com"
    echo -e "  ${GREEN}5${NC}) 自定义"
    echo ""
    read -p "$(echo -e ${YELLOW}请选择 [默认: 2]: ${NC})" SNI_CHOICE
    SNI_CHOICE=${SNI_CHOICE:-2}
    
    case $SNI_CHOICE in
        1) SNI="www.microsoft.com" ;;
        2) SNI="itunes.apple.com" ;;
        3) SNI="www.lovelive-anime.jp" ;;
        4) SNI="gateway.icloud.com" ;;
        5) read -p "$(echo -e ${YELLOW}请输入域名: ${NC})" SNI ;;
        *) SNI="itunes.apple.com" ;;
    esac
    
    SHORT_ID=$(openssl rand -hex 8)
    GRPC_SERVICE="grpc$(openssl rand -hex 4)"
    
    INBOUND_CONFIG='
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "users": [
                {
                    "uuid": "'${UUID}'",
                    "flow": ""
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "'${SNI}'",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "'${SNI}'",
                        "server_port": 443
                    },
                    "private_key": "'${PRIVATE_KEY}'",
                    "short_id": ["'${SHORT_ID}'"]
                }
            },
            "transport": {
                "type": "grpc",
                "service_name": "'${GRPC_SERVICE}'"
            }
        }'
    
    NODE_NAME="Reality-gRPC|博客:dlmn.lol"
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=grpc&serviceName=${GRPC_SERVICE}&mode=gun#${NODE_NAME}"
    
    PROTOCOL_NAME="Reality-gRPC"
    PROTOCOL_DESC="VLESS + Reality + gRPC"
    print_success "Reality + gRPC 配置完成"
}

# SOCKS5 配置
setup_socks5() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}SOCKS5 协议配置 (中转专用)${NC}                    ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 1080]: ${NC})" PORT
    PORT=${PORT:-1080}
    
    echo ""
    read -p "$(echo -e ${YELLOW}是否启用认证? [Y/n]: ${NC})" ENABLE_AUTH
    ENABLE_AUTH=${ENABLE_AUTH:-Y}
    
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        read -p "$(echo -e ${YELLOW}用户名 [默认: user]: ${NC})" SOCKS_USER
        SOCKS_USER=${SOCKS_USER:-user}
        
        read -p "$(echo -e ${YELLOW}密码 [留空自动生成]: ${NC})" SOCKS_PASS
        if [ -z "$SOCKS_PASS" ]; then
            SOCKS_PASS=$(openssl rand -base64 16)
        fi
        
        INBOUND_CONFIG='
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "::",
            "listen_port": '${PORT}',
            "users": [
                {
                    "username": "'${SOCKS_USER}'",
                    "password": "'${SOCKS_PASS}'"
                }
            ]
        }'
        AUTH_INFO="用户名: ${SOCKS_USER}\n密码: ${SOCKS_PASS}"
        CLIENT_LINK="socks://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${PORT}#SOCKS5|博客:dlmn.lol"
    else
        INBOUND_CONFIG='
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "::",
            "listen_port": '${PORT}'
        }'
        AUTH_INFO="无需认证"
        CLIENT_LINK="socks://${SERVER_IP}:${PORT}#SOCKS5|博客:dlmn.lol"
    fi
    
    NODE_NAME="SOCKS5|博客:dlmn.lol"
    PROTOCOL_NAME="SOCKS5"
    PROTOCOL_DESC="SOCKS5 代理 (中转专用)"
    print_success "SOCKS5 配置完成"
}

# 配置中转出站
setup_relay_outbound() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}中转出站配置${NC}                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${GREEN}Y${NC}) 配置中转出站"
    echo -e "  ${RED}N${NC}) 直连出站 (默认)"
    echo ""
    read -p "$(echo -e ${YELLOW}请选择 [y/N]: ${NC})" USE_RELAY
    USE_RELAY=${USE_RELAY:-N}
    
    if [[ ! "$USE_RELAY" =~ ^[Yy]$ ]]; then
        OUTBOUND_TAG="direct"
        OUTBOUND_CONFIG='
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }'
        print_info "使用直连出站"
        return
    fi
    
    echo ""
    print_info "请粘贴分享链接 (vless/vmess/ss/trojan)"
    echo ""
    read -p "$(echo -e ${YELLOW}粘贴链接: ${NC})" SHARE_LINK
    
    if [ -z "$SHARE_LINK" ]; then
        print_warning "链接为空，使用直连"
        OUTBOUND_TAG="direct"
        OUTBOUND_CONFIG='
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }'
        return
    fi
    
    parse_share_link "$SHARE_LINK"
}

# 解析分享链接
parse_share_link() {
    local link="$1"
    local protocol=$(echo "$link" | cut -d':' -f1)
    
    case "$protocol" in
        vless)
            local data=$(echo "$link" | sed 's/vless:\/\///')
            local uuid=$(echo "$data" | cut -d'@' -f1)
            local rest=$(echo "$data" | cut -d'@' -f2)
            local server=$(echo "$rest" | cut -d':' -f1)
            local port_params=$(echo "$rest" | cut -d':' -f2)
            local port=$(echo "$port_params" | cut -d'?' -f1)
            local params=$(echo "$port_params" | cut -d'?' -f2 | cut -d'#' -f1)
            
            local security=$(echo "$params" | grep -oP 'security=\K[^&]+' || echo "none")
            local sni=$(echo "$params" | grep -oP '(sni|peer)=\K[^&]+' || echo "")
            local flow=$(echo "$params" | grep -oP 'flow=\K[^&]+' || echo "")
            local pbk=$(echo "$params" | grep -oP 'pbk=\K[^&]+' || echo "")
            local sid=$(echo "$params" | grep -oP 'sid=\K[^&]+' || echo "")
            
            OUTBOUND_TAG="relay"
            
            if [ "$security" = "reality" ] || [ -n "$pbk" ]; then
                OUTBOUND_CONFIG='
        {
            "type": "vless",
            "tag": "relay",
            "server": "'${server}'",
            "server_port": '${port}',
            "uuid": "'${uuid}'",
            "flow": "'${flow}'",
            "tls": {
                "enabled": true,
                "server_name": "'${sni}'",
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                },
                "reality": {
                    "enabled": true,
                    "public_key": "'${pbk}'",
                    "short_id": "'${sid}'"
                }
            }
        },
        {
            "type": "block",
            "tag": "block"
        }'
            else
                OUTBOUND_CONFIG='
        {
            "type": "vless",
            "tag": "relay",
            "server": "'${server}'",
            "server_port": '${port}',
            "uuid": "'${uuid}'"
        },
        {
            "type": "block",
            "tag": "block"
        }'
            fi
            
            print_success "已解析 VLESS 中转配置"
            ;;
        *)
            print_warning "暂不支持该协议，使用直连"
            OUTBOUND_TAG="direct"
            OUTBOUND_CONFIG='
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }'
            ;;
    esac
}

# 保存配置
save_config() {
    mkdir -p /etc/sing-box
    
    cat > /etc/sing-box/config.json <<CONFIGEND
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "dns": {
        "servers": [
            {
                "tag": "google",
                "address": "8.8.8.8"
            }
        ]
    },
    "inbounds": [${INBOUND_CONFIG}
    ],
    "outbounds": [${OUTBOUND_CONFIG}
    ],
    "route": {
        "rules": [],
        "final": "${OUTBOUND_TAG}"
    }
}
CONFIGEND
    
    print_success "配置文件已生成"
    
    # 验证配置
    if ! sing-box check -c /etc/sing-box/config.json > /dev/null 2>&1; then
        print_error "配置文件验证失败"
        cat /etc/sing-box/config.json
        exit 1
    fi
}

# 启动服务
start_service() {
    print_info "启动 sing-box 服务..."
    
    systemctl enable sing-box > /dev/null 2>&1
    systemctl restart sing-box
    
    sleep 2
    
    if systemctl is-active --quiet sing-box; then
        print_success "sing-box 服务启动成功"
    else
        print_error "服务启动失败"
        journalctl -u sing-box -n 20 --no-pager
        exit 1
    fi
}

# 配置防火墙
setup_firewall() {
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow ${PORT}/tcp > /dev/null 2>&1
        ufw allow ${PORT}/udp > /dev/null 2>&1
        print_success "防火墙规则已添加"
    fi
}

# 显示结果
show_result() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║              🎉 SingBox 安装完成 ✓                   ║${NC}"
    echo -e "${CYAN}${BOLD}║          更多工具: ${PURPLE}https://dlmn.lol${CYAN}                 ║${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════ 📋 配置信息 ═══════════════${NC}"
    echo -e "  ${CYAN}IP:${NC} ${YELLOW}${SERVER_IP}${NC}"
    echo -e "  ${CYAN}协议:${NC} ${YELLOW}${PROTOCOL_NAME}${NC}"
    echo -e "  ${CYAN}端口:${NC} ${YELLOW}${PORT}${NC}"
    
    if [[ "$PROTOCOL_NAME" =~ "Reality" ]]; then
        echo -e "  ${CYAN}UUID:${NC} ${YELLOW}${UUID}${NC}"
        echo -e "  ${CYAN}公钥:${NC} ${YELLOW}${PUBLIC_KEY}${NC}"
        echo -e "  ${CYAN}Short ID:${NC} ${YELLOW}${SHORT_ID}${NC}"
        echo -e "  ${CYAN}SNI:${NC} ${YELLOW}${SNI}${NC}"
    elif [ "$PROTOCOL_NAME" = "Hysteria2" ] || [ "$PROTOCOL_NAME" = "ShadowTLS v3" ]; then
        echo -e "  ${CYAN}${PASSWORD_INFO}${NC}"
    elif [ "$PROTOCOL_NAME" = "SOCKS5" ]; then
        echo -e "  ${CYAN}${AUTH_INFO}${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════ 📱 客户端链接 ═══════════════${NC}"
    echo -e "${YELLOW}${CLIENT_LINK}${NC}"
    echo ""
    
    if command -v qrencode &> /dev/null; then
        qrencode -t ANSIUTF8 -s 1 -m 1 "${CLIENT_LINK}"
        echo ""
    fi
    
    echo -e "${GREEN}${BOLD}═══════════════ ⚙️  管理命令 ═══════════════${NC}"
    echo -e "  systemctl status sing-box   # 查看状态"
    echo -e "  journalctl -u sing-box -f  # 查看日志"
    echo ""
    echo -e "${PURPLE}${BOLD}更多工具: ${CYAN}https://dlmn.lol${NC}"
    echo ""
}

# 主菜单
main_menu() {
    show_banner
    echo -e "${CYAN}${BOLD}═══════════════ 请选择协议 ═══════════════${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}) Reality         ${CYAN}(最安全)${NC}"
    echo -e "  ${GREEN}2${NC}) Hysteria2       ${CYAN}(高速传输)${NC}"
    echo -e "  ${GREEN}3${NC}) ShadowTLS v3    ${CYAN}(稳定)${NC}"
    echo -e "  ${GREEN}4${NC}) Reality + gRPC  ${CYAN}(备用)${NC}"
    echo -e "  ${GREEN}5${NC}) SOCKS5          ${CYAN}(中转)${NC}"
    echo -e "  ${RED}0${NC}) 退出"
    echo ""
    read -p "$(echo -e ${YELLOW}请选择 [1-5]: ${NC})" choice
    
    case $choice in
        1) setup_reality ;;
        2) setup_hysteria2 ;;
        3) setup_shadowtls ;;
        4) setup_reality_grpc ;;
        5) setup_socks5 ;;
        0) exit 0 ;;
        *) print_error "无效选择"; sleep 2; main_menu ;;
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
