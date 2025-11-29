#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   GitHub 一键推送脚本                            ║${NC}"
echo -e "${BLUE}║   仓库: JasonV001/singbox-install                ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

if [ ! -d ".git" ]; then
    echo -e "${YELLOW}[*] 初始化 Git 仓库...${NC}"
    git init
    git branch -M main
    git remote add origin git@github.com:JasonV001/singbox-install.git
    echo -e "${GREEN}[✓] Git 仓库初始化完成${NC}"
else
    echo -e "${GREEN}[✓] Git 仓库已存在${NC}"
    git remote set-url origin git@github.com:JasonV001/singbox-install.git
fi

echo ""
echo -e "${YELLOW}[*] 测试 GitHub SSH 连接...${NC}"
if ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
    echo -e "${GREEN}[✓] SSH 连接正常${NC}"
else
    echo -e "${RED}[✗] SSH 连接失败${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}[*] 添加文件...${NC}"
git add .
echo ""
echo -e "${BLUE}待提交的文件:${NC}"
git status --short

echo ""
read -p "提交信息 [更新 sing-box 脚本 v2.4]: " MSG
MSG=${MSG:-"更新 sing-box 脚本 v2.4 - 优化 AnyTLS 多客户端支持"}

echo ""
echo -e "${YELLOW}[*] 提交更改...${NC}"
git commit -m "$MSG"

echo ""
echo -e "${YELLOW}[*] 推送到 GitHub...${NC}"
git push -u origin main

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            🎉 推送成功！                          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}仓库地址: ${YELLOW}https://github.com/JasonV001/singbox-install${NC}"
    echo ""
else
    echo ""
    echo -e "${RED}[✗] 推送失败${NC}"
    exit 1
fi
