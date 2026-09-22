#!/usr/bin/env bash
# AuditForwarder - Linux 安装脚本
# 在 Linux 系统上安装 AuditForwarder Agent。
#
# 用法：sudo ./install.sh [选项]
#   --prefix PATH        安装前缀，默认 /usr/local
#   --etcdir PATH        配置目录，默认 /etc/auditforwarder
#   --datadir PATH       数据目录，默认 /var/lib/auditforwarder
#   --logdir PATH        日志目录，默认 /var/log/auditforwarder
#   --no-systemd         跳过 systemd 服务安装
#   --no-keys            跳过 Ed25519 签名密钥生成
#   --start              安装完成后启动服务
#   --uninstall          卸载 Agent

set -euo pipefail

PREFIX="/usr/local"
ETCDIR="/etc/auditforwarder"
DATADIR="/var/lib/auditforwarder"
LOGDIR="/var/log/auditforwarder"
USE_SYSTEMD=1
GENERATE_KEYS=1
START=0
UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)     PREFIX="$2"; shift 2;;
        --etcdir)     ETCDIR="$2"; shift 2;;
        --datadir)    DATADIR="$2"; shift 2;;
        --logdir)     LOGDIR="$2"; shift 2;;
        --no-systemd) USE_SYSTEMD=0; shift;;
        --no-keys)    GENERATE_KEYS=0; shift;;
        --start)      START=1; shift;;
        --uninstall)  UNINSTALL=1; shift;;
        -h|--help)    sed -n '2,16p' "$0"; exit 0;;
        *)            echo "未知选项：$1" >&2; exit 2;;
    esac
done

BIN="$PREFIX/bin/auditforwarderd"

uninstall() {
    echo "[卸载] 正在停止服务..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop    auditforwarder.service 2>/dev/null || true
        systemctl disable auditforwarder.service 2>/dev/null || true
        rm -f /etc/systemd/system/auditforwarder.service
        systemctl daemon-reload
    fi
    echo "[卸载] 正在删除程序文件..."
    rm -f "$BIN"
    rm -rf "$PREFIX/share/auditforwarder"
    echo "[卸载] 数据、日志和配置已保留在以下位置："
    echo "  $ETCDIR  $DATADIR  $LOGDIR"
    echo "  如需删除，请执行：rm -rf $ETCDIR $DATADIR $LOGDIR"
    echo "AuditForwarder 已卸载。"
}

if [ "$UNINSTALL" = "1" ]; then
    uninstall
    exit 0
fi

# ---- 安装前检查 -----------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "此脚本必须以 root 身份运行，请使用 sudo。" >&2
    exit 1
fi

echo "[安装] prefix=$PREFIX  etc=$ETCDIR  data=$DATADIR  log=$LOGDIR"

# ---- 程序文件 -------------------------------------------------------------
if [ ! -x "$BIN" ]; then
    SRC_BIN="$(cd "$(dirname "$0")" && pwd)/../build/auditforwarderd"
    if [ ! -x "$SRC_BIN" ]; then
        echo "错误：未找到程序文件：$BIN 或 $SRC_BIN" >&2
        echo "请先构建项目：cmake -S . -B build && cmake --build build -j" >&2
        exit 1
    fi
    install -d "$PREFIX/bin"
    install -m 0755 "$SRC_BIN" "$BIN"
    echo "[安装] 已安装 $BIN"
fi

# ---- 配置目录 -------------------------------------------------------------
install -d -m 0750 "$ETCDIR" "$ETCDIR/keys" "$ETCDIR/tls"
install -d -m 0750 "$DATADIR" "$DATADIR/batches"
install -d -m 0750 "$LOGDIR"

# ---- 默认配置 -------------------------------------------------------------
if [ ! -f "$ETCDIR/agent.yaml" ]; then
    install -m 0640 "$(dirname "$0")/../config/agent.yaml" "$ETCDIR/agent.yaml"
    sed -i "s|/etc/auditforwarder|$ETCDIR|g; s|/var/lib/auditforwarder|$DATADIR|g; s|/var/log/auditforwarder|$LOGDIR|g" "$ETCDIR/agent.yaml"
fi
if [ ! -f "$ETCDIR/rules.yaml" ]; then
    install -m 0640 "$(dirname "$0")/../config/rules.yaml" "$ETCDIR/rules.yaml"
fi

# ---- 签名密钥 -------------------------------------------------------------
if [ "$GENERATE_KEYS" = "1" ] && [ ! -f "$ETCDIR/keys/agent.pem" ]; then
    if command -v openssl >/dev/null 2>&1; then
        echo "[安装] 正在生成 Ed25519 签名密钥..."
        openssl genpkey -algorithm ed25519 -out "$ETCDIR/keys/agent.pem" 2>/dev/null
        openssl pkey -in "$ETCDIR/keys/agent.pem" -pubout -out "$ETCDIR/keys/agent.pub"
        chmod 0640 "$ETCDIR/keys/agent.pem" "$ETCDIR/keys/agent.pub"
        echo "[安装] 密钥已写入 $ETCDIR/keys/"
    else
        echo "[安装] 未找到 openssl，将使用 HMAC 备用方案"
    fi
fi

# ---- TLS 初始化 -----------------------------------------------------------
if [ ! -f "$ETCDIR/tls/client.crt" ]; then
    echo "[安装] 正在生成自签名客户端证书，生产环境请替换为正式证书"
    openssl req -x509 -newkey ed25519 -nodes -days 3650 \
        -keyout "$ETCDIR/tls/client.key" -out "$ETCDIR/tls/client.crt" \
        -subj "/CN=auditforwarder-$(hostname)" 2>/dev/null || true
    chmod 0600 "$ETCDIR/tls/client.key"
    chmod 0644 "$ETCDIR/tls/client.crt"
    # 临时将自签名证书作为 CA 使用
    cp "$ETCDIR/tls/client.crt" "$ETCDIR/tls/ca.crt"
fi

# ---- systemd 服务 ---------------------------------------------------------
if [ "$USE_SYSTEMD" = "1" ] && command -v systemctl >/dev/null 2>&1; then
    cat > /etc/systemd/system/auditforwarder.service <<EOF
[Unit]
Description=AuditForwarder 安全审计 Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN -c $ETCDIR/agent.yaml -d $DATADIR
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
CapabilityBoundingSet=CAP_AUDIT_READ CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
AmbientCapabilities=CAP_AUDIT_READ CAP_DAC_READ_SEARCH
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 /etc/systemd/system/auditforwarder.service
    systemctl daemon-reload
    if [ "$START" = "1" ]; then
        systemctl enable --now auditforwarder.service
    fi
    echo "[安装] systemd 服务已安装。"
fi

# ---- Linux 能力说明 -------------------------------------------------------
# 如果以非 root 身份运行并使用 libaudit，用户或用户组需要 CAP_AUDIT_READ。
# 当前 systemd 服务单元已经授予该能力。
echo
echo "AuditForwarder 安装成功。"
echo "  程序文件：$BIN"
echo "  配置文件：$ETCDIR/agent.yaml"
echo "  规则文件：$ETCDIR/rules.yaml"
echo "  签名密钥：$ETCDIR/keys/agent.pem"
echo "  数据目录：$DATADIR"
echo "  日志目录：$LOGDIR"
[ "$USE_SYSTEMD" = "1" ] && echo
[ "$USE_SYSTEMD" = "1" ] && echo "  管理服务：sudo systemctl {start|stop|status} auditforwarder"
[ "$USE_SYSTEMD" = "1" ] && echo "  查看日志：sudo journalctl -u auditforwarder -f"
