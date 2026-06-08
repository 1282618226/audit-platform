#!/bin/bash
# ============================================================================
# CNAS 容器化源代码安全审计平台 —— 容器入口
#
# 用法:
#   docker run -v $(pwd)/code:/workspace/code \
#              -v $(pwd)/report:/workspace/report \
#              -e ANTHROPIC_API_KEY=sk-... \
#              audit-platform scan
#
#   docker run ... audit-platform scan --offline
#   docker run ... audit-platform feedback --finding-id=XXX --verdict=rejected
#   docker run ... audit-platform tune
#   docker run ... audit-platform stats
# ============================================================================

set -euo pipefail

# ─── 颜色输出 ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }

# ─── 环境检测 ─────────────────────────────────────────────────────

detect_environment() {
    log_step "检测运行环境..."

    echo "  Platform: $(uname -m)"
    echo "  OS: $(uname -s)"
    echo "  Python: $(python3 --version 2>/dev/null || echo 'not found')"

    # 检测 LLM 可用性
    if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        # 兼容 claude CLI（使用 AUTH_TOKEN 而非 API_KEY）
        export ANTHROPIC_AUTH_TOKEN="${ANTHROPIC_API_KEY}"
        log_info "ANTHROPIC_API_KEY 已设置 → 在线模式可用"
    else
        log_warn "ANTHROPIC_API_KEY 未设置 → 仅离线模式可用"
    fi

    # 设置 claude CLI 需要的环境变量
    if [ -n "${ANTHROPIC_BASE_URL:-}" ]; then
        export CLAUDE_CODE_ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL}"
    fi

    # 检测网络连通性
    if curl -s --connect-timeout 5 https://api.deepseek.com/anthropic > /dev/null 2>&1; then
        log_info "DeepSeek API 可达"
    else
        log_warn "DeepSeek API 不可达 → LLM 功能不可用"
    fi
}

# ─── 工具可用性 ───────────────────────────────────────────────────

check_tools() {
    log_step "检查工具可用性..."

    # JAVA_HOME 动态修复（容器 ENV 无法在 build 时确定架构时，运行时修正）
    REAL_ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
    JAVA_HOME_CANDIDATE="/usr/lib/jvm/java-21-openjdk-${REAL_ARCH}"
    if [ -d "${JAVA_HOME_CANDIDATE}" ]; then
        export JAVA_HOME="${JAVA_HOME_CANDIDATE}"
        log_info "JAVA_HOME=${JAVA_HOME} (arch=${REAL_ARCH})"
    fi

    # Semgrep
    if semgrep --version > /dev/null 2>&1; then
        log_info "Semgrep: $(semgrep --version 2>&1 | head -1)"
    else
        log_warn "Semgrep 未安装"
    fi

    # Semgrep Pro Engine（如果提供了 token）
    if [ -n "${SEMGREP_APP_TOKEN:-}" ]; then
        if [ -f /opt/semgrep-pro/semgrep-pro ]; then
            log_info "Semgrep Pro: 已安装"
        else
            log_info "Semgrep Pro: 检测到 TOKEN，正在安装..."
            semgrep install-semgrep-pro 2>/dev/null && \
                log_info "Semgrep Pro: 安装成功" || \
                log_warn "Semgrep Pro: 安装失败（可忽略，将使用 CE）"
        fi
    else
        log_info "Semgrep Pro: 未启用（设置 SEMGREP_APP_TOKEN 可启用）"
    fi

    # CodeQL
    if /opt/codeql/codeql --version > /dev/null 2>&1; then
        log_info "CodeQL: $(/opt/codeql/codeql --version 2>&1 | head -1)"
    else
        log_warn "CodeQL 未安装"
    fi

    # Java
    if java -version 2>&1 | head -1; then
        log_info "Java: $(java -version 2>&1 | head -1)"
    else
        log_warn "Java 未安装"
    fi

    # GCC
    if gcc --version > /dev/null 2>&1; then
        log_info "GCC: $(gcc --version 2>&1 | head -1)"
    else
        log_warn "GCC 未安装"
    fi

    echo
}

# ─── 目录准备 ─────────────────────────────────────────────────────

prepare_directories() {
    log_step "准备工作目录..."

    mkdir -p /workspace/code
    mkdir -p /workspace/report
    mkdir -p /workspace/feedback
    mkdir -p /workspace/cache/codeql-dbs

    log_info "工作目录已就绪"
    echo "  /workspace/code     → 源代码（挂载点）"
    echo "  /workspace/report   → 审计报告（挂载点）"
    echo "  /workspace/feedback → 反馈数据库（挂载点）"
    echo "  /workspace/cache    → CodeQL 缓存"
    echo
}

# ─── 命令分发 ─────────────────────────────────────────────────────

run_command() {
    local cmd="${1:-}"

    if [ -z "$cmd" ]; then
        echo "用法: docker run audit-platform <command> [options]"
        echo ""
        echo "命令:"
        echo "  scan      完整扫描（SAST + LLM）"
        echo "  scan --offline  离线模式（纯 SAST）"
        echo "  feedback  人工标注发现"
        echo "  tune      规则调优分析"
        echo "  stats     反馈数据库统计"
        echo ""
        echo "示例:"
        echo "  docker run -v \$(pwd)/code:/workspace/code \\"
        echo "             -v \$(pwd)/report:/workspace/report \\"
        echo "             -e ANTHROPIC_API_KEY=sk-... \\"
        echo "             audit-platform scan"
        exit 1
    fi

    shift || true
    exec python3 -m src.main "$cmd" "$@"
}

# ─── 信号处理 ─────────────────────────────────────────────────────

cleanup() {
    log_info "收到终止信号，清理中..."
    # 确保子进程被终止
    kill -TERM 0 2>/dev/null || true
    wait
    log_info "退出。"
    exit 0
}

trap cleanup SIGTERM SIGINT

# ─── 主入口 ───────────────────────────────────────────────────────

main() {
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  CNAS 容器化源代码安全审计平台 v1.0                       ║"
    echo "║  GB/T 34944-2017 (Java) + GB/T 34943-2017 (C/C++)       ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo

    detect_environment
    check_tools
    prepare_directories

    # 切换到应用目录
    cd /app

    # 分发命令（scan / feedback / tune / stats）
    run_command "${@}"
}

main "$@"
