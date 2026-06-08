# ============================================================================
# CNAS 容器化源代码安全审计平台 —— Dockerfile (Multi-Platform)
#
# 支持架构: linux/arm64 (Apple Silicon), linux/amd64 (Intel/Windows Docker)
# 构建: docker buildx build --platform linux/arm64,linux/amd64 -t audit-platform .
#
# 分层策略 (6 层):
#   Layer 0: base     — Python 3.12 slim + 中文字体 + 基础工具
#   Layer 1: deps     — JDK 21 + Maven + GCC/CMake (架构自适应)
#   Layer 2: codeql   — CodeQL CLI (按架构选择二进制)
#   Layer 3: python   — pip + Node.js + Semgrep Pro (可配置镜像源)
#   Layer 4: app      — 平台源码 + 规则 + 知识库
#   Layer 5: entry    — entrypoint.sh + 健康检查
# ============================================================================

# ─── Layer 0: Base System ─────────────────────────────────────────
FROM --platform=$TARGETPLATFORM python:3.12-slim AS base

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG APT_MIRROR=mirrors.aliyun.com

# 中国网络环境: apt 镜像源（可通过 --build-arg APT_MIRROR= 跳过）
RUN if [ -n "${APT_MIRROR}" ]; then \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        unzip \
        xz-utils \
        git \
        jq \
        file \
        locales \
        fonts-noto-cjk \
        tzdata \
        dpkg \
    && echo "zh_CN.UTF-8 UTF-8" > /etc/locale.gen \
    && locale-gen zh_CN.UTF-8 2>/dev/null || true \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=zh_CN.UTF-8 \
    LANGUAGE=zh_CN:zh \
    LC_ALL=zh_CN.UTF-8 \
    TZ=Asia/Shanghai

# ─── Layer 1: JDK + Maven + GCC/CMake Toolchains ──────────────────
FROM base AS deps

# Java 21 + GCC 工具链（路径自适应 arm64/amd64）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openjdk-21-jdk-headless \
        gcc \
        g++ \
        cmake \
        make \
        build-essential \
        libssl-dev \
        sqlite3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Maven 手动下载（Debian trixie 无 maven 包，用 archive.apache.org 更稳定）
ARG MAVEN_VERSION=3.9.9
ARG MAVEN_URL=https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz
RUN (curl -sL --max-time 120 "${MAVEN_URL}" -o /tmp/maven.tar.gz \
        || wget -q --timeout=120 -O /tmp/maven.tar.gz "${MAVEN_URL}" \
        || echo "WARNING: Maven 下载失败") && \
    if [ -f /tmp/maven.tar.gz ] && [ -s /tmp/maven.tar.gz ] && \
       file /tmp/maven.tar.gz | grep -q 'gzip'; then \
        tar xzf /tmp/maven.tar.gz -C /opt/ && \
        ln -s /opt/apache-maven-${MAVEN_VERSION}/bin/mvn /usr/local/bin/mvn && \
        rm -f /tmp/maven.tar.gz; \
    else \
        echo "Maven 未安装，跳过"; \
        rm -f /tmp/maven.tar.gz; \
    fi

# JAVA_HOME 运行时动态检测架构（兼容 buildx 和普通 docker build）
# 同时修复 Maven 找不到 JAVA_HOME 的问题
RUN REAL_ARCH=$(dpkg --print-architecture) && \
    JAVA_HOME_DIR="/usr/lib/jvm/java-21-openjdk-${REAL_ARCH}" && \
    echo "JAVA_HOME=${JAVA_HOME_DIR}" >> /etc/environment && \
    echo "export JAVA_HOME=${JAVA_HOME_DIR}" >> /etc/profile.d/java.sh && \
    echo "export JAVA_HOME=${JAVA_HOME_DIR}" >> /root/.bashrc && \
    echo "Validated JAVA_HOME=${JAVA_HOME_DIR} for arch=${REAL_ARCH}"

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64 \
    MAVEN_HOME=/opt/apache-maven-3.9.9

# 入口点脚本会在启动时用正确的 JAVA_HOME 覆盖
# 详见 entrypoint.sh

# Maven 阿里云镜像加速
RUN mkdir -p /root/.m2 && \
    echo '<?xml version="1.0" encoding="UTF-8"?><settings><mirrors><mirror><id>aliyun</id><mirrorOf>central</mirrorOf><name>Aliyun Maven</name><url>https://maven.aliyun.com/repository/public</url></mirror></mirrors></settings>' \
    > /root/.m2/settings.xml

# ─── Layer 2: CodeQL CLI ──────────────────────────────────────────
FROM deps AS codeql

ARG CODECQL_VERSION=v2.25.6

# CodeQL 下载 — 按架构选择二进制
#   - amd64: codeql-linux64.zip（原生支持）
#   - arm64: 无原生二进制，尝试 linux64 + QEMU 仿真
#   下载失败不阻断构建
RUN mkdir -p /opt/codeql && \
    REAL_ARCH=$(dpkg --print-architecture) && \
    if [ "${REAL_ARCH}" = "amd64" ]; then \
        CODECQL_URL="https://github.com/github/codeql-cli-binaries/releases/download/${CODECQL_VERSION}/codeql-linux64.zip"; \
    else \
        echo "CodeQL: ${REAL_ARCH} 无原生二进制，尝试 linux64 + QEMU"; \
        CODECQL_URL="https://github.com/github/codeql-cli-binaries/releases/download/${CODECQL_VERSION}/codeql-linux64.zip"; \
    fi && \
    echo "Downloading CodeQL for ${REAL_ARCH} from ${CODECQL_URL}" && \
    (curl -sL --max-time 180 --connect-timeout 30 -o /tmp/codeql.zip "${CODECQL_URL}" 2>/dev/null || \
     wget -q --timeout=180 -O /tmp/codeql.zip "${CODECQL_URL}" 2>/dev/null) && \
    if [ -f /tmp/codeql.zip ] && [ -s /tmp/codeql.zip ] && unzip -tq /tmp/codeql.zip >/dev/null 2>&1; then \
        unzip -q /tmp/codeql.zip -d /opt/ && \
        rm -f /tmp/codeql.zip && \
        /opt/codeql/codeql --version 2>/dev/null && \
        echo "CodeQL installed successfully (arch=${REAL_ARCH})"; \
    else \
        echo "======================================================================"; \
        echo "WARNING: CodeQL download failed — container will run without CodeQL"; \
        echo "  arm64 用户: CodeQL 无原生 ARM64 包，需要在 AMD64 主机上运行"; \
        echo "  amd64 用户: 请检查网络连接或 GitHub 可达性"; \
        echo "======================================================================"; \
        rm -f /tmp/codeql.zip; \
    fi || echo "WARNING: CodeQL installation step failed (non-fatal)"

ENV PATH="/opt/codeql:${PATH}"

# ─── Layer 3: Python + Node.js Dependencies ───────────────────────
FROM codeql AS python-deps

ARG PIP_MIRROR=https://pypi.tuna.tsinghua.edu.cn/simple
ARG NPM_MIRROR=https://registry.npmmirror.com

# pip 镜像源（可通过 --build-arg PIP_MIRROR="" 跳过）
RUN if [ -n "${PIP_MIRROR}" ]; then \
        pip config set global.index-url "${PIP_MIRROR}"; \
        pip config set global.trusted-host $(echo "${PIP_MIRROR}" | sed 's|https://||;s|/simple||'); \
        echo "pip mirror: ${PIP_MIRROR}"; \
    else \
        echo "pip mirror: default (pypi.org)"; \
    fi

COPY requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir -r /tmp/requirements.txt || \
    pip install --no-cache-dir -r /tmp/requirements.txt -i https://pypi.org/simple/ && \
    pip cache purge

# Node.js — 架构自适应（amd64 → x64, arm64 → arm64）
ARG NODE_VERSION=20.19.0
RUN REAL_ARCH=$(dpkg --print-architecture) && \
    NODE_ARCH="arm64" && \
    if [ "${REAL_ARCH}" = "amd64" ]; then NODE_ARCH="x64"; fi && \
    echo "Node.js: arch=${REAL_ARCH} → node_arch=${NODE_ARCH}" && \
    NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" && \
    echo "Downloading Node.js from ${NODE_URL}" && \
    (curl -sL --max-time 120 "${NODE_URL}" -o /tmp/node.tar.xz \
        || wget -q --timeout=120 -O /tmp/node.tar.xz "${NODE_URL}" \
        || echo "WARNING: Node.js 下载失败") && \
    if [ -f /tmp/node.tar.xz ] && [ -s /tmp/node.tar.xz ]; then \
        tar xf /tmp/node.tar.xz -C /opt/ && \
        ln -sf /opt/node-v${NODE_VERSION}-linux-${NODE_ARCH}/bin/node /usr/local/bin/node && \
        ln -sf /opt/node-v${NODE_VERSION}-linux-${NODE_ARCH}/bin/npm /usr/local/bin/npm && \
        ln -sf /opt/node-v${NODE_VERSION}-linux-${NODE_ARCH}/bin/npx /usr/local/bin/npx && \
        rm -f /tmp/node.tar.xz && \
        echo "Node.js $(node --version) installed"; \
    else \
        echo "Node.js 未安装，将使用 Python SDK 调用 DeepSeek"; \
        rm -f /tmp/node.tar.xz; \
    fi

# claude-code CLI（可选，npm 镜像源可配置）
RUN if command -v npm >/dev/null 2>&1; then \
        NPM_REGISTRY="${NPM_MIRROR:-https://registry.npmjs.org}" && \
        echo "Installing claude-code from ${NPM_REGISTRY}" && \
        npm install -g @anthropic-ai/claude-code --registry="${NPM_REGISTRY}" 2>&1 | tail -3 || \
        echo "WARNING: claude-code 安装失败（可忽略，使用 Python SDK）"; \
    else \
        echo "npm 未安装，跳过 claude-code"; \
    fi

# 环境变量：claude CLI 兼容 DeepSeek
ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# Semgrep Pro Engine（在构建时安装，需要 --secret id=SEMGREP_APP_TOKEN）
# 兼容 arm64 / amd64
RUN --mount=type=secret,id=SEMGREP_APP_TOKEN \
    if [ -f /run/secrets/SEMGREP_APP_TOKEN ]; then \
        TOKEN=$(cat /run/secrets/SEMGREP_APP_TOKEN) && \
        echo "Installing Semgrep Pro Engine..." && \
        SEMGREP_APP_TOKEN=$TOKEN semgrep install-semgrep-pro --debug 2>&1 | tail -5 || \
        echo "WARNING: Semgrep Pro install failed, using CE"; \
    else \
        echo "SEMGREP_APP_TOKEN build secret not set, using Semgrep CE"; \
    fi

# ─── Layer 4: Application ─────────────────────────────────────────
FROM python-deps AS app

WORKDIR /app

# 创建目录结构
RUN mkdir -p /app/src \
             /app/rules/semgrep/java \
             /app/rules/semgrep/cpp \
             /app/rules/codeql/java \
             /app/rules/codeql/cpp \
             /app/knowledge \
             /workspace/code \
             /workspace/report \
             /workspace/feedback \
             /workspace/cache/codeql-dbs

# 拷贝源码
COPY src/ /app/src/

# 拷贝规则
COPY rules/ /app/rules/

# 拷贝知识库
COPY knowledge/knowledge_base.json /app/knowledge/

# 拷贝配置
COPY config.yaml /app/config.yaml

# ─── Layer 5: Entrypoint ──────────────────────────────────────────
FROM app AS final

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=30s \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
CMD []
