---
name: docker-build-china
description: Build Docker images on Apple Silicon (ARM64) Macs in Chinese network environments — mirrors, proxy, deb822 sources, and common pitfalls.
category: devops
triggers:
  - user asks to build/rebuild a Docker image
  - docker build fails on ARM64 Mac in China
  - permission denied / apt source / mirror / proxy errors in build
  - user mentions "国内网络" / "镜像源" / "代理" in Docker context
---

# Docker Build on ARM64 in China

## Core Architecture

Docker builds on Apple Silicon Macs use `linux/arm64` emulation via Docker Desktop. The build container has its own network namespace — **`host.docker.internal` does NOT work in `build` context** (only in `run`/`compose up`). Use the host machine's LAN IP instead:

```bash
# Get host IP
ipconfig getifaddr en0     # macOS
```

## Debian trixie (Debian 13) Specifics

Debian trixie has important differences from earlier Debian versions that affect Docker builds in China.

### deb822 apt sources format

trixie uses `/etc/apt/sources.list.d/debian.sources` (deb822 format), NOT legacy `sources.list`:

```dockerfile
# WRONG — this file doesn't exist on trixie:
# RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list

# CORRECT:
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true
```

### Package availability changes (trixie vs bookworm)

| Package | Debian 12 (bookworm) | Debian 13 (trixie) |
|---------|---------------------|-------------------|
| `openjdk-17-jdk-headless` | ✅ Available | ❌ NOT available — use `openjdk-21-jdk-headless` |
| `maven` | ✅ Available | ❌ NOT available — must download from Apache archive |
| `gcc` / `g++` / `cmake` | ✅ Available | ✅ Available |
| `sqlite3` | ✅ Available | ✅ Available |

### Maven manual download (when apt package missing)

```dockerfile
ARG MAVEN_VERSION=3.9.9
ARG MAVEN_URL=https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz
RUN (curl -sL --max-time 120 "${MAVEN_URL}" -o /tmp/maven.tar.gz \
        || echo "WARNING: Maven download failed") && \
    if [ -f /tmp/maven.tar.gz ] && [ -s /tmp/maven.tar.gz ] && \
       file /tmp/maven.tar.gz | grep -q 'gzip'; then \
        tar xzf /tmp/maven.tar.gz -C /opt/ && \
        ln -s /opt/apache-maven-${MAVEN_VERSION}/bin/mvn /usr/local/bin/mvn; \
    fi
```

Use `archive.apache.org` (not `dlcdn.apache.org`) for reliability. The `file` command verifies the download is actual gzip, not an HTML error page. Install `file` via apt if not present.

## Chinese Mirror Configuration

### For Kali apt sources (deb822 format)

Kali uses `/etc/apt/sources.list.d/kali.sources` in deb822 format (NOT `sources.list`):

```dockerfile
RUN printf 'Types: deb\nURIs: http://mirrors.ustc.edu.cn/kali/\nSuites: kali-rolling\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/kali-archive-keyring.gpg\n' > /etc/apt/sources.list.d/kali.sources
```

### For Debian/Ubuntu (legacy sources.list)

```dockerfile
RUN sed -i 's|http://deb.debian.org|http://mirrors.ustc.edu.cn|g' /etc/apt/sources.list
```

### Available Chinese Mirrors

| Mirror | URL | Notes |
|--------|-----|-------|
| 中科大 (USTC) | `http://mirrors.ustc.edu.cn/kali/` | Fast, occasional drops |
| 阿里云 (Aliyun) | `http://mirrors.aliyun.com/kali/` | Good fallback |
| 清华 (TUNA) | `https://mirrors.tuna.tsinghua.edu.cn/kali/` | SSL cert issues with Kali |
| 上海交大 | `http://ftp.sjtu.edu.cn/kali/` | Alternative |

### Recommended: Multiple Mirror Fallback + --fix-missing

```dockerfile
RUN printf '...ustc...' > /etc/apt/sources.list.d/ustc.sources && \
    printf '...aliyun...' > /etc/apt/sources.list.d/aliyun.sources && \
    apt update && \
    apt -y install --fix-missing --no-install-recommends <packages> && \
    apt clean && rm -rf /var/lib/apt/lists/*
```

## Proxy for GitHub / npm in Docker Build

Prefix RUN commands with proxy env vars:

```dockerfile
RUN HTTP_PROXY=http://HOST_IP:1080 HTTPS_PROXY=http://HOST_IP:1080 \
    curl -sL "https://github.com/..." -o file.zip
```

**Do NOT use `host.docker.internal`** — not resolved during `docker build`.

### Steps typically needing proxy in China:
1. `curl` downloading from GitHub Releases
2. `git clone` from GitHub
3. `npm install` / `npx` from npm registry
4. `pip install` from PyPI (unless using Chinese mirror)

## Pitfalls

### Kali deb822 format
Do NOT overwrite `sources.list` — Kali uses `sources.list.d/*.sources` in deb822 format. The `sources.list` file is intentionally empty.

### SSL cert issues
Many Chinese mirrors fail SSL verification with Kali. Use HTTP (`http://mirrors.ustc.edu.cn/kali/`) instead.

### npm apt dependency explosion
`apt install npm` pulls ~200+ node packages. Split into a separate RUN layer with `--no-install-recommends`.

### docker build vs docker run network
- **build**: no `host.docker.internal`. Use host LAN IP.
- **run/compose up**: `host.docker.internal` works (macOS Docker Desktop).

### --no-cache on retry
Docker caches failed layers. Always use `--no-cache` when retrying after failures.

#### Dynamic multi-arch detection: `dpkg --print-architecture`

For Dockerfiles that need different packages or paths per architecture, use `dpkg` at build time (works because all Debian-based images have it):

```dockerfile
# Dynamic JAVA_HOME for arm64 vs amd64
RUN JAVA_ARCH=$(dpkg --print-architecture) && \
    JAVA_HOME_DIR="/usr/lib/jvm/java-21-openjdk-${JAVA_ARCH}" && \
    if [ ! -d "$JAVA_HOME_DIR" ]; then \
        OTHER_ARCH="$(if [ "$JAVA_ARCH" = "arm64" ]; then echo amd64; else echo arm64; fi)" && \
        JAVA_HOME_DIR="/usr/lib/jvm/java-21-openjdk-${OTHER_ARCH}"; \
    fi && echo "JAVA_HOME=${JAVA_HOME_DIR}"
```

```dockerfile
# Dynamic Node.js arch selection
RUN REAL_ARCH=$(dpkg --print-architecture) && \
    NODE_ARCH="arm64" && \
    [ "${REAL_ARCH}" = "amd64" ] && NODE_ARCH="x64" || true
```

### Build-time mirror override via build args

Use conditional build args for cross-environment portability:

```dockerfile
ARG APT_MIRROR=mirrors.aliyun.com
ARG PIP_MIRROR=https://pypi.tuna.tsinghua.edu.cn/simple
ARG NPM_MIRROR=https://registry.npmmirror.com

# Apply mirror only when set (empty = skip)
RUN if [ -n "${APT_MIRROR}" ]; then \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
    fi
```

```bash
# Build with mirrors (China):
docker build --build-arg APT_MIRROR=mirrors.aliyun.com -t image .
# Build without mirrors (global):
docker build --build-arg APT_MIRROR= -t image .
```

## Multi-Arch CodeQL Download

When Dockerfile needs CodeQL on both arm64 and amd64:
CodeQL CLI releases (`github/github/codeql-cli-binaries`) only ship `codeql-linux64.zip` (AMD64). There is **no** `codeql-arm64.zip`. On ARM64 Docker builds, CodeQL can only run under QEMU emulation, which is very slow and may time out during the 120s download window.

Strategy: make CodeQL download non-fatal. The container operates in "Semgrep-only" mode when CodeQL is unavailable:

```dockerfile
RUN curl -sL --max-time 180 --connect-timeout 30 \
      -o /tmp/codeql.zip "https://github.com/.../codeql-linux64.zip" \
      || echo "WARNING: CodeQL download failed - container will run without CodeQL" || true
```

ARM64 Mac users should expect CodeQL to be unavailable in Docker containers unless running under `--platform linux/amd64` with QEMU. For local development without Docker, CodeQL CLI can be installed directly on macOS (native ARM64 binary available via `codeql-osx64.zip`).

### Node.js static binary installation (faster than apt)
When a container needs Node.js/npm but `apt install nodejs` pulls hundreds of Debian node packages, use a static binary instead:

```dockerfile
ARG NODE_VERSION=20.19.0
RUN NODE_ARCH="arm64" && \
    echo "$TARGETPLATFORM" | grep -q "amd64" && NODE_ARCH="x64" || true && \
    NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" && \
    (curl -sL --max-time 120 "${NODE_URL}" -o /tmp/node.tar.xz \
        || echo "WARNING: Node.js download failed") && \
    if [ -f /tmp/node.tar.xz ] && [ -s /tmp/node.tar.xz ]; then \
        tar xf /tmp/node.tar.xz -C /opt/ && \
        ln -s /opt/node-v${NODE_VERSION}-linux-${NODE_ARCH}/bin/node /usr/local/bin/node && \
        ln -s /opt/node-v${NODE_VERSION}-linux-${NODE_ARCH}/bin/npm /usr/local/bin/npm; \
    fi
```

Requirements: `xz-utils` package for `tar.xz` extraction. The TARGETPLATFORM build arg must be declared: `ARG TARGETPLATFORM`. This method adds ~40MB per Node.js version (vs ~150MB+ from apt).

Use with npm registry mirror for China:
```dockerfile
RUN npm install -g <package> --registry=https://registry.npmmirror.com || true
```

### Semgrep Pro Engine via Docker build secrets
Semgrep Pro Engine must be installed during Docker build (not at runtime) because the `install-semgrep-pro` command downloads a proprietary binary. The token must be passed as a Docker build secret:

```dockerfile
# In Dockerfile:
RUN --mount=type=secret,id=SEMGREP_APP_TOKEN \
    if [ -f /run/secrets/SEMGREP_APP_TOKEN ]; then \
        TOKEN=$(cat /run/secrets/SEMGREP_APP_TOKEN) && \
        SEMGREP_APP_TOKEN=$TOKEN semgrep install-semgrep-pro --debug; \
    fi
```

```bash
# Build command:
echo "token..." > /tmp/token.txt
docker build --secret id=SEMGREP_APP_TOKEN,src=/tmp/token.txt -t image:tag .
# Clean up token file after build
rm -f /tmp/token.txt
```

The secret is mounted at `/run/secrets/<id>` during build and is NOT persisted in the final image (no layer captures it). Requires Docker BuildKit (enabled by default in Docker Desktop).

After successful install, enable Pro with `--pro` CLI flag or `pro: true` in config. The install adds ~300MB to the image (semgrep-core-proprietary binary).

### Docker build secrets for authenticated downloads (generic pattern)
The `--mount=type=secret` pattern works for any build-time auth:

```dockerfile
RUN --mount=type=secret,id=MY_TOKEN \
    if [ -f /run/secrets/MY_TOKEN ]; then \
        TOKEN=$(cat /run/secrets/MY_TOKEN) && \
        curl -H "Authorization: Bearer $TOKEN" ... ; \
    fi
```

### Downloaded file may be HTML, not archive
When downloading from GitHub or Apache mirrors in China, failed connections may return HTML error pages with exit code 0. Always verify downloaded files:

```dockerfile
if [ -f file.zip ] && [ -s file.zip ] && \
   file file.zip | grep -qi 'zip\|archive\|gzip\|tar'; then
    # file is valid
fi
```

This prevents `tar: not in gzip format` errors from corrupting the build. Install `file` and `xz-utils` in base layer.

### DeepSeek API via Python SDK in Docker
DeepSeek's Anthropic-compatible endpoint (`https://api.deepseek.com/anthropic`) has stricter rate limiting against Python SDK than against Claude Code CLI. Guidelines:

- **Python Anthropic SDK**: `client = Anthropic(base_url="https://api.deepseek.com/anthropic", api_key="sk-...")`
- **Claude Code CLI** (`@anthropic-ai/claude-code`): installed via npm, uses `ANTHROPIC_AUTH_TOKEN` env var. Supports both `ANTHROPIC_BASE_URL` and `CLAUDE_CODE_ANTHROPIC_BASE_URL`.
- **Rate limiting**: Avoid separate `check_connectivity` API calls (they consume rate limit budget). Let the actual call fail and retry with generous backoff.
- **API unavailability**: `Authentication Fails (governor)` indicates a server-side gateway block, not a key problem. Retry after delay resolves it.

## Verification

```bash
# Test proxy reachability from build context
docker run --rm <image> \
  bash -c "curl -s -x http://HOST_IP:1080 -o /dev/null -w '%{http_code}' https://github.com"

# Check apt sources
docker run --rm <image> cat /etc/apt/sources.list.d/*.sources
```
