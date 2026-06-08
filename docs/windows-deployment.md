# Windows 11 AMD64 部署指南

## 方案 A: Docker Desktop（推荐）

### 1. 安装 Docker Desktop

从 https://www.docker.com/products/docker-desktop/ 下载 Windows 版本。

```powershell
# 验证安装
docker --version
docker compose version
```

### 2. 构建多平台镜像

```powershell
# 创建 buildx builder（支持 multi-arch）
docker buildx create --name multiarch --use
docker buildx inspect --bootstrap

# 构建 amd64 镜像（Windows 本地）
cd audit-platform
docker build --platform linux/amd64 -t audit-platform:pro .

# 或一键构建多平台
docker buildx build --platform linux/amd64,linux/arm64 -t audit-platform:pro --load .
```

### 3. 运行

```powershell
# CLI 模式
docker run --rm `
  -v ${PWD}\code:/workspace/code `
  -v ${PWD}\report:/workspace/report `
  -e ANTHROPIC_API_KEY=sk-... `
  audit-platform:pro scan --offline

# Web 模式
docker compose up -d
# 浏览器访问 http://localhost:8000
```

### 4. 路径注意事项

Windows 路径在 Docker 中需要使用 Linux 格式或 Docker 命名卷：

```powershell
# bind mount（本地目录）
-v "C:\Users\xxx\code:/workspace/code"

# 或使用命名卷（推荐，跨平台兼容）
docker volume create code_data
docker run -v code_data:/workspace/code ...
```

---

## 方案 B: 直接部署（无 Docker）

### 环境要求

| 工具 | 版本 | 下载 |
|------|------|------|
| Python | 3.12+ | https://www.python.org/downloads/ |
| OpenJDK | 21 | https://adoptium.net/download/ |
| Maven | 3.9+ | https://maven.apache.org/download.cgi |
| GCC | 13+ (MinGW-w64) | https://www.mingw-w64.org/ |
| CMake | 3.22+ | https://cmake.org/download/ |
| CodeQL CLI | 2.25+ | https://github.com/github/codeql-cli-binaries/releases |
| Git | 2.40+ | https://git-scm.com/download/win |

### 安装步骤

#### 1. Python + 依赖

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install fastapi uvicorn jinja2 python-multipart httpx
```

#### 2. Semgrep

```powershell
pip install semgrep
semgrep --version
```

#### 3. CodeQL CLI

```powershell
# 下载 codeql.zip 后解压到 C:\tools\codeql
# 添加到 PATH
$env:Path += ";C:\tools\codeql"
codeql --version
```

#### 4. Java + Maven

```powershell
# 安装后配置环境变量
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21.0.6.7-hotspot"
$env:MAVEN_HOME = "C:\tools\apache-maven-3.9.9"
$env:Path += ";$env:JAVA_HOME\bin;$env:MAVEN_HOME\bin"
```

#### 5. GCC (MinGW-w64)

```powershell
# 安装后添加到 PATH
$env:Path += ";C:\msys64\mingw64\bin"
gcc --version
```

### 路径配置

Windows 使用反斜杠 `\`，在 config.yaml 和命令行参数中统一使用正斜杠 `/` 或双反斜杠 `\\`：

```yaml
# config.yaml (使用正斜杠)
codeql:
  cli_path: C:/tools/codeql/codeql.cmd    # Windows 需要 .cmd 后缀
  database_dir: C:/workspace/cache/codeql-dbs
```

### 启动 Web 服务

```powershell
.venv\Scripts\activate
uvicorn src.web.app:app --host 0.0.0.0 --port 8000
```

### 命令行扫描

```powershell
python -m src.main scan --code-dir C:\projects\myapp --offline
```

---

## 多平台构建完整命令

```powershell
# 创建多架构 builder（仅首次）
docker buildx create --name multiarch --driver docker-container --use
docker buildx inspect --bootstrap

# 构建并推送（需要 registry）
docker buildx build `
  --platform linux/amd64,linux/arm64 `
  -t your-registry/audit-platform:latest `
  --push .

# 仅本地加载当前架构
docker buildx build `
  --platform linux/amd64 `
  -t audit-platform:pro `
  --load .
```
