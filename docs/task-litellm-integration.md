## 任务：修复 DeepSeek LLM 调用 + 引入 LiteLLM 代理

项目路径：`/Users/chenhaoming/Projects/AIProjects/audit-platform`

### 问题诊断

当前平台通过 Python Anthropic SDK 调用 `https://api.deepseek.com/anthropic`，返回 401 Authentication Fails。

**根因**：Python Anthropic SDK 发送 API key 时使用 `x-api-key` 请求头。而 DeepSeek 的 Anthropic 兼容端点对 Python SDK 的 User-Agent 和请求头格式有限流/拒绝策略。

**Cairn 的做法（已验证可行）**：使用 `claude` CLI（Node.js），设置 `ANTHROPIC_AUTH_TOKEN` 环境变量。Claude Code CLI 使用 `Authorization: Bearer` 请求头发送 token，DeepSeek 端点正确处理此格式。

**解决方案**：引入 **LiteLLM**（开源，github.com/BerriAI/litellm）作为本地代理网关。

LiteLLM 的优势：
- 平台 Python 代码→Anthropic SDK→LiteLLM（localhost）→DeepSeek（OpenAI 原生格式）
- 自动协议转换：Anthropic ↔ OpenAI
- 支持多 provider 故障转移（DeepSeek 挂了自动切到其他 provider）
- 可作为 Docker sidecar 容器运行
- 支持请求重试、限流、负载均衡

### 实施步骤

#### 第一步：搭建 LiteLLM 代理

在 `docker-compose.yml` 中添加 LiteLLM sidecar：

```yaml
services:
  # ... 已有的 web 服务

  litellm:
    image: ghcr.io/berriai/litellm:main-latest
    ports:
      - "4000:4000"
    volumes:
      - ./litellm-config.yaml:/app/config.yaml
    environment:
      - DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY}
      - OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
    command: ["--config", "/app/config.yaml", "--port", "4000", "--host", "0.0.0.0"]
    restart: unless-stopped
```

创建 `litellm-config.yaml`：

```yaml
model_list:
  - model_name: deepseek-chat
    litellm_params:
      model: deepseek/deepseek-chat
      api_key: os.environ/DEEPSEEK_API_KEY
      rpm: 60
  - model_name: deepseek-reasoner
    litellm_params:
      model: deepseek/deepseek-reasoner
      api_key: os.environ/DEEPSEEK_API_KEY
      rpm: 10

litellm_settings:
  drop_params: true
  set_verbose: false

general_settings:
  master_key: sk-litellm-master
  database_url: "sqlite:///litellm.db"
```

#### 第二步：修改平台配置指向本地 LiteLLM

修改 `config.yaml` 中 LLM 配置：

```yaml
llm:
  provider: litellm
  model: deepseek-chat
  reason_model: deepseek-reasoner
  base_url: "http://litellm:4000"
  api_key_env: ANTHROPIC_API_KEY
  api_key: "sk-litellm-master"  # LiteLLM master key
  offline: false
```

#### 第三步：修复 LLM 客户端认证方式

修改 `src/llm_client.py`：

1. 改用 `Authorization: Bearer` 请求头（而非 `x-api-key`）
2. 如果使用直接 DeepSeek Anthropic 端点，传 `ANTHROPIC_AUTH_TOKEN` 而不是 `ANTHROPIC_API_KEY`

关键改动：

```python
# 使用 LiteLLM 时，Anthropic SDK 正常配置
client = Anthropic(
    base_url="http://litellm:4000",
    api_key="sk-litellm-master",  # LiteLLM master key
)

# 直接调 DeepSeek 时（备用方案），用 requests 而非 Anthropic SDK
import requests

def call_deepseek_direct(messages, model="deepseek-chat"):
    """直接调 DeepSeek OpenAI API，绕过 Anthropic SDK 兼容层"""
    resp = requests.post(
        "https://api.deepseek.com/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ['DEEPSEEK_API_KEY']}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": messages,
            "max_tokens": 4096,
        },
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]
```

#### 第四步：故障转移机制

`llm_client.py` 中实现三级降级策略：

```python
# Level 1: LiteLLM (首选)
try:
    return call_via_litellm(...)
except Exception as e1:
    log_warn(f"LiteLLM 失败: {e1}")

# Level 2: DeepSeek OpenAI API 直连 (备用)
try:
    return call_deepseek_direct(...)
except Exception as e2:
    log_warn(f"DeepSeek 直连失败: {e2}")

# Level 3: 离线模式 (最终降级)
return fallback_to_offline(...)
```

#### 第五步：更新 docker-compose 环境变量

确保 `.env` 文件（或 compose 环境变量）中包含：

```bash
DEEPSEEK_API_KEY=sk-xxx
OPENROUTER_API_KEY=sk-or-v1-xxx  # 可选，作为故障转移
```

#### 第六步：验证

1. LiteLLM 容器启动：
   ```bash
   docker compose up -d litellm
   curl http://localhost:4000/health
   ```

2. LLM 连通性检测：
   ```bash
   cd /Users/chenhaoming/Projects/AIProjects/audit-platform
   python3 -c "
   from src.llm_client import LLMClient
   import yaml
   with open('config.yaml') as f:
       cfg = yaml.safe_load(f)
   llm = LLMClient(cfg['llm'])
   print(llm.check_connectivity())
   "
   ```

3. 完整扫描验证：
   ```bash
   python3 -m src.main scan --code-dir /Users/chenhaoming/Projects/eclipse-workspace/YP-34944-E-007/src --output-dir /tmp/llm-report
   ```

4. 测试通过：
   ```bash
   .venv/bin/python3 -m pytest tests/ -q
   ```

### 不要做的事

- ❌ 不要移除原有离线模式（`--offline`）——LLM 不可用时自动降级
- ❌ 不要修改 `src/orchestrator.py` 或 `src/report_generator.py`
- ❌ 不要在代码中硬编码 API key
