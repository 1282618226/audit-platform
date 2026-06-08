## 任务：集成 CodeQL 内置安全查询包 + GB/T 条款映射

项目路径：`/Users/chenhaoming/Projects/AIProjects/audit-platform`

### 背景

当前 CodeQL 只有 15 条自定义 QL 查询，都是简单模式匹配，没有用上 CodeQL 真正的数据流分析能力。CodeQL 内置了 63 个 CWE 分类的 Java 安全查询包（位于 `codeql/java-queries`），覆盖 SQL注入、XSS、命令注入、路径遍历、弱加密等，**全部带数据流追踪**。

目标：复用这些内置查询，用 SARIF 输出的 rule ID 映射到 GB/T 条款号。

### 现状确认

```bash
# 确认宿主机 CodeQL 查询包可用
/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-cli/codeql resolve packs 2>&1 | grep java-queries

# 看看 CWE 目录结构
ls /Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-repo/java/ql/src/Security/CWE/
```

### 实施步骤

#### 第一步：创建 CodeQL 规则 → GB/T 条款映射文件

新建 `rules/codeql/codeql-to-gbt-mapping.json`，将 CodeQL 内置查询的 rule ID 映射到国标条款号。

CodeQL 内置查询的 rule ID 格式为：`java/ql/src/Security/CWE/<CWE-ID>/<QueryName>.ql`

完整映射表（从 CWE 到 GB/T 条款）：

```json
{
  "java/ql/src/Security/CWE/CWE-089/SqlInjection.ql": {
    "gb_clause": "6.2.3.4",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "SQL注入",
    "cwe": "CWE-89"
  },
  "java/ql/src/Security/CWE/CWE-078/ExecOfUninterpretedQuery.ql": {
    "gb_clause": "6.2.3.3",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "命令注入",
    "cwe": "CWE-78"
  },
  "java/ql/src/Security/CWE/CWE-079/Xss.ql": {
    "gb_clause": "6.2.8.1",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "跨站脚本",
    "cwe": "CWE-79"
  },
  "java/ql/src/Security/CWE/CWE-022/TaintedPath.ql": {
    "gb_clause": "6.2.3.2",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "路径遍历",
    "cwe": "CWE-22"
  },
  "java/ql/src/Security/CWE/CWE-094/ExpressionLanguageInjection.ql": {
    "gb_clause": "6.2.3.5",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "代码注入",
    "cwe": "CWE-94"
  },
  "java/ql/src/Security/CWE/CWE-113/ResponseSplitting.ql": {
    "gb_clause": "6.2.8.3",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "HTTP响应拆分",
    "cwe": "CWE-113"
  },
  "java/ql/src/Security/CWE/CWE-117/LogInjection.ql": {
    "gb_clause": "6.2.3.8",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "日志注入",
    "cwe": "CWE-117"
  },
  "java/ql/src/Security/CWE/CWE-134/FormatString.ql": {
    "gb_clause": "7.2.3.7",
    "gb_standard": "GB/T 34943-2017",
    "vuln_name": "格式化字符串",
    "cwe": "CWE-134"
  },
  "java/ql/src/Security/CWE/CWE-190/ArithmeticTainted.ql": {
    "gb_clause": "7.2.3.5",
    "gb_standard": "GB/T 34943-2017",
    "vuln_name": "整数溢出",
    "cwe": "CWE-190"
  },
  "java/ql/src/Security/CWE/CWE-326/InsufficientKeySize.ql": {
    "gb_clause": "6.2.6.7",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "使用已破解的加密算法",
    "cwe": "CWE-326"
  },
  "java/ql/src/Security/CWE/CWE-327/BrokenCryptoAlgorithm.ql": {
    "gb_clause": "6.2.6.7",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "使用已破解的加密算法",
    "cwe": "CWE-327"
  },
  "java/ql/src/Security/CWE/CWE-330/InsufficientlyRandomValues.ql": {
    "gb_clause": "6.2.6.10",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "不充分的随机数",
    "cwe": "CWE-330"
  },
  "java/ql/src/Security/CWE/CWE-352/Csrf.ql": {
    "gb_clause": "6.2.8.2",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "跨站请求伪造",
    "cwe": "CWE-352"
  },
  "java/ql/src/Security/CWE/CWE-502/DeserializationOfUntrustedData.ql": {
    "gb_clause": "6.2.5.1",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "可序列化的类包含敏感数据",
    "cwe": "CWE-502"
  },
  "java/ql/src/Security/CWE/CWE-522/InsufficientlyProtectedCredentials.ql": {
    "gb_clause": "6.2.6.1",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "明文存储口令",
    "cwe": "CWE-522"
  },
  "java/ql/src/Security/CWE/CWE-601/UrlRedirect.ql": {
    "gb_clause": "6.2.8.4",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "开放重定向",
    "cwe": "CWE-601"
  },
  "java/ql/src/Security/CWE/CWE-611/Xxe.ql": {
    "gb_clause": "6.2.3.12",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "XML外部实体注入",
    "cwe": "CWE-611"
  },
  "java/ql/src/Security/CWE/CWE-614/InsecureCookie.ql": {
    "gb_clause": "6.2.6.17",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "Cookie未设置安全属性",
    "cwe": "CWE-614"
  },
  "java/ql/src/Security/CWE/CWE-643/XPathInjection.ql": {
    "gb_clause": "6.2.3.12",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "XPath注入",
    "cwe": "CWE-643"
  },
  "java/ql/src/Security/CWE/CWE-798/HardcodedCredentials.ql": {
    "gb_clause": "6.2.6.3",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "口令硬编码",
    "cwe": "CWE-798"
  },
  "java/ql/src/Security/CWE/CWE-917/LdapInjection.ql": {
    "gb_clause": "6.2.3.13",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "LDAP注入",
    "cwe": "CWE-917"
  },
  "java/ql/src/Security/CWE/CWE-918/RequestForgery.ql": {
    "gb_clause": "6.2.8.2",
    "gb_standard": "GB/T 34944-2017",
    "vuln_name": "SSRF",
    "cwe": "CWE-918"
  }
}
```

**注意**：以上规则 ID 是 CodeQL 标准库的路径格式，实际运行时使用 `codeql database analyze ... codeql/java-queries` 会自动选取所有安全查询。SARIF 输出中的 rule ID 格式为 `java/ql/src/Security/CWE/...`，可以直接匹配。

#### 第二步：修改 `src/scanner_codeql.py`

增加一个 `_run_builtin_queries` 方法，使用 CodeQL 内置的 `codeql/java-queries` 查询包：

```python
def _run_builtin_queries(self, database_path: str, language: str = "java") -> list[dict]:
    """使用 CodeQL 内置安全查询包进行扫描，结果映射到 GB/T 条款。"""
    import tempfile, json, os
    
    # 使用内置查询包
    if language == "java":
        query_spec = "codeql/java-queries"
    else:
        query_spec = "codeql/cpp-queries"
    
    # SARIF 输出
    with tempfile.NamedTemporaryFile(suffix=".sarif", mode="w", delete=False) as f:
        sarif_path = f.name
    
    cmd = [
        self.cli_path, "database", "analyze",
        str(database_path),
        query_spec,
        "--format", "sarif-latest",
        "--output", sarif_path,
        "--no-save-cache",
        "--no-upload",
        "--threads", "2",
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=self._timeout)
        if result.returncode not in (0, 2):
            return []
        return self._parse_builtin_sarif(sarif_path)
    except Exception as e:
        logger.error("CodeQL 内置查询失败: %s", e)
        return []
```

新增 `_parse_builtin_sarif` 方法解析 SARIF 并映射到 GB/T：

```python
@staticmethod
def _parse_builtin_sarif(sarif_path: str) -> list[dict]:
    """解析 CodeQL 内置查询的 SARIF 输出，映射到 GB/T 条款。"""
    import json, os
    
    # 加载映射表
    mapping_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "rules", "codeql", "codeql-to-gbt-mapping.json"
    )
    with open(mapping_path) as f:
        rule_mapping = json.load(f)
    
    with open(sarif_path) as f:
        data = json.load(f)
    
    findings = []
    for run in data.get("runs", []):
        # 从 runs[0].tool.driver.rules 构建 rule_id → 元数据映射
        rules_meta = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules_meta[rule["id"]] = rule
        
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            
            # 查映射表
            mapping = rule_mapping.get(rule_id, {})
            if not mapping:
                # 如果没有映射，尝试从 CWE 号推断
                logger.debug("CodeQL: 未映射的规则 %s", rule_id)
                continue
            
            # 提取位置
            locations = result.get("locations", [])
            if not locations:
                continue
            loc = locations[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {})
            region = loc.get("region", {})
            
            # 消息
            msg = result.get("message", {}).get("text", "")
            
            findings.append({
                "clause": mapping["gb_clause"],
                "standard": mapping["gb_standard"],
                "vuln_name": mapping["vuln_name"],
                "file_path": CodeQLScanner._resolve_uri(
                    artifact.get("uri", ""), ""
                ),
                "line_start": region.get("startLine", 0),
                "line_end": region.get("endLine", 0),
                "source_tool": "codeql-builtin",
                "auto_confidence": 0.85,
                "code_snippet": region.get("snippet", {}).get("text", ""),
                "tool_raw_output": {
                    "rule_id": rule_id,
                    "message": msg,
                    "cwe": mapping.get("cwe", ""),
                },
                "entry_point": {},  # 内置查询的 dataflow_trace 在 SARIF codeFlows 中
            })
    
    return findings
```

#### 第三步：修改 `src/orchestrator.py`

在 `_parallel_scan` 方法中，在现有的 CodeQL 调用之后，增加内置查询包的调用：

```python
# 在现有 CodeQL 扫描之后（约第 440 行）
# ── CodeQL 内置查询包 ──
if self._codeql and self._config.get("codeql", {}).get("enabled", True):
    for lang in metadata.languages_detected:
        lang_key = "java" if lang == "Java" else "cpp"
        db_path = self._codeql.create_database(code_dir, language=lang_key)
        if db_path:
            # 1. 运行自定义 QL 查询（已有的）
            custom_findings = self._codeql.analyze(db_path, language=lang_key)
            codeql_findings.extend(custom_findings)
            
            # 2. 运行内置安全查询包（新增）
            builtin_findings = self._codeql._run_builtin_queries(db_path, language=lang_key)
            codeql_findings.extend(builtin_findings)
```

#### 第四步：更新 `rules/standard-mapping.json`

为新加的 CodeQL 内置查询发现的 GB/T 条款号补充映射条目。

#### 第五步：更新 C/C++ 的内置查询

对 C/C++ 同样处理，CodeQL 有 `codeql/cpp-queries` 包，含缓冲区溢出、格式化字符串、整数溢出等。在 `codeql-to-gbt-mapping.json` 中补充 C/C++ 映射。

### 关于 ARM64 兼容

在 macOS ARM64 Docker 容器内 CodeQL 无法运行（Rosetta 限制）。平台已有自动降级逻辑：
- CodeQL 不可用时静默跳过
- 在 Windows AMD64 上 CodeQL 原生支持，内置查询包自动生效
- 所有新增逻辑需在 CodeQL 不可用时 graceful fallback

### 验证要求

1. 在宿主机（macOS）验证：
```bash
# 创建 CodeQL 数据库
/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-cli/codeql database create \
  /tmp/codeql-test-db \
  --language=java \
  --source-root=/Users/chenhaoming/Projects/eclipse-workspace/YP-34944-E-007/src \
  --overwrite

# 运行内置查询
/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-cli/codeql database analyze \
  /tmp/codeql-test-db \
  codeql/java-queries \
  --format=sarif-latest \
  --output=/tmp/codeql-test.sarif

# 查看结果
python3 -c "
import json
with open('/tmp/codeql-test.sarif') as f:
    d = json.load(f)
results = d['runs'][0]['results'] if d.get('runs') else []
print(f'CodeQL 内置查询发现: {len(results)} 条')
for r in results[:10]:
    print(f'  {r[\"ruleId\"]}')
"
```

2. 全量测试通过：
```bash
.venv/bin/python3 -m pytest tests/ -q
```

### 不要做的事

- ❌ 不要删除现有的自定义 CodeQL 查询（`rules/codeql/java/cnas-java.ql` 等）——保留作为补充
- ❌ 不要修改 `src/report_generator.py`（报告格式已验证）
- ❌ 不要在 Python 代码中硬编码映射表——映射必须从 JSON 文件加载
