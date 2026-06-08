## 任务：补充 Java CodeQL 内置查询 → GB/T 映射

项目路径：`/Users/chenhaoming/Projects/AIProjects/audit-platform`

### 现状

当前 `rules/codeql/codeql-to-gbt-mapping.json` 只有 C/C++ 的映射（22条），缺少 Java 的映射。

宿主机上 Java CodeQL 查询有 **63 个 CWE 目录**，每个目录下有若干 `.ql` 文件，总计约 80+ 条安全查询。

### 确认可用查询

```bash
# Java 安全查询目录
ls /Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-repo/java/ql/src/Security/CWE/

# 查看每个 CWE 目录下的 .ql 文件
for dir in /Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-repo/java/ql/src/Security/CWE/*/; do
  cwe=$(basename "$dir")
  qls=$(ls "$dir"*.ql 2>/dev/null)
  if [ -n "$qls" ]; then
    echo "$cwe:"
    for ql in $qls; do
      echo "  $(basename $ql)"
    done
  fi
done
```

### 任务

在 `rules/codeql/codeql-to-gbt-mapping.json` 中追加 Java 查询的映射条目。

每个条目的格式（与现有 C/C++ 条目保持一致）：

```json
"java/ql/src/Security/CWE/CWE-XXX/QueryName.ql": {
  "gb_clause": "X.X.X.X",
  "gb_standard": "GB/T 34944-2017",
  "vuln_name": "漏洞中文名称",
  "cwe": "CWE-XXX"
}
```

**注意**：rule ID 的实际格式可能在运行时有所差异。请在宿主机上先运行一次 CodeQL Java 查询确认实际的 SARIF rule ID 格式。

### Java → GB/T 映射表

按 CWE 分组列出所有可映射的 Java 查询：

#### 注入类（映射到 GB/T 34944-2017）

| CodeQL 查询 | CWE | GB/T 条款 | 漏洞名称 |
|------------|-----|----------|---------|
| `CWE-089/SqlTainted.ql` | CWE-89 | 6.2.3.4 | SQL注入 |
| `CWE-089/SqlConcatenated.ql` | CWE-89 | 6.2.3.4 | SQL注入（字符串拼接） |
| `CWE-078/ExecTainted.ql` | CWE-78 | 6.2.3.3 | 命令注入 |
| `CWE-078/ExecRelative.ql` | CWE-78 | 6.2.3.3 | 命令注入（相对路径） |
| `CWE-078/ExecTaintedEnvironment.ql` | CWE-78 | 6.2.3.3 | 命令注入（环境变量） |
| `CWE-079/XSS.ql` | CWE-79 | 6.2.8.1 | 跨站脚本 |
| `CWE-022/TaintedPath.ql` | CWE-22 | 6.2.3.2 | 路径遍历 |
| `CWE-022/ZipSlip.ql` | CWE-22 | 6.2.3.2 | Zip Slip路径遍历 |
| `CWE-094/GroovyInjection.ql` | CWE-94 | 6.2.3.5 | 代码注入（Groovy） |
| `CWE-094/InsecureBeanValidation.ql` | CWE-94 | 6.2.3.5 | Bean验证注入 |
| `CWE-090/LdapInjection.ql` | CWE-90 | 6.2.3.12 | LDAP注入 |
| `CWE-643/XPathInjection.ql` | CWE-643 | 6.2.3.12 | XPath注入 |
| `CWE-917/OgnlInjection.ql` | CWE-917 | 6.2.3.5 | OGNL表达式注入 |
| `CWE-611/XXE.ql` | CWE-611 | 6.2.3.12 | XML外部实体注入 |
| `CWE-918/RequestForgery.ql` | CWE-918 | 6.2.8.2 | SSRF服务端请求伪造 |
| `CWE-113/ResponseSplitting.ql` | CWE-113 | 6.2.8.3 | HTTP响应拆分 |
| `CWE-113/NettyResponseSplitting.ql` | CWE-113 | 6.2.8.3 | Netty响应拆分 |
| `CWE-117/LogInjection.ql` | CWE-117 | 6.2.3.8 | 日志注入 |

#### 加密与认证类（映射到 GB/T 34944-2017）

| CodeQL 查询 | CWE | GB/T 条款 | 漏洞名称 |
|------------|-----|----------|---------|
| `CWE-326/InsufficientKeySize.ql` | CWE-326 | 6.2.6.7 | 使用已破解的加密算法（密钥长度不足） |
| `CWE-327/BrokenCryptoAlgorithm.ql` | CWE-327 | 6.2.6.7 | 使用已破解的加密算法 |
| `CWE-327/MaybeBrokenCryptoAlgorithm.ql` | CWE-327 | 6.2.6.7 | 可能的安全加密算法问题 |
| `CWE-330/InsecureRandomness.ql` | CWE-330 | 6.2.6.10 | 不充分的随机数 |
| `CWE-522/InsecureBasicAuth.ql` | CWE-522 | 6.2.6.1 | 明文传输认证信息 |
| `CWE-522/InsecureLdapAuth.ql` | CWE-522 | 6.2.6.1 | LDAP认证信息明文传输 |
| `CWE-798/HardcodedCredentialsApiCall.ql` | CWE-798 | 6.2.6.3 | 口令硬编码（API调用） |
| `CWE-798/HardcodedCredentialsComparison.ql` | CWE-798 | 6.2.6.3 | 口令硬编码（比较） |
| `CWE-798/HardcodedCredentialsSourceCall.ql` | CWE-798 | 6.2.6.3 | 口令硬编码（源码中） |
| `CWE-614/InsecureCookie.ql` | CWE-614 | 6.2.6.17 | Cookie未设置安全属性 |
| `CWE-295/InsecureTrustManager.ql` | CWE-295 | 6.2.6.6 | 不安全的证书信任管理器 |
| `CWE-297/UnsafeHostnameVerification.ql` | CWE-297 | 6.2.6.6 | 不安全的主机名验证 |
| `CWE-319/HttpsUrls.ql` | CWE-319 | 6.2.6.6 | 敏感信息明文传输 |
| `CWE-319/UseSSL.ql` | CWE-319 | 6.2.6.6 | 未使用SSL |

#### Web安全类（映射到 GB/T 34944-2017）

| CodeQL 查询 | CWE | GB/T 条款 | 漏洞名称 |
|------------|-----|----------|---------|
| `CWE-352/CsrfUnprotectedRequestType.ql` | CWE-352 | 6.2.8.2 | 跨站请求伪造 |
| `CWE-352/SpringCSRFProtection.ql` | CWE-352 | 6.2.8.2 | Spring CSRF防护缺失 |
| `CWE-601/UrlRedirect.ql` | CWE-601 | 6.2.8.4 | 开放重定向 |
| `CWE-502/UnsafeDeserialization.ql` | CWE-502 | 6.2.5.1 | 不安全的反序列化 |
| `CWE-807/ConditionalBypass.ql` | CWE-807 | 6.2.6.4 | 依赖不可信条件绕过认证 |
| `CWE-807/TaintedPermissionsCheck.ql` | CWE-807 | 6.2.6.4 | 受污染的权限检查 |
| `CWE-020/UntrustedDataToExternalAPI.ql` | CWE-20 | 6.2.3.1 | 不可信数据传给外部API |
| `CWE-020/ExternalAPIsUsedWithUntrustedData.ql` | CWE-20 | 6.2.3.1 | 外部API使用不可信数据 |

#### 配置与信息泄露类（映射到 GB/T 34944-2017）

| CodeQL 查询 | CWE | GB/T 条款 | 漏洞名称 |
|------------|-----|----------|---------|
| `CWE-312/CleartextStorageAndroidDatabase.ql` | CWE-312 | 6.2.6.1 | 明文存储敏感数据（数据库） |
| `CWE-312/CleartextStorageAndroidFilesystem.ql` | CWE-312 | 6.2.6.1 | 明文存储敏感数据（文件系统） |
| `CWE-829/InsecureDependencyResolution.ql` | CWE-829 | 6.2.2.1 | 不安全的依赖解析 |
| `CWE-833/LockOrderInconsistency.ql` | CWE-833 | 6.2.7.1 | 锁顺序不一致 |

#### 映射到 GB/T 39412-2020 的 Java 查询

部分 Java 查询覆盖的漏洞类型在 39412 中有对应条款（且与 34944 的分配不同时）：

| CodeQL 查询 | CWE | GB/T 条款 | 漏洞名称 |
|------------|-----|----------|---------|
| `CWE-134/FormatString.ql` | CWE-134 | 7.3.1 | 格式化字符串（Java 也适用） |
| `CWE-190/ArithmeticTainted.ql` | CWE-190 | 8.1.9 | 算法逻辑问题 |
| `CWE-835/InfiniteLoop.ql` | CWE-835 | 8.1.8 | 无限循环 |
| `CWE-367/TOCTOU.ql` | CWE-367 | 7.2.3 | 竞态条件 |
| `CWE-676/DangerousFunction.ql` | CWE-676 | 8.2.6 | 危险函数调用 |
| `CWE-489/ActiveDebugCode.ql` | CWE-489 | 9.1 | 遗留调试代码 |
| `CWE-501/TrustBoundaryViolation.ql` | CWE-501 | 6.1.1.15 | 数据信任边界违背 |
| `CWE-524/CleartextStorage.ql` | CWE-524 | 6.2.2.1 | 敏感信息暴露 |
| `CWE-532/InfoExposureLog.ql` | CWE-532 | 6.4.2 | 日志信息丢失或遗漏 |
| `CWE-552/UnsafeFileUpload.ql` | CWE-552 | 8.4.2 | 不安全的文件上传 |

### 验证宿主机 SARIF rule ID 格式

在宿主机上跑一次 CodeQL Java 查询，确认 SARIF 中的 rule ID 格式与映射文件的 key 是否匹配：

```bash
# 先用测试项目建数据库
/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-cli/codeql database create \
  /tmp/java-codeql-db --language=java \
  --source-root=/Users/chenhaoming/Projects/eclipse-workspace/YP-34944-E-007/src \
  --overwrite 2>&1 | tail -5

# 运行内置查询
/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-cli/codeql database analyze \
  /tmp/java-codeql-db codeql/java-queries --format=sarif-latest \
  --output=/tmp/java-codeql.sarif 2>&1 | tail -5

# 查看 rule ID 格式
python3 << 'EOF'
import json
with open('/tmp/java-codeql.sarif') as f:
    d = json.load(f)
rules = d['runs'][0]['tool']['driver']['rules']
results = d['runs'][0].get('results', [])
print(f"规则数: {len(rules)}, 发现数: {len(results)}")
print("\n首个 rule ID:", rules[0]['id'] if rules else '无')
print("示例 rule ID:", [r['ruleId'] for r in results[:3]] if results else '无发现')
EOF
```

根据实际的 SARIF rule ID 格式调整映射文件中的 key。

### 完成确认

```bash
python3 -c "
import json
m = json.load(open('rules/codeql/codeql-to-gbt-mapping.json'))
cpp = sum(1 for k in m if k.startswith('cpp'))
java = sum(1 for k in m if k.startswith('java'))
print(f'C/C++ 映射: {cpp}, Java 映射: {java}, 总计: {len(m)}')
"

.venv/bin/python3 -m pytest tests/ -q
```
