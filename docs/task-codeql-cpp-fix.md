## 任务：彻底修复 C/C++ CodeQL 映射（69 条全部映射正确）

### 问题：现有 22 条 C/C++ 映射的文件名全部错误

之前的映射是 Clauded 猜的文件名，跟实际 CodeQL 仓库的文件对不上。例如：
- 映射写 `BufferOverflow.ql`，实际叫 `OverflowBuffer.ql`
- 映射写 `UseAfterFree.ql`，实际叫 `UseOfStringAfterLifetimeEnds.ql`

**导致：22 条映射一条都不会命中。**

同时还有 47 条 C/C++ 查询完全没映射。

### 修复方法

正确的做法：遍历 CodeQL 实际文件系统，对每个 `.ql` 文件建立映射。

```bash
# CodeQL C/C++ 安全查询实际路径
ls /Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-repo/cpp/ql/src/Security/CWE/*/*.ql

# 查看每个查询的 @name 或 @description 以理解其功能
head -5 /Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-repo/cpp/ql/src/Security/CWE/CWE-119/OverflowBuffer.ql
```

正确的映射方法（替换掉现有错误的 C/C++ 条目）：

```python
import os, json

base = "/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-repo/cpp/ql/src/Security/CWE"

# 按 CWE 分组，逐个检查每个 .ql 文件的内容以确定其映射到哪个 GB/T 条款
for cwe_dir in sorted(os.listdir(base)):
    cwe_path = os.path.join(base, cwe_dir)
    if not os.path.isdir(cwe_path):
        continue
    for ql_file in sorted(os.listdir(cwe_path)):
        if not ql_file.endswith('.ql'):
            continue
        ql_path = os.path.join(cwe_path, ql_file)
        
        # 读取查询头部的注释以理解其功能
        with open(ql_path) as f:
            header = f.read(500)
        
        rule_id = f"cpp/ql/src/Security/CWE/{cwe_dir}/{ql_file}"
        print(f"\n{rule_id}")
        print(f"  内容: {header[:200]}")
        # TODO: 根据 @name/@description 确定 GB/T 条款号
```

### 完整 C/C++ 映射表（按实际文件）

请逐个 CWE 目录检查实际的 .ql 文件，根据文件名和文件头部注释确定其对应 GB/T 条款。以下为完整的映射参考：

**内存与缓冲区安全（映射到 GB/T 39412 8.2.x 和 GB/T 34943 7.2.3.x）：**

| 实际文件路径 | CWE | 建议映射条款 |
|-----------|-----|-----------|
| `CWE-119/OverflowBuffer.ql` | 119 | 8.2.7 缓冲区溢出 |
| `CWE-119/OverrunWriteProductFlow.ql` | 119 | 8.2.7 缓冲区溢出 |
| `CWE-120/OverrunWrite.ql` | 120 | 8.2.6 内存缓冲区边界操作 |
| `CWE-120/BadlyBoundedWrite.ql` | 120 | 8.2.8 使用错误长度访问缓冲区 |
| `CWE-120/UnboundedWrite.ql` | 120 | 8.2.6 |
| `CWE-120/OverrunWriteFloat.ql` | 120 | 8.2.6 |
| `CWE-120/VeryLikelyOverrunWrite.ql` | 120 | 8.2.7 |
| `CWE-121/UnterminatedVarargsCall.ql` | 121 | 8.2.6 |
| `CWE-131/NoSpaceForZeroTerminator.ql` | 131 | 8.2.8 |
| `CWE-129/ImproperArrayIndexValidation.ql` | 129 | 8.2.8 |
| `CWE-170/ImproperNullTerminationTainted.ql` | 170 | 8.2.6 |
| `CWE-416/UseOfStringAfterLifetimeEnds.ql` | 416 | 8.2.4 访问已释放内存 |
| `CWE-416/UseOfUniquePointerAfterLifetimeEnds.ql` | 416 | 8.2.4 |
| `CWE-416/IteratorToExpiredContainer.ql` | 416 | 8.2.4 |
| `CWE-676/DangerousFunctionOverflow.ql` | 676 | 8.2.6 |
| `CWE-676/DangerousUseOfCin.ql` | 676 | 8.2.6 |
| `CWE-676/PotentiallyDangerousFunction.ql` | 676 | 8.2.6 |

**算数与逻辑安全（映射到 GB/T 34943 7.2.3.x 和 GB/T 39412 8.1.x）：**

| 实际文件路径 | CWE | 建议映射条款 |
|-----------|-----|-----------|
| `CWE-190/IntegerOverflowTainted.ql` | 190 | 7.2.3.5 整数溢出 |
| `CWE-190/ArithmeticTainted.ql` | 190 | 7.2.3.5 |
| `CWE-190/ArithmeticUncontrolled.ql` | 190 | 8.1.9 算法复杂度攻击 |
| `CWE-190/ArithmeticWithExtremeValues.ql` | 190 | 7.2.3.5 |
| `CWE-190/TaintedAllocationSize.ql` | 190 | 8.2.9 堆空间耗尽 |
| `CWE-190/ComparisonWithWiderType.ql` | 190 | 7.2.3.5 |
| `CWE-191/UnsignedDifferenceExpressionComparedZero.ql` | 191 | 7.2.3.5 |
| `CWE-193/InvalidPointerDeref.ql` | 193 | 7.5.5 指针偏移越界 |
| `CWE-835/InfiniteLoopWithUnsatisfiableExitCondition.ql` | 835 | 8.1.8 无限循环 |
| `CWE-570/IncorrectAllocationErrorHandling.ql` | 570 | 8.1.3 初始化失败后未安全退出 |

**指针与类型安全（映射到 GB/T 39412 7.5.x）：**

| 实际文件路径 | CWE | 建议映射条款 |
|-----------|-----|-----------|
| `CWE-468/IncorrectPointerScaling.ql` | 468 | 7.5.5 指针偏移越界 |
| `CWE-468/IncorrectPointerScalingChar.ql` | 468 | 7.5.5 |
| `CWE-468/IncorrectPointerScalingVoid.ql` | 468 | 7.5.5 |
| `CWE-468/SuspiciousAddWithSizeof.ql` | 468 | 7.5.5 |
| `CWE-704/WcharCharConversion.ql` | 704 | 7.5.4 |
| `CWE-843/TypeConfusion.ql` | 843 | 7.5.4 |

**并发与资源安全（映射到 GB/T 39412 7.2.x 和 8.1.x）：**

| 实际文件路径 | CWE | 建议映射条款 |
|-----------|-----|-----------|
| `CWE-764/TwiceLocked.ql` | 764 | 7.2.3 共享资源的并发安全 |
| `CWE-764/LockOrderCycle.ql` | 764 | 7.2.3 |
| `CWE-764/UnreleasedLock.ql` | 764 | 7.2.3 |
| `CWE-367/TOCTOUFilesystemRace.ql` | 367 | 7.2.3 |
| `CWE-457/ConditionallyUninitializedVariable.ql` | 457 | 8.1.2 资源不安全初始化 |
| `CWE-253/HResultBooleanConversion.ql` | 253 | 8.1.3 |
| `CWE-014/MemsetMayBeDeleted.ql` | 14 | 8.2.5 数据/内存布局 |

**注入类（映射到 GB/T 39412 6.1.x 和 8.3.x/8.4.x）：**

| 实际文件路径 | CWE | 建议映射条款 |
|-----------|-----|-----------|
| `CWE-078/ExecTainted.ql` | 78 | 6.1.1.6 命令行注入 |
| `CWE-089/SqlTainted.ql` | 89 | 8.3.2 SQL注入 |
| `CWE-022/TaintedPath.ql` | 22 | 8.4.4 路径遍历 |
| `CWE-079/CgiXss.ql` | 79 | 6.1.2.1 跨站脚本 |
| `CWE-611/XXE.ql` | 611 | 6.1.1.5 |
| `CWE-114/UncontrolledProcessOperation.ql` | 114 | 6.1.1.6 |
| `CWE-428/UnsafeCreateProcessCall.ql` | 428 | 6.1.1.6 |
| `CWE-020/CountUntrustedDataToExternalAPI.ql` | 20 | 6.1.1.1 关键状态数据外部可控 |
| `CWE-020/IRCountUntrustedDataToExternalAPI.ql` | 20 | 6.1.1.1 |
| `CWE-020/IRUntrustedDataToExternalAPI.ql` | 20 | 6.1.1.1 |
| `CWE-020/UntrustedDataToExternalAPI.ql` | 20 | 6.1.1.1 |
| `CWE-134/UncontrolledFormatString.ql` | 134 | 7.3.1 格式化字符串 |
| `CWE-807/TaintedCondition.ql` | 807 | 6.1.1.10 条件比较不充分 |

**加密与通信安全（映射到 GB/T 39412 6.2.x 和 8.5.x）：**

| 实际文件路径 | CWE | 建议映射条款 |
|-----------|-----|-----------|
| `CWE-326/InsufficientKeySize.ql` | 326 | 6.2.1.1 密码安全 |
| `CWE-327/BrokenCryptoAlgorithm.ql` | 327 | 6.2.1.1 |
| `CWE-327/OpenSslHeartbleed.ql` | 327 | 8.5.4 通信安全 |
| `CWE-311/CleartextBufferWrite.ql` | 311 | 6.2.2.1 敏感信息暴露 |
| `CWE-311/CleartextFileWrite.ql` | 311 | 6.2.2.1 |
| `CWE-311/CleartextTransmission.ql` | 311 | 8.5.4 通信安全 |
| `CWE-313/CleartextSqliteDatabase.ql` | 313 | 6.2.2.1 |
| `CWE-319/UseOfHttp.ql` | 319 | 8.5.4 |
| `CWE-295/SSLResultConflation.ql` | 295 | 8.5.4 |
| `CWE-295/SSLResultNotChecked.ql` | 295 | 8.5.4 |
| `CWE-732/DoNotCreateWorldWritable.ql` | 732 | 8.1.6 将资源暴露给非授权范围 |
| `CWE-732/OpenCallMissingModeArgument.ql` | 732 | 8.1.6 |
| `CWE-732/UnsafeDaclSecurityDescriptor.ql` | 732 | 8.1.6 |
| `CWE-497/ExposedSystemData.ql` | 497 | 6.2.2.1 |
| `CWE-497/PotentiallyExposedSystemData.ql` | 497 | 6.2.2.1 |
| `CWE-290/AuthenticationBypass.ql` | 290 | 6.3.3.1 权限访问控制 |

### 验证

修复后确认：

```bash
# 1. 验证所有 C/C++ 映射的 rule ID 都对应实际存在的文件
python3 -c "
import os, json
base = '/Users/chenhaoming/PenetrationTools/10-CodeTools/CodeQL/codeql-repo/cpp/ql/src/Security/CWE'
m = json.load(open('rules/codeql/codeql-to-gbt-mapping.json'))
cpp_keys = {k for k in m if k.startswith('cpp')}
actual = set()
for root, dirs, files in os.walk(base):
    for f in files:
        if f.endswith('.ql'):
            cwe = os.path.basename(root)
            actual.add(f'cpp/ql/src/Security/CWE/{cwe}/{f}')
valid = len(cpp_keys & actual)
invalid = len(cpp_keys - actual)
missing = len(actual - cpp_keys)
print(f'有效: {valid}, 无效: {invalid}, 遗漏: {missing}')
print(f'总计映射: {len(m)} (C/C++: {len(cpp_keys)} + Java: {len(m)-len(cpp_keys)})')
"

# 2. 测试通过
.venv/bin/python3 -m pytest tests/ -q
```

目标：
- 有效映射: 69 （全部 C/C++ 查询都映射正确）
- 无效映射: 0
- 总计 C/C++ 映射: 69 条
