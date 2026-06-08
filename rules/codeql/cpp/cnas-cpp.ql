/**
 * CNAS GB/T 34943-2017 C/C++ 安全检测查询
 * 覆盖: 缓冲区溢出、格式化字符串、命令注入、SQL注入
 */

import cpp

// ─── 7.2.3.6 缓冲区溢出 ────────────────────────────────────────────
from FunctionCall fc
where
  fc.getTarget().hasName("strcpy")
  or fc.getTarget().hasName("strcat")
  or fc.getTarget().hasName("gets")
  or fc.getTarget().hasName("sprintf")
select fc, "【GB/T 34943-2017 7.2.3.6】缓冲区溢出 — 应使用安全函数(strncpy/snprintf)"

// ─── 7.2.3.7 格式化字符串 ──────────────────────────────────────────
from FunctionCall fc
where
  fc.getTarget().hasName("printf")
  or fc.getTarget().hasName("fprintf")
select fc, "【GB/T 34943-2017 7.2.3.7】格式化字符串 — 应使用固定格式串"

// ─── 7.2.3.3 命令注入 ──────────────────────────────────────────────
from FunctionCall fc
where
  fc.getTarget().hasName("system")
  or fc.getTarget().hasName("popen")
select fc, "【GB/T 34943-2017 7.2.3.3】命令注入 — 应验证输入"

// ─── 7.2.3.4 SQL注入 ──────────────────────────────────────────────
from FunctionCall fc
where
  fc.getTarget().hasName("mysql_query")
  or fc.getTarget().hasName("sqlite3_exec")
select fc, "【GB/T 34943-2017 7.2.3.4】SQL注入 — 应使用参数化查询"

// ─── 7.2.7.3 硬编码凭据 ────────────────────────────────────────────
from StringLiteral sl
where
  sl.getParent() instanceof FunctionCall
  and sl.getParent().(FunctionCall).getTarget().hasName("strcmp")
select sl, "【GB/T 34943-2017 7.2.7.3】可能的口令硬编码"

// ─── 8.1.1 重复释放 ──────────────────────────────────────────────
from FunctionCall fc
where
  fc.getTarget().hasName("free")
select fc, "【GB/T 39412-2020 8.1.1】重复释放 — 检查是否同一指针被释放多次"

// ─── 8.2.3 内存泄漏 ──────────────────────────────────────────────
from FunctionCall fc
where
  fc.getTarget().hasName("malloc")
  or fc.getTarget().hasName("calloc")
  or fc.getTarget().hasName("realloc")
select fc, "【GB/T 39412-2020 8.2.3】内存分配 — 检查是否在异常路径中正确释放"
