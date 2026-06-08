/**
 * CNAS GB/T 34944-2017 Java 安全检测查询
 * 覆盖: SQL注入、命令注入、XSS、路径遍历、硬编码凭据
 *
 * 每个查询对应一个 GB/T 34944 条款号
 */

import java

// ─── 6.2.3.4 SQL注入 ──────────────────────────────────────────────
from MethodAccess ma, Expr arg
where
  ma.getMethod().hasQualifiedName("java.sql", "Statement", "executeQuery")
  or ma.getMethod().hasQualifiedName("java.sql", "Statement", "execute")
  or ma.getMethod().hasQualifiedName("java.sql", "Statement", "executeUpdate")
  or ma.getMethod().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate", "query")
  or ma.getMethod().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate", "update")
select ma, "【GB/T 34944-2017 6.2.3.4】SQL注入 — 应使用 PreparedStatement 参数化查询"

// ─── 6.2.3.3 命令注入 ──────────────────────────────────────────────
from MethodAccess ma
where
  ma.getMethod().hasQualifiedName("java.lang", "Runtime", "exec")
  or ma.getMethod().hasQualifiedName("java.lang", "ProcessBuilder", ["ProcessBuilder", "start"])
select ma, "【GB/T 34944-2017 6.2.3.3】命令注入 — 应对输入进行白名单验证"

// ─── 6.2.8.1 XSS ──────────────────────────────────────────────────
from MethodAccess ma
where
  ma.getMethod().hasQualifiedName("javax.servlet", "ServletOutputStream", "print")
  or ma.getMethod().hasQualifiedName("javax.servlet", "ServletOutputStream", "write")
  or ma.getMethod().hasQualifiedName("java.io", "PrintWriter", ["print", "write"])
select ma, "【GB/T 34944-2017 6.2.8.1】跨站脚本 — 应进行 HTML 编码"

// ─── 6.2.3.1 路径遍历 ──────────────────────────────────────────────
from ClassInstanceExpr cie
where
  cie.getConstructedType().hasQualifiedName("java.io", "File")
  or cie.getConstructedType().hasQualifiedName("java.io", "FileInputStream")
  or cie.getConstructedType().hasQualifiedName("java.io", "FileReader")
select cie, "【GB/T 34944-2017 6.2.3.1】路径遍历 — 应验证文件路径"

// ─── 6.2.6.3 硬编码凭据 ────────────────────────────────────────────
from StringLiteral sl
where
  sl.getParent() instanceof EqExpr
  or sl.getParent() instanceof AssignExpr
select sl, "【GB/T 34944-2017 6.2.6.3】可能的口令硬编码 — 应使用外部配置"
