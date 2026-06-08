"""CNAS 代码安全审计平台 —— Web 服务入口。

FastAPI + Jinja2 + SQLite。后台任务不阻塞 HTTP 响应。

启动: uvicorn src.web.app:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

# ─── 请求模型 ───────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    """扫描请求参数。"""
    standard: str = ""
    offline: bool = True

from .models.scan import get_db, init_db
from .tasks import run_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("web")

# ─── 初始化 ───────────────────────────────────────────────────────

init_db()

app = FastAPI(title="CNAS 代码安全审计平台")

# 静态文件 & 模板
BASE_DIR = Path(__file__).parent
static_dir = BASE_DIR / "static"
template_dir = BASE_DIR / "templates"

if static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

templates = Jinja2Templates(directory=str(template_dir)) if template_dir.is_dir() else None

WORKSPACE = Path(os.environ.get("WEB_WORKSPACE", "/workspace/projects"))


# ─── 工具函数 ─────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_row(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "source_type": row["source_type"],
        "git_url": row["git_url"] or "",
        "created_at": row["created_at"],
    }


def _scan_row(row) -> dict:
    return {
        "id": row["id"],
        "project_id": row["project_id"],
        "status": row["status"],
        "standard": row["standard"] or "",
        "offline": bool(row["offline"]),
        "total_findings": row["total_findings"],
        "report_dir": row["report_dir"] or "",
        "started_at": row["started_at"] or "",
        "finished_at": row["finished_at"] or "",
        "error_message": row["error_message"] or "",
    }


# ─── 页面路由 ─────────────────────────────────────────────────────


@app.get("/")
async def index(request: Request):
    """首页：项目列表。"""
    return templates.TemplateResponse(request, "index.html")


@app.get("/projects/{project_id}")
async def project_page(project_id: int, request: Request):
    """项目详情页。"""
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj:
        conn.close()
        raise HTTPException(404, "项目不存在")
    scans = conn.execute(
        "SELECT * FROM scans WHERE project_id = ? ORDER BY id DESC", (project_id,)
    ).fetchall()
    conn.close()
    return templates.TemplateResponse(
        request,
        "scan.html",
        {
            "project": _project_row(proj),
            "scans": [_scan_row(s) for s in scans],
        },
    )


@app.get("/scans/{scan_id}")
async def report_page(scan_id: int, request: Request):
    """报告查看页。"""
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(404, "扫描不存在")
    proj = conn.execute(
        "SELECT * FROM projects WHERE id = ?", (scan["project_id"],)
    ).fetchone()
    conn.close()

    # 读取报告 JSON
    report_data = None
    report_json = os.path.join(scan["report_dir"], "report.json") if scan["report_dir"] else ""
    if report_json and os.path.isfile(report_json):
        with open(report_json, encoding="utf-8") as f:
            report_data = json.load(f)

    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "project": _project_row(proj) if proj else {},
            "scan": _scan_row(scan),
            "report": report_data,
        },
    )


# ─── API: 项目管理 ────────────────────────────────────────────────


@app.post("/api/projects")
async def create_project(
    name: str = Form(...),
    file: UploadFile | None = None,
    git_url: str = Form(""),
):
    """创建项目：上传 ZIP 文件或指定 Git 仓库地址。"""
    conn = get_db()

    project_id_row = conn.execute(
        "INSERT INTO projects (name, source_type, git_url, created_at) VALUES (?, ?, ?, ?)",
        (name, "upload" if file else "git", git_url or "", _now()),
    ).lastrowid
    conn.commit()

    # 创建工作目录
    project_dir = WORKSPACE / str(project_id_row)
    project_dir.mkdir(parents=True, exist_ok=True)

    if file and file.filename:
        # ── ZIP 上传 ──
        if not file.filename.endswith(".zip"):
            conn.close()
            raise HTTPException(400, "仅支持 ZIP 文件上传")

        zip_path = project_dir / "upload.zip"
        with open(zip_path, "wb") as f:
            content = await file.read()
            f.write(content)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(project_dir)
            zip_path.unlink()  # 删除临时 ZIP
        except zipfile.BadZipFile:
            conn.close()
            raise HTTPException(400, "无效的 ZIP 文件")

        conn.execute(
            "UPDATE projects SET source_path = ? WHERE id = ?",
            (str(project_dir), project_id_row),
        )

    elif git_url:
        # ── Git 仓库克隆 ──
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", git_url, str(project_dir)],
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.CalledProcessError as e:
            conn.close()
            raise HTTPException(400, f"Git 克隆失败: {e.stderr[:200]}")
        except subprocess.TimeoutExpired:
            conn.close()
            raise HTTPException(400, "Git 克隆超时")

        conn.execute(
            "UPDATE projects SET source_path = ? WHERE id = ?",
            (str(project_dir), project_id_row),
        )
    else:
        conn.close()
        raise HTTPException(400, "请上传 ZIP 文件或提供 Git 仓库地址")

    conn.commit()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id_row,)).fetchone()
    conn.close()

    logger.info("项目创建: id=%d name=%s type=%s", project_id_row, name, "upload" if file else "git")
    return _project_row(proj)


@app.get("/api/projects")
async def list_projects():
    """项目列表。"""
    conn = get_db()
    rows = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
    conn.close()
    return [_project_row(r) for r in rows]


@app.get("/api/projects/{project_id}")
async def get_project(project_id: int):
    """项目详情。"""
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    conn.close()
    if not proj:
        raise HTTPException(404, "项目不存在")
    return _project_row(proj)


# ─── API: 扫描管理 ────────────────────────────────────────────────


@app.post("/api/projects/{project_id}/scans")
async def start_scan(
    project_id: int,
    background_tasks: BackgroundTasks,
    body: ScanRequest,
):
    """触发异步扫描。"""
    conn = get_db()
    proj = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj:
        conn.close()
        raise HTTPException(404, "项目不存在")
    if not proj["source_path"] or not os.path.isdir(proj["source_path"]):
        conn.close()
        raise HTTPException(400, "项目代码目录不存在，请先上传代码")

    scan_id = conn.execute(
        """INSERT INTO scans (project_id, status, standard, offline, started_at)
           VALUES (?, 'pending', ?, ?, ?)""",
        (project_id, body.standard, int(body.offline), _now()),
    ).lastrowid
    conn.commit()
    conn.close()

    # 启动后台任务
    background_tasks.add_task(run_scan, scan_id, body.standard, body.offline)

    logger.info("扫描已入队: scan_id=%d project_id=%d standard=%s", scan_id, project_id, body.standard)
    return {"scan_id": scan_id, "status": "pending"}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    """扫描状态查询。"""
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan:
        raise HTTPException(404, "扫描不存在")
    return _scan_row(scan)


@app.get("/api/projects/{project_id}/scans")
async def list_scans(project_id: int):
    """某项目的扫描历史。"""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scans WHERE project_id = ? ORDER BY id DESC", (project_id,)
    ).fetchall()
    conn.close()
    return [_scan_row(r) for r in rows]


# ─── API: 报告下载 ────────────────────────────────────────────────


@app.get("/api/scans/{scan_id}/report")
async def get_report_json(scan_id: int):
    """获取报告 JSON。"""
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan:
        raise HTTPException(404, "扫描不存在")
    if scan["status"] != "done":
        raise HTTPException(400, "扫描尚未完成")

    report_path = os.path.join(scan["report_dir"], "report.json")
    if not os.path.isfile(report_path):
        raise HTTPException(404, "报告文件不存在")

    with open(report_path, encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/scans/{scan_id}/report.docx")
async def download_docx(scan_id: int):
    """下载 DOCX 报告。"""
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan or scan["status"] != "done":
        raise HTTPException(404, "扫描不存在或未完成")

    path = os.path.join(scan["report_dir"], "report.docx")
    if not os.path.isfile(path):
        raise HTTPException(404, "DOCX 报告不存在")

    return FileResponse(
        path,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=f"report-{scan_id}.docx",
    )


@app.get("/api/scans/{scan_id}/report.md")
async def download_markdown(scan_id: int):
    """下载 Markdown 报告。"""
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan or scan["status"] != "done":
        raise HTTPException(404, "扫描不存在或未完成")

    path = os.path.join(scan["report_dir"], "report.md")
    if not os.path.isfile(path):
        raise HTTPException(404, "Markdown 报告不存在")

    return FileResponse(path, media_type="text/markdown", filename=f"report-{scan_id}.md")


# ─── API: 统计 ────────────────────────────────────────────────────


@app.get("/api/stats")
async def get_stats():
    """统计面板数据。"""
    conn = get_db()
    total_projects = conn.execute("SELECT COUNT(*) as n FROM projects").fetchone()["n"]
    total_scans = conn.execute("SELECT COUNT(*) as n FROM scans").fetchone()["n"]
    done_scans = conn.execute(
        "SELECT COUNT(*) as n FROM scans WHERE status = 'done'"
    ).fetchone()["n"]
    total_findings = conn.execute(
        "SELECT COALESCE(SUM(total_findings), 0) as n FROM scans WHERE status = 'done'"
    ).fetchone()["n"]
    conn.close()

    return {
        "total_projects": total_projects,
        "total_scans": total_scans,
        "done_scans": done_scans,
        "total_findings": total_findings,
    }
