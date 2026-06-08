# Web 服务 Dockerfile — 基于现有审计平台镜像
FROM audit-platform:pro AS base

# 安装 Web 依赖
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    jinja2 \
    python-multipart \
    aiofiles \
    2>&1 | tail -1

# 拷贝 Web 代码
COPY src/web/ /app/src/web/

# Web 工作目录配置
RUN mkdir -p /workspace/projects /workspace/report /workspace/web

ENV WEB_WORKSPACE=/workspace/projects

EXPOSE 8000

# 覆盖基础镜像的 entrypoint（它期望 scan/feedback 等 CLI 命令）
ENTRYPOINT []
WORKDIR /app
ENV PYTHONPATH=/app
CMD ["uvicorn", "src.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
