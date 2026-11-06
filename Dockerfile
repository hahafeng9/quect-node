# quect.host 节点镜像：Python + xray + 哪吒探针
FROM python:3.12-slim

# 构建时尽量把 xray 与哪吒 agent 烘进镜像；下不到也不怕，app.py 启动时会再下载一次。
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/bin /app/nezha-agent \
    && (curl -fsSL -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip \
        && unzip -o -q /tmp/xray.zip -d /app/bin xray geoip.dat geosite.dat \
        && chmod +x /app/bin/xray && rm -f /tmp/xray.zip \
        && echo "xray baked into image" || echo "xray download failed at build time, app.py will retry at runtime") \
    && (curl -fsSL -o /tmp/nz.zip https://github.com/nezhahq/agent/releases/download/v2.4.0/nezha-agent_linux_amd64.zip \
        && unzip -o -q /tmp/nz.zip -d /app/nezha-agent \
        && chmod +x /app/nezha-agent/nezha-agent && rm -f /tmp/nz.zip \
        && echo "nezha-agent baked into image" || echo "nezha-agent download failed at build time, app.py will retry at runtime")

WORKDIR /app
COPY app.py .
COPY requirements.txt .

# Quect 用 HTTP port（默认 3000）做健康检查与公网入口；xray 分流器直接监听它。
EXPOSE 3000
CMD ["python", "app.py"]
