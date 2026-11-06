#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""quect.host 单文件节点：xray + 订阅服务 + 哪吒探针，三合一。

部署：quect.host 面板从 GitHub 仓库发布（Dockerfile 构建）。
  - xray 单端口设计：公开 HTTP 端口（环境变量 PORT，默认 3000）上是个纯 TCP 分流器，
    按 WS 路径分到 VLESS+WS（8004）、VMess（8002）、Trojan（8003），
    其余流量 fallback 到 3100 订阅服务。只给一个公网 HTTPS 地址（*.quect.cloud），
    所以三协议 + 订阅全走这一个端口、同一个域名。
  - 哪吒探针跑后台线程：自动下载 agent、写 config.yml、挂了自动重启。
  - 节点凭据（UUID、Trojan 密码、路径密钥）全部走环境变量，不写进仓库；
    PUBLIC_URL（公网域名，如 p-quect-xxxx.quect.cloud）发布后在面板设一次，
    设好重启应用即发 TG 通知；没设 PUBLIC_URL 时节点照常跑，只是不发 TG。
环境变量：
  PORT（公开 HTTP 端口，默认 3000；须和面板里填的 HTTP port 一致）
  PUBLIC_URL（公网域名，可带或不带 https://，如 p-quect-xxxx.quect.cloud）
  NODE_UUID、NODE_TROJAN_PW、NODE_S1、NODE_S2、NODE_S3（节点凭据）
  TG_BOT_TOKEN、TG_CHAT_ID（TG 通知）
  NZ_CLIENT_SECRET（哪吒密钥；也可放 client_secret.txt）
  NZ_SERVER、NZ_TLS、NZ_VERSION（哪吒面板，默认 nezha2026.5785787.xyz:443）
"""

import base64
import json
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent


def node_log(msg):
    print(f"[quect-node] {msg}", flush=True)


# ============================== 基础配置 ==============================
BIN_DIR = BASE / "bin"
CONFIG_FILE = BASE / "xray-config.json"
SUB_TXT = BASE / "sub.txt"
LINKS_TXT = BASE / "links.txt"
XRAY_LOG = BASE / "xray.log"

XRAY_VERSION = "v26.10.31"
XRAY_URL = (
    "https://github.com/XTLS/Xray-core/releases/download/"
    + XRAY_VERSION
    + "/Xray-linux-64.zip"
)

# 公开 HTTP 端口：Quect 网关把 HTTPS 转到这里，xray 分流器直接监听它。
PUBLIC_PORT = int(os.environ.get("PORT") or "3000")
# 订阅服务端口（内网，xray fallback 指过来）
SUB_PORT = 3100
VMESS_PORT = 8002
TROJAN_PORT = 8003
VLESS_WS_PORT = 8004
SUB_PATH = "sub"

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "").strip()

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

_links = {"text": "", "b64": ""}
_public_url = ""


def public_host():
    """公网域名（去 https:// 前缀、去尾斜杠），没设就返回空。"""
    u = (os.environ.get("PUBLIC_URL", "").strip()
         or _public_url)
    u = u.replace("https://", "").replace("http://", "").strip().strip("/")
    return u.split("/")[0] if u else ""


def node_creds():
    """节点凭据：全走环境变量；缺了就现生成（仅本次运行有效，重启会变，
    所以部署时务必在面板把这 5 项设成固定值）。"""
    creds = {
        "uuid": os.environ.get("NODE_UUID", "").strip() or str(uuid.uuid4()),
        "trojan_pw": os.environ.get("NODE_TROJAN_PW", "").strip() or secrets.token_urlsafe(16),
        "s1": os.environ.get("NODE_S1", "").strip() or secrets.token_hex(3),
        "s2": os.environ.get("NODE_S2", "").strip() or secrets.token_hex(3),
        "s3": os.environ.get("NODE_S3", "").strip() or secrets.token_hex(3),
    }
    if not os.environ.get("NODE_UUID"):
        node_log("警告：NODE_UUID 未设，本次随机生成，重启后链接会变，请在面板设固定值")
    return creds


STATE = node_creds()


# ============================== 下载 ==============================
def _http_get(url, dest, tries=3):
    last_err = None
    for attempt in range(1, tries + 1):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=180) as r, open(dest, "wb") as f:
                while True:
                    chunk = r.read(1024 * 256)
                    if not chunk:
                        break
                    f.write(chunk)
            if dest.stat().st_size < 1_000_000:
                raise RuntimeError(f"文件只有 {dest.stat().st_size} 字节，疑似错误页")
            return True
        except Exception as e:
            last_err = e
            node_log(f"下载失败（第 {attempt} 次）：{url} -> {e}")
            try:
                dest.unlink()
            except FileNotFoundError:
                pass
            time.sleep(5)
    node_log(f"下载最终失败：{url}：{last_err}")
    return False


def ensure_xray():
    exe = BIN_DIR / "xray"
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if exe.exists() and exe.stat().st_size >= 1_000_000:
        node_log("xray 已存在，直接使用")
        return
    node_log(f"下载 xray {XRAY_VERSION} ...")
    zf = BIN_DIR / "xray.zip"
    if not _http_get(XRAY_URL, zf):
        raise RuntimeError("xray 下载失败")
    with zipfile.ZipFile(zf) as z:
        for name in ("xray", "geoip.dat", "geosite.dat"):
            try:
                z.extract(name, BIN_DIR)
            except KeyError:
                pass
    zf.unlink(missing_ok=True)
    exe.chmod(0o755)
    if not exe.exists():
        raise RuntimeError("解压后找不到 xray")
    node_log("xray 就绪")


# ============================== xray 配置与链接 ==============================
def build_xray_config():
    # 单端口设计：公开端口是纯 TCP 分流器（VLESS+TCP），按 WS 路径分流到三个 WS 入站。
    # 注意：主入站必须是 TCP——如果主入站本身是 WS，WS 层会先按自己的 path 校验、
    # 不匹配直接 404，fallback 根本没机会分流（2026-11-06 本地双版本实测）。
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": PUBLIC_PORT,
                "listen": "0.0.0.0",
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": STATE["uuid"], "flow": ""}],
                    "decryption": "none",
                    "fallbacks": [
                        {"path": f"/vless-{STATE['s1']}", "dest": VLESS_WS_PORT},
                        {"path": f"/vmess-{STATE['s2']}", "dest": VMESS_PORT},
                        {"path": f"/trojan-{STATE['s3']}", "dest": TROJAN_PORT},
                        {"dest": SUB_PORT},
                    ],
                },
                "streamSettings": {"network": "tcp"},
            },
            {
                "port": VLESS_WS_PORT,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": STATE["uuid"], "flow": ""}],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {"path": f"/vless-{STATE['s1']}"},
                },
            },
            {
                "port": VMESS_PORT,
                "listen": "127.0.0.1",
                "protocol": "vmess",
                "settings": {"clients": [{"id": STATE["uuid"], "alterId": 0}]},
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {"path": f"/vmess-{STATE['s2']}"},
                },
            },
            {
                "port": TROJAN_PORT,
                "listen": "127.0.0.1",
                "protocol": "trojan",
                "settings": {"clients": [{"password": STATE["trojan_pw"]}]},
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {"path": f"/trojan-{STATE['s3']}"},
                },
            },
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
    }
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg


def build_links(host):
    u = STATE["uuid"]
    s1, s2, s3 = STATE["s1"], STATE["s2"], STATE["s3"]
    pw = urllib.parse.quote(STATE["trojan_pw"], safe="")
    vless = (
        f"vless://{u}@{host}:443?encryption=none&security=tls&sni={host}"
        f"&fp=chrome&type=ws&host={host}&path=%2Fvless-{s1}#Quect-VLESS"
    )
    vmess_json = {
        "v": "2", "ps": "Quect-VMess", "add": host, "port": "443",
        "id": u, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": host, "path": f"/vmess-{s2}", "tls": "tls", "sni": host,
    }
    vmess = "vmess://" + base64.b64encode(
        json.dumps(vmess_json, separators=(",", ":")).encode()
    ).decode()
    trojan = (
        f"trojan://{pw}@{host}:443?security=tls&sni={host}"
        f"&type=ws&host={host}&path=%2Ftrojan-{s3}#Quect-Trojan"
    )
    text = "\n".join([vless, vmess, trojan])
    b64 = base64.b64encode(text.encode()).decode()
    _links["text"] = text
    _links["b64"] = b64
    SUB_TXT.write_text(b64, encoding="utf-8")
    LINKS_TXT.write_text(text, encoding="utf-8")
    return b64


# ============================== TG 通知 ==============================
def tg_notify(text):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False
    try:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        body = json.dumps({"chat_id": TG_CHAT_ID, "text": text}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", **UA})
        with urllib.request.urlopen(req, timeout=20) as r:
            ok = json.loads(r.read().decode("utf-8")).get("ok")
        if ok:
            node_log("TG 通知已发送")
            return True
        node_log("TG 通知发送失败：Telegram 返回 ok=false")
    except Exception as e:
        node_log(f"TG 通知发送失败：{e}")
    return False


def tg_notify_links(host):
    lines = [
        "Quect 节点已上线",
        f"地址：https://{host}",
        f"订阅：https://{host}/{SUB_PATH}",
        "",
        _links["text"],
    ]
    return tg_notify("\n".join(lines))


# ============================== 订阅 HTTP 服务 ==============================
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == f"/{SUB_PATH}":
            if _links["b64"]:
                self._send(200, _links["b64"])
            else:
                self._send(503, "subscription not ready yet")
        elif path == "/links":
            self._send(200, _links["text"] or "subscription not ready yet")
        elif path == "/":
            host = public_host() or "waiting for PUBLIC_URL..."
            body = (
                "Quect node is running.\n"
                f"Public address: https://{host}\n"
                f"Subscription: https://{host}/{SUB_PATH}\n"
            )
            self._send(200, body)
        else:
            self._send(404, "not found")


def start_http():
    srv = ThreadingHTTPServer(("0.0.0.0", SUB_PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    node_log(f"订阅服务已启动：0.0.0.0:{SUB_PORT}，订阅路径 /{SUB_PATH}")
    return srv


# ============================== 进程管理 ==============================
def _popen(argv, logfile=None):
    if logfile:
        f = open(logfile, "ab")
        proc = subprocess.Popen(argv, stdout=f, stderr=subprocess.STDOUT)
        proc._log_handle = f
        return proc
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_xray():
    build_xray_config()
    proc = _popen([str(BIN_DIR / "xray"), "-c", str(CONFIG_FILE)], logfile=XRAY_LOG)
    time.sleep(2)
    if proc.poll() is not None:
        raise RuntimeError(f"xray 启动后立即退出，返回码 {proc.poll()}，见 xray.log")
    node_log(f"xray 已启动（分流器监听 0.0.0.0:{PUBLIC_PORT}）")
    return proc


def stop_proc(proc):
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    except Exception:
        pass
    h = getattr(proc, "_log_handle", None)
    if h:
        try:
            h.close()
        except Exception:
            pass


# ============================== 主流程 ==============================
def node_main():
    node_log(f"启动：公开端口 {PUBLIC_PORT}，订阅端口 {SUB_PORT}")
    ensure_xray()
    start_http()
    host = public_host()
    if host:
        build_links(host)
        node_log(f"公网地址：https://{host}")
        node_log(f"订阅地址：https://{host}/{SUB_PATH}")
    else:
        node_log("PUBLIC_URL 未设：节点照常跑，TG 通知暂不发；请在面板设 PUBLIC_URL 后重启应用")
        build_links("localhost")
    xray = None
    backoff = 5
    tg_sent = False
    try:
        while True:
            try:
                if xray is None or xray.poll() is not None:
                    if xray is not None:
                        node_log(f"xray 退出了（返回码 {xray.poll()}），重启")
                    xray = start_xray()
                # PUBLIC_URL 可能在运行中被改了（面板改环境变量会重启应用，这里只是兜底）
                if not tg_sent and public_host():
                    if tg_notify_links(public_host()):
                        tg_sent = True
                backoff = 5
                time.sleep(5)
            except RuntimeError as e:
                node_log(f"故障：{e}，{backoff} 秒后重试")
                stop_proc(xray)
                xray = None
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
    except KeyboardInterrupt:
        pass
    finally:
        stop_proc(xray)


# ============================== 哪吒探针 ==============================
VERSION = os.environ.get("NZ_VERSION", "v2.4.0").strip() or "v2.4.0"
SERVER = os.environ.get("NZ_SERVER", "nezha2026.5785787.xyz:443").strip() or "nezha2026.5785787.xyz:443"
TLS = os.environ.get("NZ_TLS", "true").strip().lower() not in ("0", "false", "no", "off")
AGENT_DIR = BASE / "nezha-agent"
CONFIG_PATH = AGENT_DIR / "config.yml"
AGENT_LOG = AGENT_DIR / "agent.log"
UUID_PATH = AGENT_DIR / "uuid.txt"
RELEASE_BASE = "https://github.com/nezhahq/agent/releases/download"


def nz_log(msg):
    print(f"[nezha-installer] {msg}", flush=True)


def get_secret():
    secret = os.environ.get("NZ_CLIENT_SECRET", "").strip()
    if secret:
        return secret
    f = BASE / "client_secret.txt"
    if f.exists():
        secret = f.read_text(encoding="utf-8").strip().strip('"').strip("'")
        if secret:
            return secret
    return ""


def get_uuid():
    if UUID_PATH.exists():
        u = UUID_PATH.read_text(encoding="utf-8").strip()
        if u:
            return u
    u = str(uuid.uuid4())
    UUID_PATH.write_text(u, encoding="utf-8")
    return u


def platform_asset():
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("aarch64", "arm64") else "amd64"
    return f"nezha-agent_linux_{arch}.zip", "zip"


def download(url, dest, tries=3):
    for attempt in range(1, tries + 1):
        try:
            nz_log(f"下载 {url}（第 {attempt} 次）")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f, length=1024 * 256)
            size = dest.stat().st_size
            if size < 1_000_000:
                raise RuntimeError(f"下载到的文件只有 {size} 字节，可能是错误页")
            nz_log(f"下载完成：{size / 1024 / 1024:.1f} MB")
            return
        except Exception as e:
            nz_log(f"下载失败：{e}")
            if attempt == tries:
                raise
            time.sleep(5)


def ensure_agent():
    binary = AGENT_DIR / "nezha-agent"
    if binary.exists():
        nz_log(f"agent 已存在，直接使用：{binary}")
        return binary
    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    asset, kind = platform_asset()
    url = f"{RELEASE_BASE}/{VERSION}/{asset}"
    archive = AGENT_DIR / asset
    download(url, archive)
    nz_log("解压中...")
    with zipfile.ZipFile(archive) as z:
        z.extractall(AGENT_DIR)
    archive.unlink(missing_ok=True)
    binary.chmod(0o755)
    if not binary.exists():
        raise RuntimeError(f"解压后找不到 {binary}")
    nz_log(f"agent 就绪：{binary}")
    return binary


def write_config(secret, machine_uuid):
    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    content = (
        f"client_secret: {secret}\n"
        f"debug: false\n"
        f"disable_auto_update: true\n"
        f"disable_command_execute: true\n"
        f"server: {SERVER}\n"
        f"tls: {'true' if TLS else 'false'}\n"
        f"uuid: {machine_uuid}\n"
    )
    if CONFIG_PATH.exists() and CONFIG_PATH.read_text(encoding="utf-8") == content:
        return
    CONFIG_PATH.write_text(content, encoding="utf-8")
    nz_log("config.yml 已写入")


def nezha_main():
    nz_log(f"系统：{platform.system()} {platform.machine()}，agent 版本：{VERSION}，面板：{SERVER}")
    secret = get_secret()
    if not secret:
        nz_log("缺少密钥：请在面板环境变量里设 NZ_CLIENT_SECRET，")
        nz_log("或在 app.py 同目录放一个 client_secret.txt，里面只写密钥一行。")
        return
    binary = ensure_agent()
    machine_uuid = get_uuid()
    write_config(secret, machine_uuid)
    backoff = 5
    while True:
        nz_log(f"启动 agent，uuid：{machine_uuid}")
        logf = open(AGENT_LOG, "a", encoding="utf-8", errors="replace")
        try:
            logf.write(f"\n===== agent 启动 {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n")
            logf.flush()
            proc = subprocess.Popen([str(binary), "-c", str(CONFIG_PATH)],
                                    stdout=logf, stderr=subprocess.STDOUT)
            try:
                rc = proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                raise
        finally:
            logf.close()
        nz_log(f"agent 退出（返回码 {rc}），{backoff} 秒后重启（原因见 nezha-agent/agent.log）")
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)


# ============================== 启动器 ==============================
def _run_nezha_forever():
    backoff = 5
    while True:
        try:
            nezha_main()
        except KeyboardInterrupt:
            raise
        except BaseException as e:
            node_log(f"nezha-installer 退出（{e}），{backoff} 秒后重启")
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)


def _run_node_forever():
    backoff = 5
    while True:
        try:
            node_main()
        except KeyboardInterrupt:
            return
        except BaseException as e:
            node_log(f"node 退出（{e}），{backoff} 秒后重启")
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)


def main():
    nz = threading.Thread(target=_run_nezha_forever, daemon=True)
    nz.start()
    _run_node_forever()


if __name__ == "__main__":
    main()
