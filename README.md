# quect-node

quect.host 免费节点：xray（VLESS/VMess/Trojan + WS，单端口分流）+ 订阅服务 + 哪吒探针，三合一。

## 部署（quect.host 面板）

1. 从 GitHub 仓库创建项目，选 Dockerfile 构建。
2. 环境变量（Runtime variables）：
   - `PORT`：公开 HTTP 端口，默认 3000（须和面板里填的 HTTP port 一致）
   - `PUBLIC_URL`：公网域名，如 `p-quect-xxxx.quect.cloud`（发布后在面板设一次，再重启应用）
   - `NODE_UUID`、`NODE_TROJAN_PW`、`NODE_S1`、`NODE_S2`、`NODE_S3`：节点凭据（固定值）
   - `TG_BOT_TOKEN`、`TG_CHAT_ID`：TG 通知
   - `NZ_CLIENT_SECRET`：哪吒密钥
3. 发布后公网地址形如 `https://<PUBLIC_URL>`，订阅 `https://<PUBLIC_URL>/sub`。

## 原理

- 公开端口是 xray 的纯 TCP 分流器，按 WS 路径分到 VLESS+WS（8004）、VMess（8002）、Trojan（8003），其余流量 fallback 到 3100 订阅服务。
- 主入站必须是 TCP（WS 主入站会先按路径校验回 404，fallback 没机会分流）。
