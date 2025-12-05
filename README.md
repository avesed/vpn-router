# Smart WireGuard VPN Gateway

该项目提供一个集中式“智能网关”Docker 容器：终端通过 WireGuard 接入容器，容器内部由 sing-box 负责多出口调度，并基于 geosite / geoip / 域名分类实现游戏、流媒体、国内/国际流量的精细分流以及 DNS/IPv6 泄露防护。

## 关键特性
- **WireGuard inbound**：容器直接提供 WireGuard Server，所有终端先接入容器的 `wg-ingress` 接口。
- **多出口调度**：内置直连、本地/国内出口、游戏专线、US/JP 流媒体线路等多个 outbound，可按需拓展。
- **按业务智能分流**：结合 geosite/geoip、SNI/域名规则，实现“流媒体(US/JP) / 游戏 / 国内网站 / 加拿大网站 / 其它”等多级策略。
- **DNS/IPv6 防泄漏**：流媒体相关查询强制走对应出口的加密 DNS，默认在容器侧关闭 IPv6 并强制 IPv4-only。
- **可模板化扩展**：所有配置集中在 `config/sing-box.json`，可为不同业务/地区新增 WireGuard/VPN 出口与规则集。

## 目录结构
```
.
├── Dockerfile            # 构建 sing-box 网关镜像
├── docker-compose.yml    # 快速启动容器
├── config/
│   └── sing-box.json     # 默认示例配置 (记得用真实参数替换)
└── scripts/
    ├── entrypoint.sh     # 容器启动脚本，负责 sysctl + geodata
    └── fetch-geodata.sh  # 下载 geosite / geoip 库并导出所需 rule-set
```

## 构建与运行
1. 生成 WireGuard 密钥：
   ```bash
   docker run --rm -it linuxserver/wireguard bash -c 'wg genkey | tee server.key | wg pubkey > server.pub'
   ```
   为每个客户端生成独立的 key，并在 `config/sing-box.json` 的 `users` 数组中登记 `public_key` 与 `allowed_ips`。
2. 用真实的出口线路（直连/US/JP/游戏/CN）替换 `outbounds` 中的 `server`、`private_key`、`peer_public_key` 等字段。如果某条出口暂未准备好，可先保留示例值但不要将规则指向它。
3. 构建镜像并启动：
   ```bash
   docker compose build
   docker compose up -d
   ```
4. 客户端 WireGuard 配置 `Endpoint = <宿主机IP>:51820`，`AllowedIPs = 0.0.0.0/0`，IP 段需与示例的 `10.23.0.0/24` 匹配。

> 默认 `docker-compose` 会把本地 `config/` 挂载到容器，方便随时调整规则。修改后执行 `docker compose restart` 即可生效。

## sing-box 配置要点
- **`inbounds`**：`wg-ingress` 是全部终端的入口，`private_key` 使用服务器私钥，`users` 数组列出各客户端 `public_key` + `allowed_ips`。可以增加更多 `users`。
- **`endpoints` / `outbounds`**：
  - `game-exit`、`us-stream`、`jp-stream` 现在通过 `endpoints` 定义 WireGuard 端点，`outbounds` 中的 selector 直接引用这些标签即可。保证 `address` 匹配远端下发的 `peer_ip`，`peers.allowed_ips` 覆盖 `0.0.0.0/0`/`::/0`。
  - `direct`：直连本地 ISP。
  - `cn-exit`：当前指向直连，可把更多国内线路加入 selector 的 `outbounds`。
  - `default-exit`：`selector` 类型，可切换默认出口（直连或任意 WireGuard 端点）。修改 `default` 字段即可。
  - 示例中的 `private_key`/`public_key` 仅为随机生成的占位值，用于让容器在没有真实线路时仍能运行，正式部署前请替换为实际 WireGuard 参数。
- **`dns`**：
  - `strategy: ipv4_only` + 启用容器 sysctl，避免 IPv6 泄漏。
  - 针对 CN / US / JP 流媒体分别使用对应出口的 DoH/DoT 服务器，规则触发后 DNS 请求也会走指定出口。
- **`route`**：
  - `rule_set` 中包含 `fetch-geodata.sh` 自动导出的本地 JSON 规则文件（`rulesets/geosite-cn.json`、`rulesets/geoip-*.json`）以及若干 `inline` 规则集（US/JP 流媒体、游戏）。
  - `rules` 顺序即优先级：`geoip-ca` -> `geosite-cn` -> `streaming-us` -> `streaming-jp` -> `gaming` -> `default-exit`。
  - 如需新增区域/业务，可在 `rule_set` 中再增加一个 `inline` 规则，然后在 `rules` 里指向新的 outbound。

## PIA 多出口集成
- `pia-desktop/` 中保留了官方客户端的核心代码与 CA 证书，容器启动时会调用 `scripts/pia/pia_provision.py`：
  1. 使用 `PIA_USERNAME`/`PIA_PASSWORD` 登录 PIA API（与 desktop 版一致，需要付费账号）。
  2. 拉取 `https://serverlist.piaservers.net/vpninfo/servers/v6`，解析 WireGuard 服务节点。
  3. 为 `config/pia/profiles.yml` 中的每个地区生成独立的 WireGuard key，并向对应 server `addKey`，形成 JSON 输出。
- `scripts/render_singbox.py` 会把上述结果写回 `sing-box.generated.json`，替换 `us-stream` / `jp-stream` / `game-exit` outbounds，使得多条 PIA 通道同时在线。
- `config/pia/profiles.yml` 可按需拓展更多出口，只需指定 `region_id`。运行 `docker compose restart` 即可重新登录并生成新线路。
- 必填环境变量（`docker-compose.yml`）：`PIA_USERNAME`、`PIA_PASSWORD`。未设置时，系统会回退到静态 WireGuard 出口。

## geosite / geoip 数据
容器入口脚本会自动调用 `scripts/fetch-geodata.sh` 下载基础数据并导出规则集：
- `GEOIP_URL` 默认指向 `github.com/SagerNet/sing-geoip` 最新 release。
- `GEOSITE_URL` 默认指向 `github.com/SagerNet/sing-geosite`。
  下载完成后会根据 `GEOSITE_CATEGORIES`（默认 `cn`）与 `GEOIP_COUNTRIES`（默认 `cn,ca`）自动调用 `sing-box geosite/geoip export` 生成 `/etc/sing-box/rulesets/*.json`。
如需自建镜像源或新增规则集，可在 `docker-compose.yml` 中通过 `environment` 覆盖上述 URL/列表，或者执行：
```bash
docker compose exec vpn-gateway env FORCE_GEODATA_REFRESH=1 fetch-geodata.sh /etc/sing-box
```

## 防止泄露的附加措施
- 默认 `DISABLE_IPV6=1`，容器启动时会写入 sysctl。若仍需 IPv6，可将该变量设为 `0` 并在 `dns.strategy` 改为 `prefer_ipv6` 或 `ipv6_only`。
- 客户端侧也建议禁用系统 IPv6，或确保 IPv6 也通过 WireGuard 进入容器。
- 对同一流媒体平台使用固定出口：`rules` 中的流媒体域名不会命中其他出口，保证行为“一致、干净”。
- `dns.rules` 会让流媒体域名在其对应出口进行解析，避免 DNS 泄露。
- PIA 出口通过 `addKey` 直接创建 WireGuard 接口，生成的配置只在容器内部使用，不会落盘账号密码；同时生成多个 key，实现多条流量并发。

## 管理 API
- 容器内默认会拉起 FastAPI 服务（端口 `8000`，可通过 `API_PORT` 环境变量覆盖），`docker-compose.yml` 已将其映射到宿主机，方便前端直接调用。
- 主要接口：
  - `GET /api/status`：sing-box 运行状态、WireGuard 接口信息、PIA profiles 配置。
  - `GET /api/endpoints` / `PUT /api/endpoints/{tag}`：读取或更新 `config/sing-box.json` 中的 WireGuard 端点。
  - `GET /api/pia/profiles`、`POST /api/pia/login`：查看 PIA 配置并触发 `pia_provision.py` + `render_singbox.py` 重新生成线路。
  - `POST /api/actions/geodata`：手动刷新 geosite/geoip 数据。
  - `GET /api/wireguard/peers`：读取接入端的 WireGuard server 配置。
- API 已启用 CORS，后续的 React + Tailwind 前端可直接通过浏览器访问这些接口实现仪表盘、线路管理、PIA 登录等功能。

## 前端控制台（React + Tailwind + Vite）
- 代码位于 `frontend/`，使用 **React + TypeScript + React Router + Tailwind CSS** 实现暗色系 UI，首版包含“仪表盘”、“线路管理”、“PIA 登录”三大页面，对应上述 API。
- API 地址通过 `VITE_API_BASE` 环境变量配置（默认为 `http://localhost:8000/api`），确保 Docker 启动时 `ENABLE_API=1` 并映射 8000 端口。
- 开发模式：
  ```bash
  cd frontend
  npm install         # 首次运行需要安装依赖
  npm run dev         # http://localhost:5173
  ```
- 打包上线时执行 `npm run build`，生成的静态文件位于 `frontend/dist/`，可由任意静态服务器（Nginx、Caddy 等）托管。
- 前端仅负责调用 API，不做登录鉴权，方便本地验证；待后端开放认证能力后，可在此基础上扩展。

## 调试与日常运维
- 查看日志：`docker compose logs -f vpn-gateway`
- 检查配置语法：`docker compose exec vpn-gateway sing-box check -c /etc/sing-box/sing-box.json`
- 更新 geosite/geoip：`docker compose exec vpn-gateway env FORCE_GEODATA_REFRESH=1 fetch-geodata.sh /etc/sing-box`
- 动态切换默认出口：修改 `config/sing-box.json` 中 `default-exit` 的 `default` 字段，例如改为 `us-stream`，然后重启容器。

## 下一步可扩展
- 使用多副本 compose stack (Swarm/K8s) 保证高可用。
- 将客户端密钥、线路信息封装进 `configmap/secret`，并配套 UI 管理面板。
- 若需按 IP 段/用户分流，可在 `rules` 中结合 `source_geoip`、`source_ip_cidr` 或 `inbound` 标签实现。
