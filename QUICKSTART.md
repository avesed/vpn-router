# 快速开始

## 使用 Docker Compose 启动

### 1. 启动所有服务

```bash
# 在项目根目录运行
docker compose up -d
```

这将启动：
- **后端服务** (vpn-gateway): `http://localhost:8000`
- **前端服务** (frontend): `http://localhost:5173`
- **WireGuard 端口**: `51820/udp`

### 2. 查看日志

```bash
# 查看所有服务日志
docker compose logs -f

# 只查看前端日志
docker compose logs -f frontend

# 只查看后端日志
docker compose logs -f vpn-gateway
```

### 3. 访问前端

打开浏览器访问：`http://localhost:5173`

### 4. 停止服务

```bash
# 停止所有服务
docker compose down

# 停止并删除数据卷
docker compose down -v
```

## 仅启动前端（用于开发）

如果后端已经在运行，只需启动前端：

```bash
docker compose up -d frontend
```

## 重新构建

如果修改了代码，需要重新构建：

```bash
# 重新构建所有服务
docker compose up -d --build

# 只重新构建前端
docker compose up -d --build frontend
```

## 环境变量配置

创建 `.env` 文件（如果需要配置 PIA）：

```env
PIA_USERNAME=your_username
PIA_PASSWORD=your_password
```

## 端口说明

- `5173`: 前端 Web 界面
- `8000`: 后端 API 服务
- `51820/udp`: WireGuard VPN 端口

## 故障排查

### 前端无法连接后端

1. 确认后端服务正在运行：`docker compose ps`
2. 检查网络连接：两个容器应该在同一个网络中
3. 查看 nginx 配置是否正确代理到后端

### 重新构建前端

```bash
docker compose build --no-cache frontend
docker compose up -d frontend
```
