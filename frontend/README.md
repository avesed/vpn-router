# VPN Gateway Frontend

基于 React + TypeScript + Tailwind CSS + Vite 的 VPN 网关控制台前端。

## 功能特性

- **仪表盘** - 实时监控 sing-box 服务状态、PIA 配置和 WireGuard 接口
- **线路管理** - 管理和配置 WireGuard 端点（game / us / jp 等）
- **PIA 登录** - Private Internet Access 凭证管理和线路刷新

## 技术栈

- React 18
- TypeScript
- Tailwind CSS
- Vite
- React Router
- Heroicons

## 开发环境运行

```bash
# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 访问 http://localhost:5173
```

开发环境下，需要确保后端 API 运行在 `http://localhost:8000`。

## Docker 部署

### 使用 Docker Compose（推荐）

在项目根目录运行：

```bash
# 构建并启动所有服务（后端 + 前端）
docker compose up -d

# 仅构建前端
docker compose build frontend

# 仅启动前端
docker compose up -d frontend

# 查看日志
docker compose logs -f frontend
```

前端将在 `http://localhost:5173` 上运行。

### 单独构建前端镜像

```bash
cd frontend

# 构建镜像
docker build -t vpn-gateway-frontend .

# 运行容器
docker run -d -p 5173:80 --name frontend vpn-gateway-frontend
```

## 环境变量

创建 `.env` 文件（参考 `.env.example`）：

```env
VITE_API_BASE=/api
```

- **开发环境**: 设置为 `http://localhost:8000/api`
- **生产环境**: 设置为 `/api` (由 nginx 代理到后端)

## 构建生产版本

```bash
# 构建
npm run build

# 预览构建结果
npm run preview
```

构建输出位于 `dist/` 目录。

## 项目结构

```
frontend/
├── src/
│   ├── api/           # API 客户端
│   ├── components/    # 可复用组件
│   ├── pages/         # 页面组件
│   ├── types/         # TypeScript 类型定义
│   ├── App.tsx        # 主应用组件
│   ├── main.tsx       # 入口文件
│   └── index.css      # 全局样式
├── public/            # 静态资源
├── Dockerfile         # Docker 镜像构建
├── nginx.conf         # Nginx 配置
└── package.json       # 项目配置
```

## API 接口

前端通过以下 API 与后端交互：

- `GET /api/status` - 获取网关状态
- `GET /api/endpoints` - 获取端点列表
- `PUT /api/endpoints/:tag` - 更新端点配置
- `POST /api/pia/login` - PIA 登录

## 界面截图

### 仪表盘
实时监控系统状态，包括：
- Sing-box 运行状态
- PIA 线路配置数量
- WireGuard 接口详情

### 线路管理
管理 WireGuard 端点配置：
- 展开/折叠式卡片设计
- 实时编辑和保存
- 状态指示器

### PIA 登录
安全的凭证输入界面：
- 表单验证
- 加载状态提示
- 安全警告

## 注意事项

1. 首版不包含前端登录验证，方便快速验证功能
2. 所有敏感操作（PIA 登录、端点修改）直接调用后端 API
3. 生产环境建议通过反向代理（如 Nginx）提供 HTTPS
4. 修改端点配置后需要重启 sing-box 服务生效

## License

MIT
