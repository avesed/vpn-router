# 前端实现说明

本前端为 VPN 网关提供可视化控制台，基于 React + TypeScript + Tailwind CSS 实现。

## 已实现功能（v1.0）

### 1. 仪表盘
- ✅ 实时显示 sing-box 运行状态
- ✅ PIA 配置数量统计
- ✅ 配置更新时间
- ✅ 最后更新时间
- ✅ 网关类型和连接状态
- ✅ WireGuard 接口详细信息
- ✅ 自动刷新（15秒间隔）

### 2. 线路管理
- ✅ 列出所有 WireGuard 端点（game-exit / us-stream / jp-stream 等）
- ✅ 展开/折叠式卡片设计
- ✅ 编辑端点配置（地址、私钥、Peer 信息）
- ✅ 配置状态指示器
- ✅ 保存成功/失败反馈
- ✅ 刷新功能

### 3. PIA 登录
- ✅ 安全的凭证输入界面
- ✅ 表单验证
- ✅ 通过 API 调用后端获取 token
- ✅ 加载状态和错误提示
- ✅ 安全警告说明
- ✅ 线路说明

## UI/UX 特性

- 深色主题设计
- 玻璃拟态效果
- 流畅的动画和过渡
- 响应式布局
- 自定义滚动条
- 状态指示器和加载动画
- 优雅的错误处理

## 技术栈

- React 18
- TypeScript
- Tailwind CSS
- Vite
- React Router
- Heroicons
- Docker + Nginx

## 部署方式

使用 Docker Compose 部署：
```bash
docker compose up -d
```

访问 `http://localhost:5173` 即可使用。

## 安全说明

- 首版未实现前端登录验证，方便快速验证功能
- PIA 凭证仅在容器内使用，不写入磁盘
- 所有敏感操作通过后端 API 处理

## 未来计划

以下功能计划在后续版本中实现：

- 分流策略可视化编辑器
- 客户端管理（WireGuard peers）
- 诊断工具（Ping/Traceroute/DNS测试）
- 配置备份与恢复
- 用户认证与权限管理
- 审计日志
