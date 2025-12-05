# 自定义 WireGuard 出口功能实现计划

## 用户需求确认
- **UI 布局**: B - 创建独立的"出口管理"页面
- **协议支持**: 目前只支持 WireGuard
- **导入方式**: 支持文件上传 + 粘贴配置

## 目标
允许用户导入自己的 WireGuard 配置作为出口选项，不仅限于 PIA。

## 当前架构分析

### 出口管理流程
1. **PIA profiles** 存储在 `config/pia/profiles.yml`
2. **pia_provision.py** 获取 PIA 服务器凭证，生成 `pia-profiles.json`
3. **render_singbox.py** 读取配置，创建 sing-box endpoints
4. 前端 ProfileManager 管理 PIA 线路

### 关键数据结构 (sing-box endpoint)
```json
{
  "type": "wireguard",
  "tag": "my-server",
  "address": ["10.0.0.2/32"],
  "private_key": "...",
  "mtu": 1300,
  "peers": [{
    "address": "server.example.com",
    "port": 51820,
    "public_key": "...",
    "allowed_ips": ["0.0.0.0/0", "::/0"],
    "persistent_keepalive_interval": 25
  }]
}
```

## 实现方案

### 1. 数据存储
创建 `/etc/sing-box/custom-egress.json`：
```json
{
  "egress": [
    {
      "tag": "my-hk-server",
      "description": "香港自建服务器",
      "type": "wireguard",
      "server": "hk.example.com",
      "port": 51820,
      "private_key": "client_private_key",
      "public_key": "server_public_key",
      "address": "10.0.0.2/32",
      "mtu": 1420,
      "dns": "1.1.1.1",
      "pre_shared_key": "",
      "reserved": []
    }
  ]
}
```

### 2. API 端点

#### GET /api/egress
列出所有出口（PIA + 自定义）
```json
{
  "egress": [
    {"tag": "pia-hk", "type": "pia", "description": "PIA 香港", "is_connected": true},
    {"tag": "my-server", "type": "custom", "description": "我的服务器", "is_connected": true}
  ]
}
```

#### GET /api/egress/custom
列出所有自定义出口

#### POST /api/egress/custom
创建自定义出口
- 支持直接输入参数
- 支持解析 WireGuard .conf 格式

#### PUT /api/egress/custom/{tag}
更新自定义出口

#### DELETE /api/egress/custom/{tag}
删除自定义出口

### 3. WireGuard 配置解析
支持解析标准 WireGuard .conf 格式：
```ini
[Interface]
PrivateKey = xxx
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = xxx
Endpoint = server:51820
AllowedIPs = 0.0.0.0/0
```

### 4. 修改 render_singbox.py
- 读取 `custom-egress.json`
- 为每个自定义出口创建 endpoint
- 与 PIA endpoints 合并

### 5. 前端 UI

#### 方案 A：扩展现有 ProfileManager
在现有页面增加"自定义出口"区域，与 PIA 线路并列显示

#### 方案 B：独立出口管理页面（推荐）
创建新页面 `/egress`，统一展示所有出口类型：
- PIA 线路（可快速添加，选择地区）
- 自定义 WireGuard（手动配置或导入）

#### 添加自定义出口表单
- 名称/标识
- 描述
- 配置方式：
  - 粘贴 .conf 文件内容（自动解析）
  - 手动输入各字段

### 6. 文件变更清单

**新增文件：**
- `config/custom-egress.json` - 自定义出口配置存储

**修改文件：**
- `scripts/api_server.py` - 添加 egress API 端点
- `scripts/render_singbox.py` - 加载自定义出口
- `frontend/src/pages/ProfileManager.tsx` - 添加自定义出口 UI
- `frontend/src/api/client.ts` - 添加 API 函数
- `frontend/src/types/index.ts` - 添加类型定义

## 实现步骤

1. **后端 API** (~30%)
   - 添加 custom-egress.json 读写函数
   - 实现 CRUD API 端点
   - 实现 WireGuard .conf 解析器

2. **配置渲染** (~20%)
   - 修改 render_singbox.py 支持自定义出口
   - 测试 sing-box 配置生成

3. **前端 UI** (~40%)
   - 添加类型定义
   - 添加 API 函数
   - 实现添加/编辑/删除 UI
   - 实现 .conf 导入功能

4. **测试验证** (~10%)
   - 测试创建自定义出口
   - 测试路由规则使用自定义出口
   - 测试重启后配置持久化

## 问题确认

需要确认以下设计决策：

1. **UI 布局**：扩展现有 ProfileManager 还是创建独立页面？
2. **出口类型**：是否需要支持其他协议（如 SOCKS5、Shadowsocks）？还是只支持 WireGuard？
3. **导入方式**：是否需要支持从文件选择导入，还是只支持粘贴配置内容？
