# vpn-router 统一架构重构计划

> 版本: 1.0
> 日期: 2026-01-03
> 状态: 草案 (合并 ARCHITECTURE_REFACTOR + RUST_DATA_PLANE)

## 1. 目标统一

整合两个计划，消除冗余，形成最优实施路径：

| 目标 | 来源计划 | 优化方案 |
|------|----------|----------|
| 热重载 | 两者皆有 | Rust 数据面 ArcSwap 实现 |
| macvlan 兼容 | ARCHITECTURE | TPROXY 保留（已验证） |
| 替代 sing-box | DATA_PLANE | 直接实现，跳过配置生成器 |
| Xray-lite | ARCHITECTURE | **降级为可选**，先用 SOCKS5 桥接 |
| Slim Node | ARCHITECTURE | 独立开发，可并行 |
| 性能提升 | 两者皆有 | 规则匹配 < 10μs |

---

## 2. 统一架构设计

### 2.1 Full Node (替代当前 sing-box 架构)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Full Node                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  入口层                                                                      │
│  ┌──────────────────┐    ┌──────────────────┐                               │
│  │ Kernel WireGuard │    │ Xray Ingress     │                               │
│  │ (wg-ingress)     │    │ (VLESS+REALITY)  │                               │
│  └────────┬─────────┘    └────────┬─────────┘                               │
│           │                       │                                          │
│           │                       ▼                                          │
│           │              ┌──────────────────┐                               │
│           │              │ TUN (xray-tun0)  │                               │
│           │              └────────┬─────────┘                               │
│           │                       │                                          │
│           └───────────┬───────────┘                                          │
│                       ▼                                                      │
│           ┌─────────────────────────────────────────────────────────────┐   │
│           │                    iptables TPROXY                           │   │
│           │     DIVERT (established) + TPROXY (new) → 127.0.0.1:7893    │   │
│           └─────────────────────────┬───────────────────────────────────┘   │
│                                     │                                        │
│  ┌──────────────────────────────────▼────────────────────────────────────┐  │
│  │                        rust-router (数据面)                            │  │
│  │  ┌────────────────────────────────────────────────────────────────┐  │  │
│  │  │  TPROXY Listener (127.0.0.1:7893)                              │  │  │
│  │  │  - TCP Accept → SNI Sniff → Connection Manager                  │  │  │
│  │  │  - UDP recvmsg → Session Manager → Packet Router                │  │  │
│  │  └────────────────────────────────────────────────────────────────┘  │  │
│  │                              │                                        │  │
│  │                              ▼                                        │  │
│  │  ┌────────────────────────────────────────────────────────────────┐  │  │
│  │  │  规则引擎 (ArcSwap<RuleSet>) ← 无锁热重载                       │  │  │
│  │  │  - Domain Matcher (Aho-Corasick + SNI sniffing)                │  │  │
│  │  │  - GeoIP Matcher (MaxMindDB)                                   │  │  │
│  │  │  - CIDR Matcher (ip_network crate)                             │  │  │
│  │  │  - fwmark Chain Matcher (DSCP via iptables mark)               │  │  │
│  │  └────────────────────────────────────────────────────────────────┘  │  │
│  │                              │                                        │  │
│  │                              ▼                                        │  │
│  │  ┌────────────────────────────────────────────────────────────────┐  │  │
│  │  │  Outbound Manager (连接池 + 热重载)                             │  │  │
│  │  │  ┌─────────┬─────────┬──────────┬──────────┬──────────┐       │  │  │
│  │  │  │ Direct  │ SOCKS5  │ Kernel WG│  Xray    │  WARP    │       │  │  │
│  │  │  │ (bind)  │ (pool)  │ (mark)   │ (bridge) │ (bridge) │       │  │  │
│  │  │  └─────────┴─────────┴──────────┴──────────┴──────────┘       │  │  │
│  │  └────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                     │                                        │
│  出口层                              ▼                                        │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┬───────────────┐   │
│  │  Direct  │ Kernel WG│  Xray    │   WARP   │  OpenVPN │ Peer Tunnel   │   │
│  │ (bind IF)│ wg-xxx   │ (SOCKS)  │ (WG/MASQ)│  tun10+  │ wg-peer-xxx   │   │
│  └──────────┴──────────┴──────────┴──────────┴──────────┴───────────────┘   │
│                                                                              │
│  管理层                                                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Python API Server (api_server.py:8000)                              │   │
│  │  ←─── Unix Socket IPC (async) ───→ rust-router                       │   │
│  │  (规则变更 → IPC 热重载，无需重启)                                    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Slim Node (独立开发，可并行)

```
┌────────────────────────────────────────────────┐
│                   Slim Node                     │
├────────────────────────────────────────────────┤
│                                                │
│  wg-peer-A ─── nftables FORWARD ─── wg-peer-B │
│                                                │
│  ┌──────────────────────────────────────────┐ │
│  │  slim_api_server.py (~500 LOC)           │ │
│  │  - /api/peers                            │ │
│  │  - /api/forwarding/rules                 │ │
│  │  - /api/health                           │ │
│  └──────────────────────────────────────────┘ │
│                                                │
│  镜像大小: < 100MB (Alpine + Python minimal)  │
│                                                │
└────────────────────────────────────────────────┘
```

---

## 3. 关键优化决策

### 3.1 跳过 "Rust 控制面" (原 ARCHITECTURE Phase 1)

| 原计划 | 优化后 | 理由 |
|--------|--------|------|
| Rust 控制面生成 sing-box.json | 直接实现 Rust 数据面 | sing-box 最终会被替代，为它写配置生成器是浪费 |
| render_singbox.py 替代 | 删除 render_singbox.py | 不再需要生成 sing-box 配置 |
| IPC → sing-box SIGHUP | IPC → Rust ArcSwap | 更优雅的热重载机制 |

**节省时间**: 4 周

### 3.2 Xray-lite 精简为协议适配器

**定位**: 最小化 VLESS+XHTTP+REALITY 协议适配器

**唯一保留的协议栈**:
```
VLESS + XHTTP (splithttp) + REALITY
```

| 组件 | 状态 | 理由 |
|------|------|------|
| **proxy/vless/** | ✅ 保留 | 核心协议 |
| **transport/internet/reality/** | ✅ 保留 | 抗检测 TLS |
| **transport/internet/splithttp/** | ✅ 保留 | XHTTP 传输 |
| **proxy/freedom/** | ✅ 保留 | 出口直连 |
| **proxy/socks/** (inbound only) | ✅ 保留 | Rust 桥接入口 |
| **app/proxyman/** | ✅ 保留 | 连接管理 |
| proxy/vmess, trojan, shadowsocks | ❌ 删除 | 不使用 |
| transport/internet/websocket | ❌ 删除 | 只用 XHTTP |
| transport/internet/grpc | ❌ 删除 | 只用 XHTTP |
| transport/internet/kcp, quic | ❌ 删除 | 只用 XHTTP |
| transport/internet/tcp (raw) | ❌ 删除 | XHTTP 已包含 |
| XTLS-Vision | ❌ 删除 | 需要 raw TCP |
| app/stats, commander | ❌ 删除 | Rust 统计 |
| app/observatory | ❌ 删除 | Python 健康检查 |
| app/router | ❌ 删除 | Rust 规则引擎 |
| app/dns | ❌ 删除 | Rust DNS |

**目标**:
- 二进制大小: ~25MB → **~4MB**
- 协议栈: 仅 VLESS + XHTTP + REALITY
- 职责: 纯协议转换，零路由逻辑

**配置示例** (入口):
```json
{
  "inbounds": [{
    "protocol": "vless",
    "settings": { "clients": [...] },
    "streamSettings": {
      "network": "xhttp",
      "security": "reality",
      "realitySettings": { "dest": "www.microsoft.com:443", ... }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "tag": "direct"
  }]
}
```

**配置示例** (出口):
```json
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 37101
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": { "vnext": [...] },
    "streamSettings": {
      "network": "xhttp",
      "security": "reality",
      "realitySettings": { ... }
    }
  }]
}
```

**架构角色**:
```
入口侧:                              出口侧:
┌──────────────────┐                ┌──────────────────┐
│ Xray-lite        │                │ Xray-lite        │
│                  │                │                  │
│ VLESS+XHTTP      │                │ SOCKS5 Inbound   │
│ +REALITY Inbound │                │ (127.0.0.1:37101)│
│        ↓         │                │        ↓         │
│ Freedom Outbound │                │ VLESS+XHTTP      │
│ (to local)       │                │ +REALITY Outbound│
└────────┬─────────┘                └────────┬─────────┘
         │                                   │
         ▼                                   ▼
   Local Network                       Remote Server
   (→ TPROXY → Rust)                  (via XHTTP/H2)
```

### 3.3 Slim Node 独立开发

- **不依赖** Rust 数据面或 Xray-lite
- 可以与其他开发**并行进行**
- 用于纯中继场景，无需复杂路由逻辑

### 3.4 规则引擎统一

两个计划的规则引擎合并为一个 Rust crate：

```rust
// rust-router-core (共享 crate)
pub mod rules {
    pub mod domain;     // Aho-Corasick
    pub mod geoip;      // MaxMindDB
    pub mod cidr;       // ip_network
    pub mod fwmark;     // DSCP chain routing
}

pub mod config {
    pub mod routing;    // 路由表常量
    pub mod types;      // 配置类型
}
```

---

## 4. 统一实施计划

### 4.1 总体时间线

```
Week  0   1   2   3   4   5   6   7   8   9  10
      │   │   │   │   │   │   │   │   │   │   │

      ┌───────────────────────────────────────┐
      │          主线开发 (8 周)               │
      ├───────────────────────────────────────┤
P0    │██│                                    │ 基础设施验证
P1    │  │████████│                           │ Rust 数据面基础
P2    │  │        │████████│                  │ 规则引擎 + 热重载
P3    │  │        │        │██████████████│   │ 桥接出口 + 集成
      └───────────────────────────────────────┘

      ┌───────────────────────────────────────┐
      │          并行开发                       │
      ├───────────────────────────────────────┤
XL    │  │████████████████│                   │ Xray-lite 精简 (4周)
SN    │  │        │████████│                  │ Slim Node (2周)
      └───────────────────────────────────────┘
      │   │   │   │   │   │   │   │   │   │   │
      0   1   2   3   4   5   6   7   8   9  10
```

**总工期**: 8 周 (主线) + 并行组件
**依赖关系**: Phase XL 需在 Phase 3 前完成

---

### 4.2 Phase 0: 基础设施验证 (1 周)

**目标**: 验证 TPROXY + iptables 技术可行性

| 天 | 任务 | 交付物 |
|----|------|--------|
| 1 | TPROXY socket PoC: `IP_TRANSPARENT` + `SO_ORIGINAL_DST` | tproxy_poc.rs |
| 2 | UDP recvmsg cmsg: `IP_RECVORIGDSTADDR` | udp_tproxy_poc.rs |
| 3 | iptables 集成: 与 DIVERT/ECMP/DSCP 规则共存测试 | iptables_compat.sh |
| 4 | 内核配置检查: route_localnet, rp_filter, ip_nonlocal_bind | kernel_check.sh |
| 5 | 可行性报告 + Phase 1 详细设计 | PHASE0_REPORT.md |

**门控条件**:
- [ ] TPROXY TCP/UDP 可正常接收流量
- [ ] 不与现有 iptables 规则冲突
- [ ] 内核参数检查脚本通过

---

### 4.3 Phase 1: Rust 数据面基础 (2 周)

**目标**: 最小可行产品 - TCP 流量转发

| 周 | 天 | 任务 | 交付物 |
|----|----|----|--------|
| 1 | 1-2 | Cargo 项目结构 + 依赖定义 | rust-router/Cargo.toml |
| 1 | 3-4 | TPROXY TCP listener + accept loop | tproxy/listener.rs |
| 1 | 5 | TCP 双向转发 (tokio::io::copy_bidirectional) | connection/tcp.rs |
| 2 | 1-2 | SNI Sniffing (TLS ClientHello) | sniff/tls.rs |
| 2 | 3-4 | Direct outbound + bind_interface | outbound/direct.rs |
| 2 | 5 | Unix Socket IPC 框架 | ipc/server.rs |

**关键代码**:
```rust
// 最小 TPROXY 监听
let socket = create_tproxy_tcp_socket("127.0.0.1:7893")?;
loop {
    let (stream, src) = socket.accept().await?;
    let dst = get_original_dst_tcp(stream.as_raw_fd())?;
    tokio::spawn(handle_connection(stream, src, dst));
}
```

**交付物**:
- [x] rust-router 可执行文件
- [x] 可处理 TCP 流量 (Direct 出口)
- [x] TLS SNI 域名提取
- [x] Python async IPC 客户端骨架

---

### 4.4 Phase 2: 规则引擎 + 热重载 (2 周)

**目标**: 完整规则匹配 + 无锁热重载

| 周 | 天 | 任务 | 交付物 |
|----|----|----|--------|
| 3 | 1-2 | Aho-Corasick 域名匹配 | rules/domain.rs |
| 3 | 3-4 | MaxMindDB GeoIP 加载 | rules/geoip.rs |
| 3 | 5 | fwmark chain 路由 (DSCP) | rules/fwmark.rs |
| 4 | 1-2 | ArcSwap 热重载机制 | connection/manager.rs |
| 4 | 3 | 差异测试框架 (对比 render_singbox.py) | tests/diff_test.py |
| 4 | 4-5 | UDP 会话管理 + QUIC sniffing | connection/udp.rs |

**关键代码**:
```rust
// ArcSwap 无锁热重载
pub struct ConnectionManager {
    ruleset: ArcSwap<RuleSet>,
}

impl ConnectionManager {
    pub fn reload(&self, new: RuleSet) {
        self.ruleset.store(Arc::new(new)); // 原子替换，无锁
    }

    pub fn match_rule(&self, ...) -> &str {
        self.ruleset.load().match_rule(...) // 无锁读取
    }
}
```

**交付物**:
- [x] 完整规则引擎 (domain/geoip/cidr/fwmark)
- [x] 热重载 < 10ms
- [x] 差异测试通过率 100%
- [x] UDP 会话管理 (5min 超时)

---

### 4.5 Phase 3: 桥接出口 + 集成 (3 周)

**目标**: 支持所有出口类型，替代 sing-box

| 周 | 天 | 任务 | 交付物 |
|----|----|----|--------|
| 5 | 1-3 | SOCKS5 client + 连接池 (deadpool) | outbound/socks5.rs |
| 5 | 4-5 | Xray-lite 桥接 (VLESS+XHTTP+REALITY) | outbound/bridge.rs |
| 6 | 1-2 | Kernel WireGuard 出口 (routing_mark) | outbound/kernel_wg.rs |
| 6 | 3-4 | WARP 桥接 (WireGuard / MASQUE) | outbound/warp.rs |
| 6 | 5 | OpenVPN 桥接 (bind_interface: tunX) | outbound/openvpn.rs |
| 7 | 1-2 | Python API 集成 (AsyncRustRouterClient) | scripts/rust_router_client.py |
| 7 | 3-4 | entrypoint.sh 集成 (替代 sing-box) | scripts/entrypoint.sh |
| 7 | 5 | Phase 11 DSCP chain 验证 | tests/dscp_chain_test.py |

**出口类型完整列表**:
| 出口类型 | Rust 实现 | 桥接方式 |
|----------|-----------|----------|
| Direct (bind_interface) | ✅ 原生 | - |
| Direct (bind_address) | ✅ 原生 | - |
| Kernel WireGuard | ✅ 原生 | routing_mark → ip rule |
| Xray-lite | - | SOCKS5 桥接 |
| WARP WireGuard | ✅ 原生 | routing_mark → ip rule |
| WARP MASQUE | - | SOCKS5 桥接 |
| OpenVPN | ✅ 原生 | bind_interface: tunX |

**交付物**:
- [x] 所有出口类型工作正常
- [x] SOCKS5 连接池 (16 连接预热)
- [x] Python API 无缝集成
- [x] Phase 11 DSCP 链路验证通过

---

### 4.6 Phase XL: Xray-lite 精简 (4 周，并行)

**目标**: 最小化 VLESS+XHTTP+REALITY 协议适配器

| 周 | 任务 | 交付物 |
|----|------|--------|
| 1 | Fork Xray-core，删除协议模块 | xray-lite/ 仓库 |
| 2 | 删除 app/ 模块 (router/dns/stats) | 精简后代码 |
| 3 | 编译验证 + 依赖裁剪 | go.mod 最小化 |
| 4 | 功能测试 + 二进制优化 (UPX) | xray-lite 二进制 |

**删除模块** (详细):
```go
// 删除的 proxy 协议
- proxy/vmess/
- proxy/trojan/
- proxy/shadowsocks/
- proxy/http/
- proxy/dokodemo/
- proxy/wireguard/
- proxy/dns/

// 删除的 transport
- transport/internet/websocket/
- transport/internet/grpc/
- transport/internet/kcp/
- transport/internet/quic/
- transport/internet/tcp/         // XHTTP 内置
- transport/internet/httpupgrade/
- transport/internet/domainsocket/

// 删除的 app
- app/router/        // Rust 规则引擎
- app/dns/           // Rust DNS
- app/stats/         // Rust 统计
- app/commander/     // 不需要
- app/observatory/   // Python 健康检查
- app/policy/        // 不需要
- app/log/           // 简化日志
```

**保留模块**:
```go
// 保留的 proxy
+ proxy/vless/       // 唯一协议
+ proxy/freedom/     // 直连出口
+ proxy/socks/       // Rust 桥接入口 (仅 inbound)

// 保留的 transport
+ transport/internet/reality/    // 唯一 TLS
+ transport/internet/splithttp/  // XHTTP

// 保留的 app
+ app/proxyman/      // 连接管理 (精简)

// 保留的核心
+ core/              // 精简后的核心框架
+ common/            // 工具函数
+ features/          // 必要特性接口
```

**交付物**:
- [x] xray-lite 二进制 (< 5MB, 使用 UPX 压缩后 < 3MB)
- [x] 仅支持: VLESS + XHTTP + REALITY
- [x] 配置模板 (入口/出口)
- [x] Dockerfile.xray-lite

---

### 4.7 Phase SN: Slim Node (2 周，并行)

**目标**: 无路由核心的轻量中继节点

| 周 | 任务 | 交付物 |
|----|------|--------|
| 1 | Dockerfile.slim + Alpine 基础镜像 | Dockerfile.slim |
| 1 | slim_entrypoint.sh + nftables 转发规则 | slim_entrypoint.sh |
| 2 | slim_api_server.py (~500 LOC) | slim_api_server.py |
| 2 | 集成测试 + 吞吐量测试 | tests/slim_node_test.py |

**API 端点** (最小集):
```
GET  /api/health
GET  /api/peers
POST /api/peers
DELETE /api/peers/{tag}
POST /api/peers/{tag}/connect
POST /api/peers/{tag}/disconnect
GET  /api/forwarding/rules
POST /api/forwarding/rules
```

**交付物**:
- [x] Slim Node 镜像 (< 100MB)
- [x] 转发吞吐量 > 1Gbps
- [x] 与 Full Node 兼容的 Peer API

---

### 4.8 Phase 4: 性能优化 (2 周，可选)

| 周 | 任务 | 优先级 |
|----|------|--------|
| 8 | 性能测试 + 稳定性测试 + Benchmark 对比 | P0 |
| 9 | Xray-lite 精简 (如果 SOCKS5 桥接成为瓶颈) | P2 |

---

## 5. 删除/简化的组件

| 组件 | 原计划 | 优化后 | 理由 |
|------|--------|--------|------|
| render_singbox.py 替代 | ARCHITECTURE Phase 1 | 删除 | 直接用 Rust 数据面 |
| sing-box 配置生成 | ARCHITECTURE Phase 1 | 删除 | sing-box 被替代 |
| Xray-lite TUN 支持 | ARCHITECTURE Phase 2 | 降级为可选 | SOCKS5 桥接足够 |
| 双实例配置切换 | ARCHITECTURE | 删除 | 无需 sing-box 配置 |

---

## 6. 风险矩阵 (更新)

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| TPROXY 与现有规则冲突 | 中 | 高 | Phase 0 验证 (已解决) |
| Rust 数据面性能不达标 | 低 | 高 | A/B 测试 + 回退到 sing-box |
| SOCKS5 桥接延迟高 | 中 | 中 | 连接池 + 如需要可升级 Xray-lite |
| Phase 11 DSCP 集成失败 | 中 | 高 | fwmark 方案 + 详细测试 |
| Slim Node 与 Full Node API 不兼容 | 低 | 中 | 统一 API 子集设计 |

---

## 7. 成功标准

| 阶段 | 标准 |
|------|------|
| Phase 0 | TPROXY + iptables 规则共存验证通过 |
| Phase 1 | TCP 流量正常转发，延迟 < 1ms |
| Phase 2 | 规则匹配延迟 < 10μs，热重载 < 10ms |
| Phase 3 | 所有出口类型工作正常，Phase 11 集成通过 |
| Phase 3' | Slim Node 镜像 < 100MB，转发 > 1Gbps |
| Phase 4 | 吞吐量 ≥ sing-box，内存 < 100MB |

---

## 8. 文件变更清单

### 新增

```
rust-router/                       # Rust 数据面项目
scripts/rust_router_client.py      # Python async IPC 客户端
scripts/slim_api_server.py         # Slim Node API (Phase 3')
Dockerfile.slim                    # Slim Node 镜像
```

### 修改

```
scripts/entrypoint.sh              # 启动 rust-router 替代 sing-box
scripts/api_server.py              # 使用 AsyncRustRouterClient
Dockerfile                         # 构建 rust-router
```

### 删除 (Phase 3 完成后)

```
scripts/render_singbox.py          # 不再需要
config/sing-box.json               # 不再需要模板
```

---

## 9. 与原计划的对应关系

| 原 ARCHITECTURE_REFACTOR | 统一计划 | 状态 |
|--------------------------|----------|------|
| Phase 0 (前置准备) | Phase 0 | 合并 |
| Phase 1 (Rust 控制面) | **删除** | 跳过 (不需要 sing-box 配置生成) |
| Phase 2 (Xray-lite) | **Phase XL** | **保留但精简** (仅 VLESS+XHTTP+REALITY) |
| Phase 3 (Slim Node) | Phase SN | 并行 |
| Phase 4 (Rust 数据面) | Phase 1-3 | **核心** |

| 原 RUST_DATA_PLANE | 统一计划 | 状态 |
|--------------------|----------|------|
| Phase 0 (基础验证) | Phase 0 | 合并 |
| Phase 1 (基础框架) | Phase 1 | 保留 |
| Phase 2 (规则引擎) | Phase 2 | 保留 |
| Phase 3 (桥接出口) | Phase 3 | 扩展 (使用 Xray-lite) |
| Phase 4 (集成测试) | Phase 3/4 | 合并 |

### Xray-lite 精简范围

| 原 Xray-core 模块 | Xray-lite 状态 | 理由 |
|-------------------|----------------|------|
| VLESS | ✅ 保留 | 唯一协议 |
| XHTTP (splithttp) | ✅ 保留 | 唯一传输 |
| REALITY | ✅ 保留 | 唯一 TLS |
| Freedom | ✅ 保留 | 直连出口 |
| SOCKS (inbound) | ✅ 保留 | Rust 桥接 |
| VMess/Trojan/SS | ❌ 删除 | 不使用 |
| WS/gRPC/KCP/QUIC/TCP | ❌ 删除 | 只用 XHTTP |
| XTLS-Vision | ❌ 删除 | 需要 raw TCP |
| Router/DNS/Stats | ❌ 删除 | Rust 实现 |

**二进制大小**: ~25MB → **~4MB**

---

## 10. 审批签字

| 角色 | 姓名 | 日期 | 签字 |
|------|------|------|------|
| 技术负责人 | | | |
| 架构师 | | | |
| 网络工程师 | | | |
