# 更新日志 (Changelog)

## v0.2.8

### 新功能 (New Features)

#### WireGuard 客户端出站 (WireGuard Client Outbound)

新增套接字级别的 WireGuard 出站支持，可将选定流量通过 WireGuard 对等节点路由，包括 Cloudflare WARP 风格的配置。

```yaml
client_chain:
  protocol:
    type: wireguard
    private-key: "YOUR_BASE64_PRIVATE_KEY"
    server: 162.159.193.5
    port: 4500
    ip: 172.16.0.2
    ipv6: 2606:4700:cf1:1000::1
    public-key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    allowed-ips: ["0.0.0.0/0", "::/0"]
    udp: true
    mtu: 1408
    ip-version: ipv6-prefer
    remote-dns-resolve: true
    dns: ["2606:4700:4700::1111"]
```

支持的 WireGuard 选项包括 `private-key`、`public-key`、`pre-shared-key`、`server`、`port`、`ip`、`ipv6`、`allowed-ips`、`udp`、`mtu`、`ip-version`、`remote-dns-resolve`、`dns` 和 `reserved`。

### 改进 (Improvements)

- 在 WireGuard 运行时中添加了有界队列和数据包缓冲区复用，避免高负载下内存无限增长。
- 为 WireGuard 出站主机名解析添加了远程 DNS 缓存。
- 在运行时选择可用目标地址时强制执行 WireGuard `allowed-ips` 规则。
- 新增索引化主机名规则匹配，加速大型主机名规则集的路由决策。
- 为 WARP 风格对等节点使用的非零 WireGuard `reserved` 字节添加了本地 BoringTun 补丁。

## v0.2.7

### 改进 (Improvements)

#### H2MUX 稳定性 (H2MUX Stability)
- 增加了连接级别的活动追踪，将 HTTP/2 控制帧 (PING, SETTINGS) 视为活动，确保保活机制 (keepalives) 正确重置空闲检测。
- 移除了应用级别的空闲超时，转而使用基于 PING 的死连接检测，与 sing-mux 行为保持一致以获得更好的兼容性。
- 增加了用于优雅关闭会话的耗尽超时 (drain timeout)。
- 更新了窗口大小，以匹配 Go http2 默认设置 (每个流 256KB，每个连接 1MB)。

#### AnyTLS 内存泄漏修复 (AnyTLS Memory Leak Fixes)
- 流处理任务现在会被追踪，并在会话关闭时被中止，从而防止孤立任务导致的内存泄漏。
- 增加了 5 分钟的流处理超时，防止挂起的流 (如缓慢的 DNS、卡住的连接) 导致内存泄漏。
- 减少了生成填充帧时的内存分配。

#### TUN 连接追踪 (TUN Connection Tracking)
- 使用显式状态 (Normal, Close, Closing, Closed) 重构了 TCP 连接状态机，以实现正确的生命周期管理。
- 参考 shadowsocks-rust 的模式，改进了连接的拆除处理。

## v0.2.6

### 新功能 (New Features)

#### H2MUX (兼容 sing-box 的 HTTP/2 多路复用)
H2MUX 将多个代理流复用到单个 HTTP/2 连接上，从而降低连接开销，并提高大量并发流的性能。这与 sing-box 的 h2mux 实现兼容。

**客户端配置 (VMess, VLESS, Trojan):**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    protocol:
      type: vmess
      cipher: aes-128-gcm
      user_id: "uuid"
      h2mux:
        max_connections: 4    # 维护的最大连接数
        min_streams: 4        # 在开启新连接之前的最小流数
        max_streams: 0        # 每个连接的最大流数 (0 = 无限制)
        padding: true         # 启用流量混淆填充
```

**服务端支持:** 在服务端，VMess、VLESS、Trojan、Shadowsocks 以及 Snell 协议均自动检测并支持 H2MUX。无需修改服务端配置。

#### H2MUX 客户端兼容性
Go 语言的 H2MUX 库曾包含一个阻止数据上传成功完成的 bug，请参阅 [https://github.com/SagerNet/sing-mux/pull/8](https://github.com/SagerNet/sing-mux/pull/8)

sing-box 现已包含此修复，但其他依赖未包含此更改的 sing-mux 的客户端 (如 mihomo) 可能会遇到问题。

#### DNS 解析超时
DNS 服务器现已支持可配置的超时时间，以防止在未响应的 DNS 服务器上发生挂起。

```yaml
- dns_group: my-dns
  servers:
    - url: "tls://dns.example.com"
      timeout_secs: 10      # 默认: 5。设置为 0 即可禁用。
```

### 改进 (Improvements)

- **DNS 连接超时**: DNS-over-TLS/HTTPS 连接现在遵守 5 秒的连接超时，以防止在无法连接 DNS 服务器时发生挂起。
- **Reality 服务端**: 改进了关闭处理，在每次转发操作后进行正确的 flush。

## v0.2.5

### 新功能 (New Features)

#### AnyTLS 协议

**服务端:**
```yaml
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      protocol:
        type: anytls
        users:
          - name: user1
            password: secret123
        udp_enabled: true
        padding_scheme: ["stop=8", "0=30-30"]  # 可选的自定义填充
        fallback: "127.0.0.1:80"               # 可选的回退地址
```

**客户端:**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    protocol:
      type: anytls
      password: secret123
```

#### NaiveProxy 协议

**服务端:**
```yaml
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      alpn_protocols: ["h2"]
      protocol:
        type: naiveproxy
        users:
          - username: user1
            password: secret123
        padding: true
        fallback: "/var/www/html"  # 可选的静态文件回退
```

**客户端:**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    alpn_protocols: ["h2"]
    protocol:
      type: naiveproxy
      username: user1
      password: secret123
```

#### 混合端口 (HTTP + SOCKS5)
自动检测 HTTP 或 SOCKS5 协议。

```yaml
- address: "0.0.0.0:7890"
  protocol:
    type: mixed
    username: user
    password: pass
    udp_enabled: true  # 启用 SOCKS5 UDP ASSOCIATE
```

#### TUN/VPN 支持
使用 TUN 设备的第三层 (Layer 3) VPN 模式，用于透明代理。支持 Linux、Android 和 iOS。

```yaml
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: vless
          user_id: "uuid"
```

**平台支持:**
- Linux: 使用指定的名称/地址创建 TUN 设备 (需要 root 权限)
- Android: 使用来自 `VpnService.Builder.establish()` 的 `device_fd`
- iOS: 使用来自 `NEPacketTunnelProvider.packetFlow` 的 `device_fd`

#### SOCKS5 UDP ASSOCIATE
为 SOCKS5 服务端提供完整的 UDP 支持，包括 UDP ASSOCIATE 命令。通过 `udp_enabled: true` (默认启用) 开启。

```yaml
protocol:
  type: socks
  udp_enabled: true  # 默认: true
```

#### VLESS 回退
将认证失败的尝试路由到回退目标，而不是直接拒绝。

```yaml
protocol:
  type: vless
  user_id: "uuid"
  fallback: "127.0.0.1:80"  # 为无效客户端提供网页内容
```

#### Reality `dest_client_chain`
通过代理链路由 Reality 回退 (dest) 连接。

```yaml
reality_targets:
  "www.example.com":
    private_key: "..."
    dest: "www.example.com:443"
    dest_client_chain:
      address: "proxy.example.com:1080"
      protocol:
        type: socks
    protocol:
      type: vless
      user_id: "uuid"
```

### 改进 (Improvements)

- **UDP 路由**: 全面重写 UDP 会话路由，更好地支持多路复用。
- **Reality**: 通过 TLS 1.3 验证增强了对主动探测的抵抗力。
- **性能**: 优化了缓冲区的处理，减少了内存分配。
- **QUIC**: 基于 quic-go 的建议优化了缓冲区的大小。

### 移动端支持 (Mobile Support)

- **iOS FFI**: 通过集成 `NEPacketTunnelProvider` 增加了 iOS 绑定。
- **Android FFI**: 通过集成 `VpnService` 增加了 Android 绑定。
- 该库现已编译为 `rlib`、`cdylib` 和 `staticlib` 格式，以供移动端嵌入使用。

---

## v0.2.1

## 新功能 (New Features)

### 客户端链 (`client_chains`)
具有负载均衡支持的多跳代理链。现在可以将流量依序路由通过多个代理。

- **多跳链**: 将流量顺序路由通过多个代理 (例如: `proxy1 -> proxy2 -> target`)
- **轮询链**: 指定多条链并在它们之间轮换，以分配负载
- **基于池的负载均衡**: 在每一跳，使用代理池进行负载均衡
- 新增配置字段: `client_chain` (单数) 和 `client_chains` (复数)
- 具体用法示例请参考 `examples/multi_hop_chain.yaml`

### TUIC v5 零往返 (Zero-RTT) 握手
为 TUIC v5 服务端新增了 `zero_rtt_handshake` 选项，启用 0-RTT (服务端为 0.5-RTT) 握手，以实现更快的连接建立。

```yaml
protocol:
  type: tuic
  uuid: "..."
  password: "..."
  zero_rtt_handshake: true  # 默认: false
```

注意: 0-RTT 容易受到重放攻击。只有在低延迟的收益大于安全隐患时才应启用。

### Reality 密码套件
Reality 的服务端和客户端现在都支持指定 TLS 1.3 密码套件。

```yaml
# 服务端
reality_targets:
  "example.com":
    cipher_suites: ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
    ...

# 客户端
protocol:
  type: reality
  cipher_suites: ["TLS_AES_256_GCM_SHA384"]
  ...
```

有效值: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`

### Reality 客户端版本控制
服务端 Reality 配置现在能够限制客户端版本:

```yaml
reality_targets:
  "example.com":
    min_client_version: [1, 8, 0]  # [主版本号, 次版本号, 补丁号]
    max_client_version: [2, 0, 0]
    ...
```

## 废弃项 (Deprecations)

### 规则中的 `client_proxy` / `client_proxies`
规则配置中的 `client_proxy` 和 `client_proxies` 字段已被废弃，现在推荐使用 `client_chain` 和 `client_chains`。

**迁移指南**: 请在您的配置文件中将 `client_proxy:` 替换为 `client_chain:`。旧字段目前仍可使用，但会触发警告提示，并可能在将来的版本中被移除。

修改前:
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_proxy: my-proxy-group
```

修改后:
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_chain: my-proxy-group
```

### VMess `force_aead` / `aead` 字段
VMess 配置中的 `force_aead` 和 `aead` 字段已被废弃。现在 AEAD 模式始终处于开启状态，并且不再支持非 AEAD (旧版) 模式。

**迁移指南**: 请从您的 VMess 配置中移除 `force_aead` 和 `aead` 字段。它们已无任何效果并将被忽略。

## 移除 / 破坏性变更 (Removed / Breaking Changes)

### VMess 非 AEAD 模式已被移除
不再支持 VMess 非 AEAD (旧版) 模式。所有 VMess 连接现在专门使用 AEAD 加密。这提升了安全性，但会破坏与不支持 AEAD 的非常老的 VMess 客户端的兼容性。

## 其他变更 (Other Changes)

- Hysteria2 和 TUIC 服务端现在具有认证超时 (默认为 3 秒)，防止连接被长时间占用。
- 改进了分片数据包处理，使用 LRU 缓存淘汰机制。
- TUIC 服务端现在发送心跳包以保持连接的活跃状态。
