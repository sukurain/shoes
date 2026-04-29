# 更新日志

本 fork 基于 https://github.com/cfal/shoes，并包含 WireGuard 出站、QUIC 配置和路由性能方面的修改。

## v0.2.8

### 新功能

#### WireGuard 客户端出站

新增套接字级别的标准 WireGuard 出站支持，可将选定流量通过 WireGuard 对等节点路由。WARP 配置中的 `reserved`/client id 扩展不再支持。

```yaml
client_chain:
  protocol:
    type: wireguard
    private-key: "YOUR_BASE64_PRIVATE_KEY"
    server: 203.0.113.10
    port: 51820
    ip: 10.8.0.2
    ipv6: 2001:db8:100::2
    public-key: "PEER_BASE64_PUBLIC_KEY"
    allowed-ips: ["0.0.0.0/0", "::/0"]
    udp: true
    mtu: 1408
    ip-version: ipv6-prefer
    remote-dns-resolve: true
    dns: ["2606:4700:4700::1111"]
```

支持的 WireGuard 选项包括 `private-key`、`public-key`、`pre-shared-key`、`server`、`port`、`ip`、`ipv6`、`allowed-ips`、`udp`、`mtu`、`ip-version`、`remote-dns-resolve` 和 `dns`。

完整可复制示例：
- `examples/wireguard_outbound_basic.yaml`
- `examples/hysteria2_server_bbr.yaml`
- `examples/tuic_v5_bbr.yaml`
- `examples/quic_client_bbr.yaml`

### 改进

- 在 WireGuard 运行时中添加了有界队列和数据包缓冲区复用，避免高负载下内存无限增长。
- WireGuard 出站在配置重载或连接器释放时通过 cancellation token 停止后台任务，避免旧隧道继续持有 UDP socket。
- WireGuard 出站队列满时会向上层返回背压错误，避免静默伪装为发送成功。
- 为 WireGuard 出站主机名解析添加了远程 DNS 缓存。
- 在运行时选择可用目标地址时强制执行 WireGuard `allowed-ips` 规则。
- QUIC 拥塞控制支持 `quic_settings.congestion: bbr`，未配置时使用 Quinn 默认行为。
- 客户端正常断开、QUIC stream reset、BrokenPipe、UnexpectedEof 等日志降级为 debug，减少运行时 ERROR 刷屏。
- 新增索引化主机名规则匹配，加速大型主机名规则集的路由决策。

## v0.2.7

### 改进

#### H2MUX 稳定性
- 添加了连接级别的活动跟踪，将 HTTP/2 控制帧（PING、SETTINGS）计为活动状态，确保保活机制正确重置空闲检测
- 移除了应用层空闲超时，改用基于 PING 的死连接检测，匹配 sing-mux 行为以获得更好的兼容性
- 添加了优雅会话关闭的排空超时
- 更新窗口大小以匹配 Go http2 默认值（每流 256KB，每连接 1MB）

#### AnyTLS 内存泄漏修复
- 流处理任务现在在会话关闭时被跟踪和中止，防止孤立任务导致的内存泄漏
- 添加了 5 分钟流处理超时，防止卡住的流（慢速 DNS、阻塞连接）导致内存泄漏
- 减少了填充帧生成中的内存分配

#### TUN 连接追踪
- 重构了 TCP 连接状态机，使用显式状态（Normal、Close、Closing、Closed）进行正确的生命周期管理
- 改进了连接拆除处理，遵循 shadowsocks-rust 模式

## v0.2.6

### 新功能

#### H2MUX（sing-box 兼容的 HTTP/2 多路复用）

H2MUX 在单个 HTTP/2 连接上多路复用多个代理流，减少连接开销并提高大量并发流的性能。与 sing-box 的 h2mux 实现兼容。

**客户端配置（VMess、VLESS、Trojan）：**
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
        min_streams: 4        # 打开新连接前的最小流数
        max_streams: 0        # 每个连接的最大流数（0 = 无限制）
        padding: true         # 启用填充以混淆流量
```

**服务端支持：** H2MUX 在服务端为 VMess、VLESS、Trojan、Shadowsocks 和 Snell 协议自动检测。无需更改服务端配置。

#### H2MUX 客户端兼容性

Go H2MUX 库包含一个阻止数据上传成功完成的 bug，参见 [https://github.com/SagerNet/sing-mux/pull/8](https://github.com/SagerNet/sing-mux/pull/8)

sing-box 已包含此修复，但其他依赖 sing-mux 且未包含此更改的客户端（如 mihomo）可能会出现问题。

#### DNS 解析超时

DNS 服务器现在支持可配置的超时，防止在无响应的 DNS 服务器上挂起。

```yaml
- dns_group: my-dns
  servers:
    - url: "tls://dns.example.com"
      timeout_secs: 10      # 默认值：5。设为 0 可禁用。
```

### 改进

- **DNS 连接超时**：DNS-over-TLS/HTTPS 连接现在遵循 5 秒连接超时，防止 DNS 服务器不可达时挂起
- **Reality 服务端**：改进了关闭处理，每次转发操作后正确刷新

## v0.2.5

### 新功能

#### AnyTLS 协议

**服务端：**
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
        padding_scheme: ["stop=8", "0=30-30"]  # 可选自定义填充
        fallback: "127.0.0.1:80"               # 可选回退地址
```

**客户端：**
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

**服务端：**
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
        fallback: "/var/www/html"  # 可选静态文件回退
```

**客户端：**
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

#### 混合端口（HTTP + SOCKS5）
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
使用 TUN 设备进行透明代理的第三层 VPN 模式。支持 Linux、Android 和 iOS。

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

**平台支持：**
- Linux：使用指定的名称/地址创建 TUN 设备（需要 root 权限）
- Android：使用来自 `VpnService.Builder.establish()` 的 `device_fd`
- iOS：使用来自 `NEPacketTunnelProvider.packetFlow` 的 `device_fd`

#### SOCKS5 UDP ASSOCIATE
完整的 SOCKS5 服务器 UDP 支持，包括 UDP ASSOCIATE 命令。使用 `udp_enabled: true`（默认值）启用。

```yaml
protocol:
  type: socks
  udp_enabled: true  # 默认值：true
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
将 Reality 回退（dest）连接通过代理链路由。

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

### 改进

- **UDP 路由**：全面重写 UDP 会话路由，更好地支持多路复用
- **Reality**：改进了主动探测抵抗能力，增加 TLS 1.3 验证
- **性能**：优化缓冲区处理并减少内存分配
- **QUIC**：根据 quic-go 建议改进缓冲区大小

### 移动端支持

- **iOS FFI**：通过 `NEPacketTunnelProvider` 集成添加 iOS 绑定
- **Android FFI**：通过 `VpnService` 集成添加 Android 绑定
- 库现在构建为 `rlib`、`cdylib` 和 `staticlib`，以支持移动端嵌入

---

## v0.2.1

## 新功能

### 客户端链式代理（`client_chains`）
支持负载均衡的多跳代理链。流量现在可以通过多个代理依次路由。

- **多跳链**：通过多个代理依次路由流量（例如 `proxy1 -> proxy2 -> target`）
- **轮询链**：指定多个链并在它们之间轮换以分配负载
- **基于池的负载均衡**：在每一跳使用代理池进行负载均衡
- 新配置字段：`client_chain`（单个）和 `client_chains`（多个）
- 使用示例参见 `examples/multi_hop_chain.yaml`

### TUIC v5 零往返握手
TUIC v5 服务器新增 `zero_rtt_handshake` 选项，启用 0-RTT（服务端为 0.5-RTT）握手以加快连接建立。

```yaml
protocol:
  type: tuic
  uuid: "..."
  password: "..."
  zero_rtt_handshake: true  # 默认值：false
```

注意：0-RTT 容易受到重放攻击。仅在延迟优势大于安全风险时启用。

### Reality 密码套件
Reality 服务端和客户端现在都支持指定 TLS 1.3 密码套件。

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

有效值：`TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`

### Reality 客户端版本控制
服务端 Reality 配置现在可以限制客户端版本：

```yaml
reality_targets:
  "example.com":
    min_client_version: [1, 8, 0]  # [主版本, 次版本, 补丁版本]
    max_client_version: [2, 0, 0]
    ...
```

## 弃用项

### 规则中的 `client_proxy` / `client_proxies`
规则配置中的 `client_proxy` 和 `client_proxies` 字段已弃用，改用 `client_chain` 和 `client_chains`。

**迁移方法**：在配置文件中将 `client_proxy:` 替换为 `client_chain:`。旧字段仍然有效，但会发出警告，可能在未来版本中移除。

之前：
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_proxy: my-proxy-group
```

之后：
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_chain: my-proxy-group
```

### VMess `force_aead` / `aead` 字段
VMess 配置中的 `force_aead` 和 `aead` 字段已弃用。AEAD 模式现在始终启用，不再支持非 AEAD（旧版）模式。

**迁移方法**：从 VMess 配置中移除 `force_aead` 和 `aead` 字段。它们没有效果，将被忽略。

## 移除/破坏性变更

### VMess 非 AEAD 模式已移除
不再支持 VMess 非 AEAD（旧版）模式。所有 VMess 连接现在专用 AEAD 加密。这提高了安全性，但会破坏与不支持 AEAD 的旧版 VMess 客户端的兼容性。

## 其他变更

- Hysteria2 和 TUIC 服务器现在有认证超时（默认 3 秒），防止连接占用
- 改进了分片数据包处理，使用 LRU 缓存淘汰
- TUIC 服务器现在发送心跳包以维持连接活跃
