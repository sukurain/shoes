# 配置参考 (Configuration Reference)

shoes 使用 YAML 配置文件。可以将多种配置类型组合在单个文件中，也可以拆分到多个文件中。

## 目录
- [配置结构](#配置结构-configuration-structure)
- [服务端配置](#服务端配置-server-config)
- [服务端协议](#服务端协议-server-protocols)
- [TUN 配置](#tun-配置-tun-config)
- [客户端配置](#客户端配置-client-config)
- [客户端协议](#客户端协议-client-protocols)
- [规则系统](#规则系统-rules-system)
- [命名组](#命名组-named-groups)
- [命名 PEM](#命名-pem-named-pems)
- [高级功能](#高级功能-advanced-features)
- [命令行](#命令行-command-line)

## 配置结构 (Configuration Structure)

配置文件是一个包含一个或多个配置项的 YAML 数组。每个配置项可以是：

- **Server Config (服务端配置)** - 定义一个代理服务器实例
- **TUN Config (TUN 配置)** - 定义用于透明代理的 TUN/VPN 设备
- **Client Config Group (客户端配置组)** - 定义可重用的上游代理配置
- **Rule Config Group (规则配置组)** - 定义可重用的路由规则
- **Named PEM (命名 PEM)** - 定义可重用的证书/密钥数据

```yaml
# 服务端配置包含 'address' 或 'path'
- address: "0.0.0.0:8080"
  protocol: ...

# TUN 配置包含 'device_name' 或 'device_fd'
- device_name: "tun0"
  address: "10.0.0.1"
  ...

# 客户端配置组包含 'client_group'
- client_group: my-upstream
  client_proxy: ...

# 规则配置组包含 'rule_group'
- rule_group: my-rules
  rules: ...

# 命名 PEM 包含 'pem'
- pem: my-cert
  path: /path/to/cert.pem
```

## 服务端配置 (Server Config)

```yaml
# 绑定到 IP 地址和端口
address: "0.0.0.0:8080"        # IPv4
address: "[::]:8080"           # IPv6
address: "0.0.0.0:443-445"     # 端口范围

# 或绑定到 Unix socket (仅支持 TCP)
path: "/tmp/shoes.sock"

# 协议配置 (必填)
protocol: ServerProxyConfig

# 传输层 (默认: tcp)
transport: tcp | quic

# TCP 设置 (仅当 transport: tcp 时有效)
tcp_settings:
  no_delay: true               # 默认: true

# QUIC 设置 (当 transport: quic 时必填)
quic_settings:
  cert: string                 # TLS 证书 (路径或命名 PEM)
  key: string                  # TLS 私钥 (路径或命名 PEM)
  alpn_protocols: [string]     # 可选的 ALPN 协议
  client_ca_certs: [string]    # 可选的客户端 CA 证书
  client_fingerprints: [string] # 可选的客户端证书指纹
  num_endpoints: int           # 可选，0 = 自动 (基于线程数)

# 路由规则 (默认: allow-all-direct)
rules: string | [RuleConfig]
```

## 服务端协议 (Server Protocols)

### HTTP
```yaml
protocol:
  type: http
  username: string?            # 可选的身份验证
  password: string?
```

### SOCKS5
```yaml
protocol:
  type: socks                  # 别名: socks5
  username: string?
  password: string?
  udp_enabled: true            # 默认: true (启用 UDP ASSOCIATE)
```

### 混合模式 (HTTP + SOCKS5)
```yaml
protocol:
  type: mixed                  # 别名: http+socks, socks+http
  username: string?
  password: string?
  udp_enabled: true            # 默认: true (为 SOCKS5 启用 UDP ASSOCIATE)
```

根据连接的第一个字节自动检测 HTTP 或 SOCKS5 协议。

### Shadowsocks
```yaml
protocol:
  type: shadowsocks            # 别名: ss
  cipher: string               # 参见下方支持的加密方式
  password: string

# 支持的加密方式:
# - aes-128-gcm
# - aes-256-gcm
# - chacha20-ietf-poly1305
# - 2022-blake3-aes-128-gcm
# - 2022-blake3-aes-256-gcm
# - 2022-blake3-chacha20-ietf-poly1305
```

### VMess
```yaml
protocol:
  type: vmess
  cipher: string               # aes-128-gcm, chacha20-poly1305, none
  user_id: string              # UUID
  udp_enabled: true            # 默认: true (启用 XUDP)
```

**注意:** VMess AEAD 模式始终处于启用状态。已废弃旧版 `force_aead` 字段，不再支持非 AEAD 模式。

### VLESS
```yaml
protocol:
  type: vless
  user_id: string              # UUID
  udp_enabled: true            # 默认: true (启用 XUDP)
  fallback: string?            # 可选的认证失败回退目标 (例如: "127.0.0.1:80")
```

### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # 可选的加密层
    cipher: string
    password: string
```

### Snell v3
```yaml
protocol:
  type: snell
  cipher: string               # aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
  password: string
  udp_enabled: true            # 默认: true
  udp_num_sockets: 1           # 默认: 1, 每个 UDP 会话的套接字数
```

### TLS Server
```yaml
protocol:
  type: tls

  # 标准 TLS 目标 (根据 SNI)
  tls_targets:                 # 别名: sni_targets, targets
    "example.com":
      cert: string             # 证书 (路径或命名 PEM)
      key: string              # 私钥 (路径或命名 PEM)
      alpn_protocols: [string] # 可选的 ALPN
      client_ca_certs: [string] # 可选的客户端 CA 证书
      client_fingerprints: [string] # 可选的客户端证书指纹
      vision: false            # 启用 Vision (需要 VLESS 内部协议)
      protocol: ServerProxyConfig
      override_rules: [RuleConfig] # 可选的规则覆盖

  # 默认 TLS 目标 (无匹配或无 SNI 时)
  default_tls_target:          # 别名: default_target
    cert: string
    key: string
    # ... 与 tls_targets 的字段相同

  # Reality 目标 (根据 SNI)
  reality_targets:
    "www.cloudflare.com":
      private_key: string      # X25519 私钥 (base64url)
      short_ids: [string]      # 有效的客户端 ID (十六进制, 0-16 个字符)
      dest: string             # 回退目标 (例如: "example.com:443")
      dest_client_chain: ClientChain?  # 可选的用于到达回退目标的代理链
      max_time_diff: 60000     # 最大时间差(毫秒) (默认: 60000)
      min_client_version: [1, 8, 0]  # 可选的 [主版本, 次版本, 补丁号]
      max_client_version: [2, 0, 0]  # 可选的 [主版本, 次版本, 补丁号]
      cipher_suites: [string]  # 可选的 TLS 1.3 密码套件 (见下方)
      vision: false            # 启用 Vision (需要 VLESS 内部协议)
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]

  # ShadowTLS v3 目标 (根据 SNI)
  shadowtls_targets:
    "example.com":
      password: string
      handshake:
        # 本地握手 (使用自己的证书):
        cert: string
        key: string
        alpn_protocols: [string]
        client_ca_certs: [string]
        client_fingerprints: [string]
        # 或远程握手 (代理至真实服务器):
        address: string        # 例如: "google.com:443"
        client_proxies: [ClientConfig] # 可选的用于握手的代理
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]

  # TLS 缓冲区大小 (可选, 最小 16384)
  tls_buffer_size: int
```

### WebSocket
```yaml
protocol:
  type: websocket              # 别名: ws
  targets:
    - matching_path: string?   # 可选的路径匹配 (例如: "/ws")
      matching_headers:        # 可选的头部匹配
        X-Custom-Header: "value"
      protocol: ServerProxyConfig
      ping_type: ping-frame    # disabled | ping-frame | empty-frame
      override_rules: [RuleConfig]
```

### 端口转发 (Port Forward)
```yaml
protocol:
  type: forward                # 别名: port_forward, portforward
  targets: string | [string]   # 目标地址
```

### Hysteria2
```yaml
protocol:
  type: hysteria2
  password: string
  udp_enabled: true            # 默认: true
```

### TUIC v5
```yaml
protocol:
  type: tuic                   # 别名: tuicv5
  uuid: string                 # UUID
  password: string
  zero_rtt_handshake: false    # 默认: false (启用 0-RTT 可实现更低延迟)
```

### AnyTLS
```yaml
protocol:
  type: anytls
  users:                       # 一个或多个用户
    - name: string?            # 可选的显示名称
      password: string         # 用户密码
  udp_enabled: true            # 默认: true (启用基于 TCP 的 UDP)
  padding_scheme: [string]?    # 可选的自定义填充 (例如: ["stop=8", "0=30-30"])
  fallback: string?            # 可选的认证失败回退目标
```

AnyTLS 是一种带有流量混淆的基于 TLS 的多路复用代理协议。应在 TLS 或 Reality 内部使用。

### NaiveProxy
```yaml
protocol:
  type: naiveproxy             # 别名: naive
  users:                       # 一个或多个用户
    - name: string?            # 可选的显示名称
      username: string         # Basic Auth 用户名
      password: string         # Basic Auth 密码
  padding: true                # 默认: true (启用填充协议)
  udp_enabled: true            # 默认: true (启用基于 TCP 的 UDP)
  fallback: string?            # 可选的用于提供静态文件以抵抗主动探测的路径
```

NaiveProxy 实现了带有用于抵抗审查填充的 HTTP/2 CONNECT。应在配置了 `alpn_protocols: ["h2"]` 的 TLS 内部使用。

## TUN 配置 (TUN Config)

TUN（网络隧道）设备在 IP 层 (第三层) 运行，这允许 shoes 作为透明 VPN 工作。

```yaml
# Linux: 根据名称创建 TUN 设备
device_name: string            # 设备名称 (例如: "tun0")
address: string                # 设备 IP 地址 (例如: "10.0.0.1")
netmask: string?               # 子网掩码 (例如: "255.255.255.0")
destination: string?           # 网关/目标 (仅限 Linux)

# iOS/Android: 使用现有的文件描述符 (File Descriptor)
device_fd: int                 # 来源于 VpnService (Android) 或 NEPacketTunnelProvider (iOS) 的 FD

# 通用设置
mtu: 1500                      # 默认: 1500 (Linux), 9000 (Android), 4064 (iOS)
tcp_enabled: true              # 默认: true
udp_enabled: true              # 默认: true
icmp_enabled: true             # 默认: true

# 路由规则
rules: [RuleConfig]
```

**平台说明:**
- **Linux**: 需要 root 权限或 `CAP_NET_ADMIN`。根据指定名称/地址创建设备。
- **Android**: 使用 `VpnService.Builder.establish()` 返回的 `device_fd`。路由由 VpnService 配置。
- **iOS**: 使用 `NEPacketTunnelProvider.packetFlow` 返回的 `device_fd`。

**示例 (Linux):**
```yaml
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: tls
          protocol:
            type: vless
            user_id: "uuid"
```

## 客户端配置 (Client Config)

在规则中用于指定上游代理。

```yaml
address: string                # 代理服务器地址 (例如: "proxy.example.com:1080")
protocol: ClientProxyConfig
transport: tcp | quic          # 默认: tcp
bind_interface: string         # 可选, 仅限 Linux/Android/Fuchsia

tcp_settings:
  no_delay: true

quic_settings:
  verify: true                 # 默认: true
  server_fingerprints: [string]
  sni_hostname: string
  alpn_protocols: [string]
  cert: string                 # 用于 mTLS 的客户端证书
  key: string                  # 用于 mTLS 的客户端私钥
```

## 客户端协议 (Client Protocols)

### 直连 (Direct)
```yaml
protocol:
  type: direct
```

### HTTP
```yaml
protocol:
  type: http
  username: string?
  password: string?
```

### SOCKS5
```yaml
protocol:
  type: socks
  username: string?
  password: string?
```

### Shadowsocks
```yaml
protocol:
  type: shadowsocks
  cipher: string
  password: string
```

### Snell
```yaml
protocol:
  type: snell
  cipher: string
  password: string
```

### VMess
```yaml
protocol:
  type: vmess
  cipher: string
  user_id: string
  h2mux:                         # 可选的 h2mux 多路复用 (见下方)
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

**注意:** VMess AEAD 模式始终启用。已废弃旧版 `aead` 字段。

### VLESS
```yaml
protocol:
  type: vless
  user_id: string
  h2mux:                         # 可选的 h2mux 多路复用 (见下方)
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # 可选
    cipher: string
    password: string
  h2mux:                         # 可选的 h2mux 多路复用 (见下方)
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

### H2MUX 多路复用 (H2MUX Multiplexing)

H2MUX 将多个代理流复用到单个 HTTP/2 连接上，从而减少连接开销。与 sing-box 兼容。支持 VMess、VLESS 和 Trojan 客户端协议。

```yaml
h2mux:
  max_connections: 4           # 维护的最大连接数 (默认: 4)
  min_streams: 4               # 在开启新连接之前的最小流数 (默认: 4)
  max_streams: 0               # 每个连接的最大流数, 0 = 无限制 (默认: 0)
  padding: false               # 启用流量混淆填充 (默认: false)
```

**服务端支持:** 服务端会自动检测 H2MUX。无需进行配置。

### TLS Client
```yaml
protocol:
  type: tls
  verify: true                 # 默认: true
  server_fingerprints: [string]
  sni_hostname: string
  alpn_protocols: [string]
  tls_buffer_size: int
  cert: string                 # 用于 mTLS 的客户端证书
  key: string                  # 用于 mTLS 的客户端私钥
  vision: false                # 启用 Vision (需要 VLESS 内部协议)
  protocol: ClientProxyConfig
```

### Reality Client
```yaml
protocol:
  type: reality
  public_key: string           # 服务器的 X25519 公钥 (base64url)
  short_id: string             # 您的客户端 ID (十六进制, 0-16 个字符)
  sni_hostname: string         # 要发送的 SNI (必须与服务端的 reality_targets key 匹配)
  cipher_suites: [string]      # 可选的 TLS 1.3 密码套件 (见下方)
  vision: false                # 启用 Vision (需要 VLESS 内部协议)
  protocol: ClientProxyConfig  # 内部协议 (通常是 VLESS)
```

**Reality 密码套件:** 有效值为 `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`。如果未指定，将提供/支持全部三种。

### ShadowTLS Client
```yaml
protocol:
  type: shadowtls
  password: string
  sni_hostname: string?        # 可选的 SNI 覆盖
  protocol: ClientProxyConfig
```

### WebSocket Client
```yaml
protocol:
  type: websocket
  matching_path: string?
  matching_headers:
    header_name: string
  ping_type: ping-frame        # disabled | ping-frame | empty-frame
  protocol: ClientProxyConfig
```

### 端口转发 (无操作) (Port Forward (No-op))
```yaml
protocol:
  type: portforward            # 别名: noop
```

直接透传原始连接，不进行协议包装。适用于测试或透明代理。

### AnyTLS Client
```yaml
protocol:
  type: anytls
  password: string             # 用户密码
  udp_enabled: true            # 默认: true (启用基于 TCP 的 UDP)
  padding_scheme: [string]?    # 可选的自定义填充方案
```

### NaiveProxy Client
```yaml
protocol:
  type: naiveproxy             # 别名: naive
  username: string             # Basic Auth 用户名
  password: string             # Basic Auth 密码
  padding: true                # 默认: true (启用填充协议)
```

## 规则系统 (Rules System)

规则决定了传入连接的路由方式。

### 规则配置 (Rule Config)
```yaml
rules:
  - masks: string | [string]   # IP/CIDR 或主机名掩码
    action: allow | block
    # 对于 action: allow
    override_address: string?  # 可选的地址覆盖
    client_chain: ClientChain | [ClientChain]  # 用于路由的代理链
```

### 客户端链 (Client Chains)

客户端链定义了流量应如何通过上游代理路由。每条链都是一系列“跃点” (hops) - 即流量按顺序通过的代理。

```yaml
# 单个代理 (最简单形式)
client_chain: my-proxy-group           # 引用命名组
client_chain:                          # 或内联配置
  address: "proxy.example.com:1080"
  protocol:
    type: socks

# 多跳链 (流量走向: 客户端 -> hop1 -> hop2 -> 目标)
client_chain:
  chain:
    - first-proxy-group
    - second-proxy-group

# 多条链 (轮询选择)
client_chains:
  - us-proxy-group                     # 链 1: 单跳
  - chain: [proxy1, proxy2]            # 链 2: 多跳

# 在跃点处进行负载均衡 (代理池)
client_chain:
  chain:
    - pool: [us-proxies, eu-proxies]   # 在池成员之间轮询
    - final-proxy
```

**迁移说明:** `client_proxy` / `client_proxies` 字段仍然有效但已被废弃。请迁移至 `client_chain` / `client_chains`。

### 掩码语法 (Mask Syntax)
```yaml
# IP/CIDR 掩码
masks: "0.0.0.0/0"             # 所有 IPv4
masks: "::/0"                  # 所有 IPv6
masks: "192.168.0.0/16"        # 子网
masks: "10.0.0.1:80"           # 特定 IP 和端口

# 主机名掩码
masks: "*.google.com"          # 通配符子域名
masks: "example.com"           # 精确匹配

# 多个掩码
masks:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "*.internal.com"
```

### 内置规则组
- `allow-all-direct` - 允许所有连接，并直连路由
- `block-all` - 阻止所有连接

### 示例规则 (Example Rules)
```yaml
rules:
  # 对本地网络使用直连
  - masks: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    action: allow
    client_chain:
      protocol:
        type: direct

  # 阻止特定域名
  - masks: ["*.ads.example.com", "tracking.example.com"]
    action: block

  # 通过上游代理路由
  - masks: "0.0.0.0/0"
    action: allow
    client_chain:
      address: "proxy.example.com:1080"
      protocol:
        type: socks
```

## 命名组 (Named Groups)

### 客户端代理组 (Client Proxy Group)
```yaml
- client_group: my-upstream
  client_proxies:              # 在此组中定义代理
    - address: "proxy1.example.com:1080"
      protocol:
        type: socks
    - address: "proxy2.example.com:1080"
      protocol:
        type: socks

# 在规则中引用
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream  # 根据名称引用
```

### 规则组 (Rule Group)
```yaml
- rule_group: standard-rules
  rules:
    - masks: ["192.168.0.0/16"]
      action: allow
      client_chain:
        protocol:
          type: direct
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream

# 在服务端配置中引用
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules: standard-rules        # 根据名称引用
```

## 命名 PEM (Named PEMs)

只需定义一次证书，便可在整个配置中引用。

```yaml
# 来自文件
- pem: my-cert
  path: /path/to/certificate.pem

# 内联数据
- pem: my-key
  data: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----

# 在配置中引用
- address: "0.0.0.0:443"
  protocol:
    type: tls
    tls_targets:
      "example.com":
        cert: my-cert          # 根据名称引用
        key: my-key
        protocol:
          type: http
```

## 高级功能 (Advanced Features)

### Vision (XTLS-Vision)

Vision 能够通过探测内部 TLS 流量并切换至直连模式来实现零拷贝性能，从而对 TLS-in-TLS 场景进行优化。

**要求:**
- 内部协议必须是 VLESS
- 支持 TLS 和 Reality 协议

```yaml
# TLS + Vision
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      vision: true
      alpn_protocols: ["http/1.1"]
      protocol:
        type: vless
        user_id: "uuid"

# Reality + Vision
protocol:
  type: tls
  reality_targets:
    "www.google.com":
      private_key: "..."
      short_ids: ["..."]
      dest: "www.google.com:443"
      vision: true
      protocol:
        type: vless
        user_id: "uuid"
```

### XUDP 多路复用 (XUDP Multiplexing)

当设置 `udp_enabled: true` 时自动为 VMess 和 VLESS 启用。可通过单个连接复用 UDP 流量。

### 代理链 (Proxy Chaining)

**协议嵌套** (将一种协议包装在另一种中):

```yaml
client_chain:
  address: "proxy.example.com:443"
  protocol:
    type: tls
    protocol:
      type: vmess
      cipher: aes-128-gcm
      user_id: "uuid"
```

**多跳链** (流量依次经过多个代理路由):

```yaml
client_chain:
  chain:
    - address: "proxy1.example.com:1080"
      protocol:
        type: socks
    - address: "proxy2.example.com:443"
      protocol:
        type: tls
        protocol:
          type: vless
          user_id: "uuid"
```

### 热重载 (Hot Reloading)

自动检测并应用配置变更，无需重启。可通过 `--no-reload` 标志来禁用。

### mTLS (双向 TLS)

要求客户端证书进行身份验证:

```yaml
# 服务端
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: server.crt
      key: server.key
      client_ca_certs: [ca.crt]  # 所需的 CA
      client_fingerprints: ["sha256:..."]  # 可选的特定证书
      protocol: ...

# 客户端
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    cert: client.crt
    key: client.key
    protocol: ...
```

## 命令行 (Command Line)

```bash
shoes [OPTIONS] <config.yaml> [config.yaml...]

OPTIONS:
  -t, --threads NUM    工作线程数 (默认: CPU 核心数)
  -d, --dry-run        解析配置并退出
  --no-reload          禁用热重载

COMMANDS:
  generate-reality-keypair                       生成 Reality X25519 密钥对
  generate-shadowsocks-2022-password <cipher>    生成 Shadowsocks 2022 密码
```

## 提示 (Tips)

### 生成密钥 (Generate Keys)

**Reality 密钥对:**
```bash
shoes generate-reality-keypair
```

**Shadowsocks 2022 密码:**
```bash
shoes generate-shadowsocks-2022-password 2022-blake3-aes-256-gcm
```

**UUID:**
```bash
uuidgen
```

**TLS 证书指纹:**
```bash
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

### 安全最佳实践 (Security Best Practices)

- 使用强大的随机密码
- 妥善保管私钥
- 使用 `127.0.0.1` 替代 `0.0.0.0` 用于仅本地访问
- 使用防火墙规则限制访问
- 为敏感服务启用客户端证书身份验证
- 将 Vision 与 Reality 搭配使用以获得最大隐私

### 性能优化提示 (Performance Tips)

- 为 TLS-in-TLS 场景启用 `vision: true`
- 为获得低延迟，使用 `tcp_settings.no_delay: true`
- 将 `quic_settings.num_endpoints` 设为匹配工作线程数
- 针对高延迟或容易丢包的网络，使用 QUIC 传输协议

### 常见问题 (Common Issues)

- **"Address already in use" (地址已被占用)**: 更改端口或停止发生冲突的服务
- **"Permission denied" (权限被拒绝)**: 端口号 < 1024 时需要 root/管理员权限
- **Reality 连接失败**: 检查密钥是否匹配、UUID 是否匹配、以及 SNI 是否与服务端的 reality_targets 键匹配
- **Vision 无法工作**: 确保内部协议为 VLESS
- **配置校验失败**: 使用 `--dry-run` 运行以获取详细错误信息
