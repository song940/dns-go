# 架构概述

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application Layer                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  CLI (main) │  │  Examples   │  │  Custom Implementation  │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                          Client Layer                            │
│  ┌─────────────────────┐  ┌─────────────────────────────────┐   │
│  │   UDP Client        │  │   DoH Client                    │   │
│  │   - Query()         │  │   - Query()                     │   │
│  │   - net.Dial        │  │   - HTTP Client                 │   │
│  └─────────────────────┘  └─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Packet Layer (Core)                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    DNSPacket                               │  │
│  │  ┌──────────┐ ┌───────────┐ ┌──────────────────────────┐  │  │
│  │  │  Header  │ │ Questions │ │  Answers/Authorities/    │  │  │
│  │  │  (12B)   │ │ (Variable)│ │  Additionals (Variable)  │  │  │
│  │  └──────────┘ └───────────┘ └──────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Resource Records: classic, DNSSEC, CAA, TLSA, SVCB/HTTPS, EDNS │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Server Layer                             │
│  ┌─────────────────────┐  ┌─────────────────────────────────┐   │
│  │   UDP Server        │  │   HTTP/DoH Server               │   │
│  │   - ListenUDP()     │  │   - ListenHTTP()                │   │
│  │   - serveUDP()      │  │   - HandleQuery()               │   │
│  └─────────────────────┘  └─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 数据流

### 客户端查询流程

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  User   │────▶│  Client  │────▶│  Packet  │────▶│  Server  │
│  Code   │     │  (UDP/  │     │  Encode  │     │  (DNS/  │
│         │     │   DoH)   │     │          │     │   DoH)   │
└─────────┘     └──────────┘     └──────────┘     └──────────┘
     ▲                                  │                │
     │                                  │                │
     │                                  ▼                │
     │                            ┌──────────┐          │
     │                            │  Network │          │
     │                            │  (UDP/  │          │
     │                            │  HTTP)   │          │
     │                            └──────────┘          │
     │                                  │                │
     │                                  ▼                │
     │                            ┌──────────┐          │
     └────────────────────────────│  Packet  │◀─────────┘
                                  │  Decode  │
                                  └──────────┘
```

### 服务器处理流程

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌─────────┐
│  Client  │────▶│  Server  │────▶│  Packet  │────▶│ Handler │
│  (DNS/  │     │  (UDP/  │     │  Decode  │     │ (User   │
│   DoH)   │     │   HTTP)  │     │          │     │ Defined)│
└──────────┘     └──────────┘     └──────────┘     └─────────┘
     ▲                                  │                │
     │                                  │                │
     │                                  ▼                │
     │                            ┌──────────┐          │
     │                            │  Packet  │          │
     │                            │  Encode  │          │
     │                            └──────────┘          │
     │                                  │                │
     │                                  ▼                │
     └──────────────────────────────┌──────────┐         │
                                    │  Server  │◀────────┘
                                    │  Write   │
                                    └──────────┘
```

## 核心组件

### 0. Engine 层 (pipeline/)

- `AuthoritativeEngine`：只服务权威 snapshot，区外返回 REFUSED，不提供递归；
- `ForwardingEngine`：缓存、过滤和 upstream 转发，不加载权威 zone；
- `LocalIndex`：反向标签 trie + owner/type RRSet 索引，支持原子 snapshot 替换。

生产环境应分别部署两个 engine；`pipeline.New` 的 hybrid 行为仅用于兼容。

### 1. Packet 层 (packet/)

**职责**: DNS 协议的编解码

- `DNSPacket`: 主数据结构，包含 Header, Questions, Answers, Authorities, Additionals
- `DNSHeader`: 12 字节的 DNS 头部
- `DNSQuestion`: 查询问题部分
- `DNSResource`: 资源记录接口，支持多种记录类型

**关键方法**:
- `FromBytes([]byte) (*DNSPacket, error)`: 解码
- `Bytes() []byte`: 编码
- `AddQuestion*()`: 添加查询问题
- `AddAnswer()`, `AddAuthority()`, `AddAdditional()`: 添加资源记录

### 2. Client 层 (client/)

**职责**: DNS 查询客户端

- `UDPClient`: 基于 UDP 的传统 DNS 查询
- `HTTPClient`: 基于 HTTPS 的 DNS over HTTPS GET/POST 查询

**接口**:
```go
type Query interface {
    Query(req *packet.DNSPacket) (res *packet.DNSPacket, err error)
}
```

### 3. Server 层 (server/)

**职责**: DNS 服务器

- `ListenUDP()`: UDP 服务器
- `ListenHTTP()`: HTTP/DoH 服务器
- `PackConn`: 连接封装，提供 `WriteResponse()` 方法

**接口**:
```go
type DNSHandler interface {
    HandleQuery(conn *PackConn)
}
```

## 设计模式

### 1. 策略模式 (Strategy Pattern)

客户端支持不同的查询策略 (UDP, DoH)，通过不同的客户端实现:

```go
client.NewUDPClient("8.8.8.8:53")
client.NewHTTPClientPost("https://cloudflare-dns.com/dns-query")
```

### 2. 命令模式 (Command Pattern)

服务器通过 `DNSHandler` 接口将查询处理委托给用户自定义的实现:

```go
type DNSHandler interface {
    HandleQuery(conn *PackConn)
}
```

### 3. 工厂模式 (Factory Pattern)

`NewPacket()`, `NewHeader()` 等工厂函数创建标准对象

### 4. 多态 (Polymorphism)

`DNSResource` 接口支持多种记录类型:

```go
type DNSResource interface {
    Bytes() []byte
    GetType() DNSType
    Encode() []byte
    Decode(reader *bytes.Reader, length uint16) error
}
```

## 依赖关系

```
┌─────────────┐
│  main.go    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  examples/  │
└──────┬──────┘
       │
       ├──────────────┬──────────────┐
       ▼              ▼              ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  client/    │ │  server/    │ │  packet/    │
└─────────────┘ └─────────────┘ └──────┬──────┘
                                       │
                                       ▼
                                 (核心依赖)
```

## 线程安全性

当前实现的线程安全性分析:

| 组件 | 线程安全 | 说明 |
|------|---------|------|
| `DNSPacket` | ❌ | 无内部锁，需外部同步 |
| `UDPClient` | ✅ | 复用连接并串行保护请求/响应匹配 |
| `HTTPClient` | ✅ | 复用线程安全的 http.Client 与连接池 |
| `ListenUDP` | ✅ | 单 goroutine 接收，每请求 goroutine 处理 |
| `ListenHTTP` | ✅ | http.Server 并发处理 |

## 性能考虑

1. **内存分配**: 每次编解码都创建新的 buffer，可能产生 GC 压力
2. **连接管理**: UDP/TCP 客户端为正确性串行化共享连接，高吞吐场景可增加连接池
3. **并发处理**: UDP 服务端当前为每请求创建 goroutine，后续应增加有界并发
