# DNS-Go 项目文档

## 目录

- [架构概述](./architecture.md)
- [请求处理流程](./request-flow.md)
- [DNS 引擎与运行模式](./engines.md)
- [测试指南](./testing.md)
- [API 参考](./api-reference.md)
- [使用指南](./usage-guide.md)
- [代码分析与改进建议](./code-analysis.md)

## 项目简介

dns-go 是一个用 Go 语言实现的 DNS 客户端和服务器库，支持 DNS 协议的编码/解码、UDP 查询、DoH (DNS over HTTPS) 等功能。

### 核心功能

- **DNS 数据包编解码**: 完整的 DNS 协议实现 (RFC 1034/1035)
- **UDP 客户端/服务器**: 传统 DNS 查询方式
- **DoH 客户端/服务器**: DNS over HTTPS 支持
- **多种记录类型**: A、AAAA、CNAME、NS、SOA、MX、TXT、SRV、CAA、DNSSEC、TLSA、SVCB/HTTPS、EDNS 等

### 项目结构

```
dns-go/
├── client/          # DNS 客户端实现
│   ├── udp.go      # UDP 客户端
│   └── doh.go      # DoH 客户端
├── server/          # DNS 服务器实现
│   ├── udp.go      # UDP 服务器
│   ├── http.go     # HTTP/DoH 服务器
│   └── tcp.go      # TCP 服务器
├── packet/          # DNS 数据包编解码
│   ├── packet.go           # 主数据包结构
│   ├── packet_header.go    # DNS 头部
│   ├── packet_question.go  # DNS 问题部分
│   ├── packet_resource.go  # 资源记录定义
│   ├── packet_resource_a.go
│   ├── packet_resource_aaaa.go
│   ├── packet_resource_cname.go
│   └── ...
├── examples/        # 示例代码
│   ├── client.go   # 客户端示例
│   ├── server.go   # 服务器示例
│   └── relay.go    # 中继示例
└── main.go         # 命令行入口
```

### 技术栈

- **语言**: Go 1.19+
- **协议**: DNS (RFC 1034/1035), DoH (RFC 8484)
- **依赖**: 无第三方依赖 (标准库实现)
