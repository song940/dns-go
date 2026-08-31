# 使用指南

## 快速开始

### 安装

```bash
go get github.com/lsongdev/dns-go
```

### 运行示例

```bash
# 运行客户端
go run main.go client

# 运行服务器
go run main.go server
```

---

## 客户端使用

### UDP 客户端

最基本的 DNS 查询方式:

```go
package main

import (
    "log"
    "github.com/lsongdev/dns-go/client"
    "github.com/lsongdev/dns-go/packet"
)

func main() {
    // 创建 UDP 客户端
    c := client.NewUDPClient("8.8.8.8:53")
    
    // 创建查询数据包
    query := packet.NewPacket()
    query.AddQuestionA("google.com")
    
    // 发送查询
    res, err := c.Query(query)
    if err != nil {
        log.Fatal(err)
    }
    
    // 处理响应
    for _, answer := range res.Answers {
        if a, ok := answer.(*packet.DNSResourceRecordA); ok {
            log.Printf("IP: %s", a.Address)
        }
    }
}
```

### DoH 客户端

使用 DNS over HTTPS 进行加密查询:

```go
package main

import (
    "log"
    "github.com/lsongdev/dns-go/client"
    "github.com/lsongdev/dns-go/packet"
)

func main() {
    // 创建 DoH 客户端
    c := client.NewHTTPClientPost("https://cloudflare-dns.com/dns-query")
    
    // 创建查询数据包
    query := packet.NewPacket()
    query.AddQuestionA("google.com")
    
    // 发送查询
    res, err := c.Query(query)
    if err != nil {
        log.Fatal(err)
    }
    
    // 处理响应
    for _, answer := range res.Answers {
        if a, ok := answer.(*packet.DNSResourceRecordA); ok {
            log.Printf("IP: %s", a.Address)
        }
    }
}
```

### 多种记录类型查询

```go
package main

import (
    "log"
    "github.com/lsongdev/dns-go/client"
    "github.com/lsongdev/dns-go/packet"
)

func main() {
    c := client.NewUDPClient("8.8.8.8:53")
    
    // A 记录
    query := packet.NewPacket()
    query.AddQuestionA("google.com")
    res, _ := c.Query(query)
    
    // AAAA 记录
    query = packet.NewPacket()
    query.AddQuestionAAAA("google.com")
    res, _ = c.Query(query)
    
    // CNAME 记录
    query = packet.NewPacket()
    query.AddQuestionCNAME("www.google.com")
    res, _ = c.Query(query)
    
    // MX 记录
    query = packet.NewPacket()
    query.AddQuestionMX("google.com")
    res, _ = c.Query(query)
    
    // TXT 记录
    query = packet.NewPacket()
    query.AddQuestionTXT("google.com")
    res, _ = c.Query(query)
    
    // NS 记录
    query = packet.NewPacket()
    query.AddQuestionNS("google.com")
    res, _ = c.Query(query)
    
    // SOA 记录
    query = packet.NewPacket()
    query.AddQuestionSOA("google.com")
    res, _ = c.Query(query)
    
    // SRV 记录
    query = packet.NewPacket()
    query.AddQuestionSRV("_sip._tls.google.com")
    res, _ = c.Query(query)
}
```

### 处理响应

```go
package main

import (
    "log"
    "github.com/lsongdev/dns-go/client"
    "github.com/lsongdev/dns-go/packet"
)

func printRecord(record packet.DNSResource) {
    switch record.GetType() {
    case packet.DNSTypeA:
        a := record.(*packet.DNSResourceRecordA)
        log.Printf("A: %s -> %s", a.Name, a.Address)
    case packet.DNSTypeAAAA:
        aaaa := record.(*packet.DNSResourceRecordAAAA)
        log.Printf("AAAA: %s -> %s", aaaa.Name, aaaa.Address)
    case packet.DNSTypeCNAME:
        cname := record.(*packet.DNSResourceRecordCNAME)
        log.Printf("CNAME: %s -> %s", cname.Name, cname.Domain)
    case packet.DNSTypeTXT:
        txt := record.(*packet.DNSResourceRecordTXT)
        log.Printf("TXT: %s -> %s", txt.Name, txt.Content)
    case packet.DNSTypeNS:
        ns := record.(*packet.DNSResourceRecordNS)
        log.Printf("NS: %s -> %s", ns.Name, ns.NameServer)
    }
}

func main() {
    c := client.NewUDPClient("8.8.8.8:53")
    query := packet.NewPacket()
    query.AddQuestionA("google.com")
    
    res, err := c.Query(query)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Println("=== Questions ===")
    for _, q := range res.Questions {
        log.Printf("%s %s %s", q.Name, q.Type, q.Class)
    }
    
    log.Println("=== Answers ===")
    for _, record := range res.Answers {
        printRecord(record)
    }
    
    log.Println("=== Authorities ===")
    for _, record := range res.Authorities {
        printRecord(record)
    }
    
    log.Println("=== Additionals ===")
    for _, record := range res.Additionals {
        printRecord(record)
    }
}
```

---

## 服务器使用

### 基本服务器

```go
package main

import (
    "log"
    "github.com/lsongdev/dns-go/packet"
    "github.com/lsongdev/dns-go/server"
)

type MyHandler struct{}

func (h *MyHandler) HandleQuery(conn *server.PackConn) {
    log.Printf("收到查询：%s", conn.Request.Questions[0].Name)
    
    // 创建响应
    res := packet.NewPacketFromRequest(conn.Request)
    
    // 添加 A 记录响应
    res.AddAnswer(&packet.DNSResourceRecordA{
        DNSResourceRecord: packet.DNSResourceRecord{
            Type:  packet.DNSTypeA,
            Class: packet.DNSClassIN,
            Name:  conn.Request.Questions[0].Name,
            TTL:   300,
        },
        Address: "127.0.0.1",
    })
    
    // 发送响应
    conn.WriteResponse(res)
}

func main() {
    h := &MyHandler{}
    
    // 启动 UDP 服务器 (需要 root 权限)
    go server.ListenUDP("0.0.0.0:53", h)
    
    // 启动 HTTP/DoH 服务器
    server.ListenHTTP("0.0.0.0:8080", h)
}
```

### 智能 DNS 服务器

根据查询域名返回不同响应:

```go
package main

import (
    "log"
    "strings"
    "github.com/lsongdev/dns-go/packet"
    "github.com/lsongdev/dns-go/server"
)

type SmartHandler struct{}

func (h *SmartHandler) HandleQuery(conn *server.PackConn) {
    query := conn.Request.Questions[0]
    log.Printf("查询：%s (类型：%d)", query.Name, query.Type)
    
    res := packet.NewPacketFromRequest(conn.Request)
    
    // 根据域名返回不同的 IP
    if strings.HasSuffix(query.Name, "example.com") {
        res.AddAnswer(&packet.DNSResourceRecordA{
            DNSResourceRecord: packet.DNSResourceRecord{
                Type:  packet.DNSTypeA,
                Class: packet.DNSClassIN,
                Name:  query.Name,
                TTL:   60,
            },
            Address: "192.168.1.100",
        })
    } else if strings.HasSuffix(query.Name, "test.com") {
        res.AddAnswer(&packet.DNSResourceRecordA{
            DNSResourceRecord: packet.DNSResourceRecord{
                Type:  packet.DNSTypeA,
                Class: packet.DNSClassIN,
                Name:  query.Name,
                TTL:   60,
            },
            Address: "192.168.1.200",
        })
    } else {
        // 其他域名返回 NXDOMAIN
        res.Header.RCode = 3  // NXDOMAIN
    }
    
    conn.WriteResponse(res)
}

func main() {
    h := &SmartHandler{}
    server.ListenUDP("0.0.0.0:5353", h)
}
```

### DNS 转发器

将查询转发到上游 DNS 服务器:

```go
package main

import (
    "log"
    "github.com/lsongdev/dns-go/client"
    "github.com/lsongdev/dns-go/packet"
    "github.com/lsongdev/dns-go/server"
)

type RelayHandler struct {
    upstream client.UDPClient
}

func (h *RelayHandler) HandleQuery(conn *server.PackConn) {
    // 转发查询到上游
    res, err := h.upstream.Query(conn.Request)
    if err != nil {
        log.Printf("上游查询失败：%v", err)
        return
    }
    
    // 返回上游响应
    conn.WriteResponse(res)
}

func main() {
    h := &RelayHandler{
        upstream: *client.NewUDPClient("8.8.8.8:53"),
    }
    
    // 本地 DNS 代理
    server.ListenUDP("0.0.0.0:5353", h)
}
```

---

## 高级用法

### 自定义资源记录

实现自定义资源记录类型:

```go
type DNSResourceRecordCustom struct {
    packet.DNSResourceRecord
    CustomData string
}

func (r *DNSResourceRecordCustom) Decode(reader *bytes.Reader, length uint16) error {
    // 实现解码逻辑
    data := make([]byte, length)
    if _, err := io.ReadFull(reader, data); err != nil {
        return err
    }
    r.CustomData = string(data)
    return nil
}

func (r *DNSResourceRecordCustom) Encode() []byte {
    return []byte(r.CustomData)
}

func (r *DNSResourceRecordCustom) Bytes() []byte {
    return r.WrapData(r.Encode())
}
```

### 批量查询

```go
func batchQuery(client *client.UDPClient, domains []string) ([]*packet.DNSPacket, error) {
    results := make([]*packet.DNSPacket, len(domains))
    
    for i, domain := range domains {
        query := packet.NewPacket()
        query.AddQuestionA(domain)
        
        res, err := client.Query(query)
        if err != nil {
            return nil, err
        }
        results[i] = res
    }
    
    return results, nil
}
```

### 并发查询

```go
func concurrentQuery(client *client.UDPClient, domains []string) ([]*packet.DNSPacket, []error) {
    results := make([]*packet.DNSPacket, len(domains))
    errors := make([]error, len(domains))
    
    var wg sync.WaitGroup
    for i, domain := range domains {
        wg.Add(1)
        go func(idx int, d string) {
            defer wg.Done()
            query := packet.NewPacket()
            query.AddQuestionA(d)
            results[idx], errors[idx] = client.Query(query)
        }(i, domain)
    }
    
    wg.Wait()
    return results, errors
}
```

---

## 测试

运行测试:

```bash
go test ./packet/...
```

---

## 常见问题

### Q: 为什么 UDP 服务器需要 root 权限？

A: 在 Unix/Linux 系统上，绑定 1024 以下的端口 (如 DNS 的 53 端口) 需要 root 权限。可以使用非特权端口 (如 5353) 进行测试:

```go
server.ListenUDP("0.0.0.0:5353", h)
```

### Q: DoH 和传统 DNS 有什么区别？

A: DoH (DNS over HTTPS) 使用 HTTPS 协议传输 DNS 查询，具有以下优势:
- 加密传输，防止窃听
- 使用 443 端口，不易被防火墙拦截
- 可以利用 HTTP/2 的性能优势

### Q: 如何调试 DNS 数据包？

A: 可以打印原始字节或解析后的结构:

```go
query := packet.NewPacket()
query.AddQuestionA("google.com")
log.Printf("原始数据：%x", query.Bytes())
log.Printf("解析结果：%+v", query)
```
