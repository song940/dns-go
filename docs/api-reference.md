# API 参考

## 包索引

- [packet](#packet-package) - DNS 数据包编解码
- [client](#client-package) - DNS 客户端
- [server](#server-package) - DNS 服务器

---

## `packet` Package

### 类型

#### `DNSPacket`

DNS 数据包主结构，表示完整的 DNS 消息。

```go
type DNSPacket struct {
    Header      *DNSHeader
    Questions   []*DNSQuestion
    Answers     []DNSResource
    Authorities []DNSResource
    Additionals []DNSResource
}
```

**字段说明**:
- `Header`: DNS 消息头部 (12 字节)
- `Questions`: 查询问题列表
- `Answers`: 答案资源记录列表
- `Authorities`: 授权资源记录列表
- `Additionals`: 附加资源记录列表

**方法**:

| 方法 | 签名 | 说明 |
|------|------|------|
| `NewPacket` | `func NewPacket() *DNSPacket` | 创建新的 DNS 数据包 |
| `NewPacketFromRequest` | `func NewPacketFromRequest(request *DNSPacket) *DNSPacket` | 从请求创建响应数据包 |
| `FromBytes` | `func FromBytes(data []byte) (*DNSPacket, error)` | 从字节切片解码 DNS 数据包 |
| `Bytes` | `func (packet *DNSPacket) Bytes() []byte` | 编码为字节切片 |
| `AddQuestion` | `func (p *DNSPacket) AddQuestion(question *DNSQuestion)` | 添加问题 |
| `AddAnswer` | `func (p *DNSPacket) AddAnswer(answer DNSResource)` | 添加答案 |
| `AddAuthority` | `func (p *DNSPacket) AddAuthority(authority DNSResource)` | 添加授权记录 |
| `AddAdditional` | `func (p *DNSPacket) AddAdditional(additional DNSResource)` | 添加附加记录 |
| `AddQuestionA` | `func (p *DNSPacket) AddQuestionA(domain string)` | 添加 A 记录查询 |
| `AddQuestionAAAA` | `func (p *DNSPacket) AddQuestionAAAA(domain string)` | 添加 AAAA 记录查询 |
| `AddQuestionCNAME` | `func (p *DNSPacket) AddQuestionCNAME(domain string)` | 添加 CNAME 记录查询 |
| `AddQuestionMX` | `func (p *DNSPacket) AddQuestionMX(domain string)` | 添加 MX 记录查询 |
| `AddQuestionNS` | `func (p *DNSPacket) AddQuestionNS(domain string)` | 添加 NS 记录查询 |
| `AddQuestionTXT` | `func (p *DNSPacket) AddQuestionTXT(domain string)` | 添加 TXT 记录查询 |
| `AddQuestionSOA` | `func (p *DNSPacket) AddQuestionSOA(domain string)` | 添加 SOA 记录查询 |
| `AddQuestionPTR` | `func (p *DNSPacket) AddQuestionPTR(domain string)` | 添加 PTR 记录查询 |
| `AddQuestionSRV` | `func (p *DNSPacket) AddQuestionSRV(domain string)` | 添加 SRV 记录查询 |

**示例**:

```go
query := packet.NewPacket()
query.AddQuestionA("google.com")
```

---

#### `DNSHeader`

DNS 消息头部结构。

```go
type DNSHeader struct {
    ID      uint16  // 事务 ID
    QR      uint8   // 0=查询，1=响应
    OpCode  uint8   // 操作码
    AA      uint8   // 授权回答标志
    TC      uint8   // 截断标志
    RD      uint8   // 期望递归标志
    RA      uint8   // 可用递归标志
    Z       uint8   // 保留位
    RCode   uint8   // 响应码
    QDCount uint16  // 问题数量
    ANCount uint16  // 答案数量
    NSCount uint16  // 授权记录数量
    ARCount uint16  // 附加记录数量
}
```

**常量**:

```go
const (
    DNSQuery    uint8 = 0  // 查询
    DNSResponse uint8 = 1  // 响应
)
```

---

#### `DNSQuestion`

DNS 查询问题结构。

```go
type DNSQuestion struct {
    Name  string    // 域名
    Type  DNSType   // 查询类型
    Class DNSClass  // 查询类
}
```

---

#### `DNSResource` (接口)

资源记录接口。

```go
type DNSResource interface {
    Bytes() []byte
    GetType() DNSType
    Encode() []byte
    Decode(reader *bytes.Reader, length uint16) error
}
```

---

#### `DNSResourceRecord`

资源记录基础结构。

```go
type DNSResourceRecord struct {
    Name  string
    Type  DNSType
    Class DNSClass
    TTL   uint32
}
```

---

#### 资源记录类型

| 类型 | 结构体 | 说明 |
|------|--------|------|
| A | `DNSResourceRecordA` | IPv4 地址记录 |
| AAAA | `DNSResourceRecordAAAA` | IPv6 地址记录 |
| CNAME | `DNSResourceRecordCNAME` | 规范名称记录 |
| NS | `DNSResourceRecordNS` | 名称服务器记录 |
| SOA | `DNSResourceRecordSOA` | 授权起始记录 |
| TXT | `DNSResourceRecordTXT` | 文本记录 |
| MX | `DNSResourceRecordMX` | 邮件交换记录 |
| PTR | `DNSResourceRecordPTR` | 反向指针记录 |
| SRV | `DNSResourceRecordSRV` | 服务定位记录 |
| EDNS | `DNSResourceRecordEDNS` | 扩展 DNS 记录 |
| CAA | `DNSResourceRecordCAA` | CA 授权记录 |
| DS | `DNSResourceRecordDS` | DNSSEC 委派签名者记录 |
| DNSKEY | `DNSResourceRecordDNSKEY` | DNSSEC 公钥记录 |
| RRSIG | `DNSResourceRecordRRSIG` | DNSSEC 签名记录 |
| NSEC | `DNSResourceRecordNSEC` | DNSSEC 不存在性证明记录 |
| TLSA | `DNSResourceRecordTLSA` | TLS 证书关联记录 |
| SVCB / HTTPS | `DNSResourceRecordSVCB` | 服务绑定记录；通过 `Type` 区分两种线类型 |

**示例 - A 记录**:

```go
type DNSResourceRecordA struct {
    DNSResourceRecord
    Address string  // IPv4 地址
}
```

---

#### `DNSType` (类型)

DNS 记录类型。

```go
type DNSType uint16
```

**常量**:

```go
const (
    DNSTypeA     DNSType = 0x0001  // A 记录
    DNSTypeNS    DNSType = 0x0002  // NS 记录
    DNSTypeCNAME DNSType = 0x0005  // CNAME 记录
    DNSTypeSOA   DNSType = 0x0006  // SOA 记录
    DNSTypePTR   DNSType = 0x000C  // PTR 记录
    DNSTypeMX    DNSType = 0x000F  // MX 记录
    DNSTypeTXT   DNSType = 0x0010  // TXT 记录
    DNSTypeAAAA  DNSType = 0x001C  // AAAA 记录
    DNSTypeSRV   DNSType = 0x0021  // SRV 记录
    DNSTypeEDNS  DNSType = 0x0029  // EDNS
    DNSTypeDS     DNSType = 0x002B  // DS
    DNSTypeRRSIG  DNSType = 0x002E  // RRSIG
    DNSTypeNSEC   DNSType = 0x002F  // NSEC
    DNSTypeDNSKEY DNSType = 0x0030  // DNSKEY
    DNSTypeTLSA   DNSType = 0x0034  // TLSA
    DNSTypeSVCB   DNSType = 0x0040  // SVCB
    DNSTypeHTTPS  DNSType = 0x0041  // HTTPS
    DNSTypeAny   DNSType = 0x00FF  // 任意类型
    DNSTypeCAA    DNSType = 0x0101  // CAA
)
```

---

#### `DNSClass` (类型)

DNS 类。

```go
type DNSClass uint16
```

**常量**:

```go
const (
    DNSClassIN  DNSClass = 0x01  // Internet
    DNSClassCS  DNSClass = 0x02  // CSNET (已废弃)
    DNSClassCH  DNSClass = 0x03  // CHAOS
    DNSClassHS  DNSClass = 0x04  // Hesiod
    DNSClassAny DNSClass = 0xFF  // 任意类
)
```

---

## `client` Package

### 类型

#### `UDPClient`

基于 UDP 的 DNS 客户端。

```go
type UDPClient struct {
    Server string  // DNS 服务器地址 (格式："host:port")
}
```

**方法**:

| 方法 | 签名 | 说明 |
|------|------|------|
| `NewUDPClient` | `func NewUDPClient(server string) *UDPClient` | 创建 UDP 客户端 |
| `Query` | `func (client *UDPClient) Query(req *packet.DNSPacket) (*packet.DNSPacket, error)` | 发送 DNS 查询 |

**示例**:

```go
c := client.NewUDPClient("8.8.8.8:53")
query := packet.NewPacket()
query.AddQuestionA("google.com")
res, err := c.Query(query)
if err != nil {
    log.Fatal(err)
}
```

---

#### `HTTPClient`

基于 HTTPS 的 DNS over HTTPS 客户端。

```go
type HTTPClient struct {
    Server  string        // DoH 服务器 URL
    Timeout time.Duration // 请求超时
    UsePost bool          // 是否使用 POST；否则使用 GET
}
```

**方法**:

| 方法 | 签名 | 说明 |
|------|------|------|
| `NewHTTPClient` | `func NewHTTPClient(server string) *HTTPClient` | 创建使用 GET 的 DoH 客户端 |
| `NewHTTPClientPost` | `func NewHTTPClientPost(server string) *HTTPClient` | 创建使用 POST 的 DoH 客户端 |
| `Query` | `func (client *HTTPClient) Query(query *packet.DNSPacket) (*packet.DNSPacket, error)` | 发送 DNS 查询 |
| `Close` | `func (client *HTTPClient) Close() error` | 关闭空闲 HTTP 连接 |

**示例**:

```go
c := client.NewHTTPClientPost("https://cloudflare-dns.com/dns-query")
query := packet.NewPacket()
query.AddQuestionA("google.com")
res, err := c.Query(query)
```

---

## `server` Package

### 类型

#### `PackConn`

封装的 DNS 连接。

```go
type PackConn struct {
    io.Writer
    RemoteAddr string
    Request    *packet.DNSPacket
}
```

**方法**:

| 方法 | 签名 | 说明 |
|------|------|------|
| `WriteResponse` | `func (p *PackConn) WriteResponse(res *packet.DNSPacket) error` | 写入响应数据包 |

---

#### `DNSHandler` (接口)

DNS 查询处理器接口。

```go
type DNSHandler interface {
    HandleQuery(conn *PackConn)
}
```

**示例**:

```go
type MyHandler struct{}

func (h *MyHandler) HandleQuery(conn *server.PackConn) {
    log.Println("query", conn.Request.Questions[0].Name)
    res := packet.NewPacketFromRequest(conn.Request)
    res.AddAnswer(&packet.DNSResourceRecordA{
        DNSResourceRecord: packet.DNSResourceRecord{
            Type:  packet.DNSTypeA,
            Class: packet.DNSClassIN,
            Name:  conn.Request.Questions[0].Name,
            TTL:   100,
        },
        Address: "127.0.0.1",
    })
    conn.WriteResponse(res)
}
```

---

### 函数

#### `ListenUDP`

启动 UDP DNS 服务器。

```go
func ListenUDP(addr string, handler DNSHandler) error
```

**参数**:
- `addr`: 监听地址 (格式："host:port")
- `handler`: DNS 查询处理器

**示例**:

```go
h := &MyHandler{}
err := server.ListenUDP("0.0.0.0:53", h)
if err != nil {
    log.Fatal(err)
}
```

---

#### `ListenHTTP`

启动 HTTP/DoH DNS 服务器，支持 RFC 8484 GET 和 POST。若需要挂载到已有
`http.Server` 或路由器，可使用 `NewHTTPHandler`。

```go
func ListenHTTP(addr string, handler DNSHandler) error
func NewHTTPHandler(handler DNSHandler) http.Handler
```

**参数**:
- `addr`: 监听地址 (格式："host:port")
- `handler`: DNS 查询处理器

**示例**:

```go
h := &MyHandler{}
err := server.ListenHTTP("0.0.0.0:8080", h)
if err != nil {
    log.Fatal(err)
}
```

---

## 错误处理

所有可能失败的方法都返回 `error`，调用者应检查错误:

```go
res, err := c.Query(query)
if err != nil {
    log.Fatal(err)
}
```

常见的错误情况:
- 网络连接失败
- 数据包解码失败
- 响应 ID 或 Question 与请求不匹配
- 请求超时

`NXDOMAIN`、`REFUSED`、`SERVFAIL` 等 RCode 是有效 DNS 响应，`Query` 会将其
返回给调用者，由调用者检查 `res.Header.RCode`，不会将其转换为网络错误。
