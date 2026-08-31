# DNS 引擎与运行模式

`dns-go` 将权威解析和递归转发作为两个独立引擎。生产部署应选择明确模式，
`hybrid` 仅用于兼容旧配置和本地开发。

## AuthoritativeEngine

权威引擎只读取 `LocalSource`，区外查询返回 `REFUSED`，`RA=0`，不会访问缓存、
过滤器或上游。

```go
index, err := pipeline.NewLocalIndexFromZones([]pipeline.ZoneData{
    {Origin: "example.com", Records: records},
})
if err != nil {
    return err
}
engine, err := pipeline.NewAuthoritativeEngine(index)
```

`NewAuthoritativeEngine` 会校验每个 `LocalIndex` zone 恰好有一个 apex SOA，并且
至少有一个 apex NS；缺少必要权威数据时拒绝启动。

`LocalIndex.ReplaceZones` 会先完整编译新的不可变 snapshot，再原子切换。编译失败
时继续使用 last-known-good snapshot。查询支持：

- 最长 zone 匹配；
- RRSet 和 ANY；
- NODATA / NXDOMAIN，并在配置 SOA 时放入 Authority；
- 区内 CNAME 链；
- wildcard 与 closest-encloser；
- delegation referral 和 in-bailiwick A/AAAA glue；
- delegation owner 上的 DS 父区查询语义。

## ForwardingEngine

转发引擎由递归缓存、过滤策略和 upstream pool 组成，不加载权威 zone。

```go
engine := pipeline.NewForwardingEngine(cache, filter, upstreamPool)
```

只有 upstream 响应会写入递归缓存。本地权威结果和过滤合成结果不会进入缓存。

## CLI 模式

```yaml
mode: authoritative # authoritative | forwarding | hybrid
```

- `authoritative`：要求至少一个 domain，并拒绝 cache、proxy 和 filter 配置；
- `forwarding`：拒绝 authoritative domains；
- `hybrid`：兼容模式，顺序为 authoritative → cache → filter → upstream。

控制面或数据库集成应生成 `[]pipeline.ZoneData`，不需要生成 YAML，也不应在 DNS
查询热路径访问数据库。`ZoneData` 中的 owner 和域名型 RDATA 建议使用规范化 FQDN；
FQDN 可以省略末尾的点，单标签 RDATA 会按当前 zone 作为相对名称处理。
