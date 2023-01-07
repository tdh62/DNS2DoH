# 基于 GO 语言实现的 DNS 转发器

## 功能

```
[o] 监听本地 TCP 请求
[o] 监听本地 UDP 请求
[o] 转发请求和响应 - DoH
[o] 转发请求和响应 - DoT
[o] 处理 TCP 拆包
[o] 命令行自定义参数
[ ] 缓存请求、解析
[ ] 自定义解析返回
[ ] 处理 TCP 粘包
```

## 安全

本程序直接对请求进行转发，未针对安全问题进行任何优化和处理，请仅在受信任的环境中使用。

## 参数

如果希望调整默认监听设置，或者希望数据转发到 DoT 而不是 DoH，则需要进行参数设置：
```
    listenAddress = "" // 监听地址
    listenPort    = 53 // 监听端口
    listenUDP     = true // 在 UDP 上进行监听
    listenTCP     = true // 在 TCP 上进行监听
    forwardTo     = "DoH" // 转发目标，DoH 或 DoT
    DoTEndPoint   = "dns.pub" // DoT 目标地址或 IP
    ServerName    = "dns.pub" // DoT 域名，若留空则忽略 DoT 的 TLS 验证
```

## 用法

```
.\DNS2DoH.exe
    -e string
        Set Target of DoH or DoT server, if use DoH, Please input the FULL address, including 'https://' and path such as '/dns-query'. (default "https://1.12.12.12/dns-query")
    -ip string
        Define the listen address (default "127.0.0.1")
    -notcp
        Disable listen on TCP
    -noudp
        Disable listen on UDP
    -port int
        Set listen port on TCP. (default 53)
    -sni string
        For TLS handshake, If empty the vitrify of TLS will be disabled.
    -to string
        Only 'DoH' or 'DoT' can be use to define wherever the data froward to. (default "DoH")
    -udpport int
        Set listen port on UDP. (default 53)
```

