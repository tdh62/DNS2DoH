# DoH TO DNS

## 基于 GO 语言实现的 DNS 转发器

本地监听 UDP 53 端口的 DNS 请求，并将其转发至 DoH 并返回解析

## Usage

直接运行即可将请求转发至 DNSPoD 公共解析的 DoH 服务（https://1.12.12.12/dns-query)，
也可手动指定要连接的 DoH 服务端

DNS2DoH doHEndpoint

example:
```shell
./DNS2DoH https://1.12.12.12/dns-query
```