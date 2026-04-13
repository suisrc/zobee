# 说明

## 目标

本目录提供一个 eBPF 监控方案，用于捕获 HTTP 和 HTTPS 流量：
- 支持 IPv4/IPv6
- 支持 TCP HTTP、TLS over TCP，以及 QUIC/HTTPS over UDP
- 输出：源 IP、源端口、目标 IP、目标端口、流量方向、域名（HTTPS 使用 SNI）、`uid`、`cr_id`、`cr_pid`
- HTTP 请求/响应会尽量保留 headers 和 body，`-max-body-size` 同时作用于 request body 和 response body

## 编译

```sh
cd app/ebpf
make all
```

## 使用

首先确保内核和用户空间依赖安装完毕：

```sh
apt update
apt install -y clang llvm libbpf-dev libelf-dev libpcap-dev libelf1 pkg-config libssl-dev zlib1g-dev git make bpftool iproute2
apt install -y linux-headers-$(uname -r)
```

运行环境要求内核 5.8+。
原因是 `cr_id` / `cr_pid` 通过 CO-RE 从 `task_struct -> thread_pid -> pid->numbers[...]` 读取，需要内核提供可用于重定位的 BTF 字段信息；低于 5.8 的内核在这条读取链路上不够稳定，容器内 PID 和 namespace 标识可能无法可靠获取。
其中 `cr_id` 表示 PID namespace 的 inode 号，`cr_pid` 表示该进程在对应 namespace 下看到的 pid。

编译完成后，直接运行数据收集程序：

```sh
sudo ./zwbee -interface eth0
```

程序会创建原始 AF_PACKET 套接字，并把 `capture_prog` 挂到 packet socket 上。
`-interface` 和 `-pcap-rules` 都会先由 userspace 写入 BPF map，再由 `capture_prog` 在内核里读取并执行；其他过滤参数仍保持在 userspace 过滤。
默认 `-pcap-rules` 为空，此时只使用内置的 HTTP/HTTPS/QUIC 粗筛；显式传入规则后，会先在内核里执行对应的 classic BPF 指令，减少进入 userspace 的流量。

常用参数：
- `-interface eth0` 监听接口
- `-pcap-rules 'tcp port 80 or tcp port 443'` 可选的内核侧 pcap 过滤规则，默认空，编译后最多 256 条指令
- `-direction ingress|egress` 只看入站或出站流量，默认双向
- `-pid 123` 按进程 pid 过滤
- `-cpid 123` 按容器内 pid 过滤
- `-crid 123` 按容器 id 过滤
- `-comm app` 按进程名称过滤
- `-src` / `-dst` 支持 CIDR 和 `!` 排除规则
- `-sport` 仅对 ingress 生效
- `-dport` 仅对 egress 生效
- `-max-body-size` 控制 request/response body 最大记录长度，`<0` 不记录，`0` 不限制，`>0` 截断

示例：

```sh
sudo ./zwbee -interface eth0 -direction ingress -pid 123 -comm app -max-body-size 4096
```

```sh
sudo ./zwbee -pcap-rules 'tcp port 80 or tcp port 443'
```

## 清理

```sh
make clean
```

## 注意

- 由于 HTTPS 流量本身被加密，程序仅解析 SNI/ALPN 等明文握手信息，不进行解密。
- PID/进程名关联优先使用 BPF 侧的 socket 归属信息，缺失时会回退到 `/proc` 扫描结果做补齐。
- `flow_owner_map` / `tracked_flow_map` 使用 LRU map，userspace 的 flow 缓冲、socket cache 和 inode owner 索引也都有上限，避免高流量场景下无限增长。
