// eBPF 探针：只识别 HTTP/HTTPS 流量并放行到 userspace。
// 这个文件的职责非常窄：
// 1. 在内核里尽量早地筛掉无关流量；
// 2. 在抓到相关 socket 时，把“这个 socket 属于谁”记录下来；
// 3. 把 userspace 需要的最小结构写进 map，后面由 userspace 负责更重的协议解析。
// 注意：这里不做 HTTP 解析、不重组 payload、不输出 JSON，所有复杂逻辑都留给 userspace。

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define PCAP_RULES_MAX_INSNS 256
#define MAX_VLAN_DEPTH 2
#define IPV6_MAX_EXT_HEADERS 3
#define MAX_L7_SCAN_OFFSETS 24
#define MAX_HTTP_SCAN_OFFSETS 12
#define HTTP_MAGIC4(a, b, c, d) \
    (((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | (__u32)(d))

struct ns_common {
    // namespace 公共头部，里面的 inum 是 namespace 的 inode 号。
    __u32 inum;
} __attribute__((preserve_access_index));

struct pid_namespace {
    // PID namespace 对象，里面嵌着 ns_common。
    struct ns_common ns;
} __attribute__((preserve_access_index));

struct upid {
    // upid 表示“某个 PID 在某一层 namespace 里的编号”。
    int nr;
    struct pid_namespace *ns;
} __attribute__((preserve_access_index));

struct pid {
    // level 表示当前进程在 PID namespace 栈里的层级。
    // numbers[0] 是最外层，numbers[level] 是当前 task 所处 namespace 里的 pid。
    int level;
    struct upid numbers[1];
} __attribute__((preserve_access_index));

struct task_struct {
    // group_leader 指向线程组 leader；对多线程程序，它对应“进程视角”的那条 task。
    struct task_struct *group_leader;
    // thread_pid 指向当前线程对应的 pid 结构体。
    struct pid *thread_pid;
} __attribute__((preserve_access_index));

struct flow_owner_key {
    __u8 family;
    __u8 l4_proto;
    __u8 pad[2];
    __u16 sport;
    __u16 dport;
    unsigned char saddr[16];
    unsigned char daddr[16];
} __attribute__((packed, aligned(4)));

struct flow_owner_value {
    __u64 pid_tgid;
    __u32 uid;
    __u64 cr_id;
    __u32 cr_pid;
    char comm[16];
};

struct tracked_flow_key {
    __u8 family;
    __u8 l4_proto;
    __u8 pad[2];
    __u16 sport;
    __u16 dport;
    unsigned char saddr[16];
    unsigned char daddr[16];
} __attribute__((packed, aligned(4)));

struct capture_config {
    __u32 ifindex;
    __u32 pcap_len;
};

struct pcap_rule_insn {
    __u16 code;
    __u8 jt;
    __u8 jf;
    __u32 k;
};

struct vlan_hdr_local {
    __be16 vlan_tci;
    __be16 encapsulated_proto;
};

struct ipv6_ext_hdr_local {
    __u8 nexthdr;
    __u8 hdrlen;
};

struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16 skc_num;
    unsigned short skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow_owner_key);
    __type(value, struct flow_owner_value);
} flow_owner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct tracked_flow_key);
    __type(value, __u8);
} tracked_flow_map SEC(".maps");

// userspace 会把 interface 和 -pcap-rules 两个运行时参数写进这里。
// capture_prog 每次处理包时都先读这个配置，决定是否先走 ifindex 限制和 classic BPF 规则。
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct capture_config);
} capture_config_map SEC(".maps");

// userspace 编译出的 classic BPF 指令数组。
// 内核侧只解释一个受限子集，目的是减少进入 userspace 的无关流量，而不是完整复刻 tcpdump 运行时。
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PCAP_RULES_MAX_INSNS);
    __type(key, __u32);
    __type(value, struct pcap_rule_insn);
} pcap_insns SEC(".maps");

static __always_inline int load_byte(struct __sk_buff *skb, __u32 offset, __u8 *value)
{
    // classic BPF 的 byte load 最终统一收敛到这里，先做边界检查再读字节。
    if (offset >= (__u32)skb->len) return -1;
    return bpf_skb_load_bytes(skb, offset, value, sizeof(*value));
}

static __always_inline int load_half(struct __sk_buff *skb, __u32 offset, __u32 *value)
{
    // 按网络字节序手工拼 16 位值，避免未对齐访问给 verifier 带来额外复杂度。
    __u8 buf[2];
    if (offset + sizeof(buf) > (__u32)skb->len) return -1;
    if (bpf_skb_load_bytes(skb, offset, buf, sizeof(buf)) < 0) return -1;
    *value = ((__u32)buf[0] << 8) | (__u32)buf[1];
    return 0;
}

static __always_inline int load_word(struct __sk_buff *skb, __u32 offset, __u32 *value)
{
    // 32 位读取同样手工拼接，保持和 classic BPF ABS/IND 语义一致。
    __u8 buf[4];
    if (offset + sizeof(buf) > (__u32)skb->len) return -1;
    if (bpf_skb_load_bytes(skb, offset, buf, sizeof(buf)) < 0) return -1;
    *value = ((__u32)buf[0] << 24) | ((__u32)buf[1] << 16) |
             ((__u32)buf[2] << 8) | (__u32)buf[3];
    return 0;
}

static __always_inline __u32 run_pcap_rules(struct __sk_buff *skb, __u32 insn_count)
{
    // classic BPF 解释器保留固定上界循环，避免动态 while 让 verifier 难以收敛。
    __u32 a = 0;
    __u32 x = 0;
    __u32 pc = 0;

    if (insn_count == 0) return (__u32)skb->len;
    if (insn_count > PCAP_RULES_MAX_INSNS) return 0;

    for (__u32 step = 0; step < PCAP_RULES_MAX_INSNS && pc < insn_count; ++step) {
        struct pcap_rule_insn *insn = bpf_map_lookup_elem(&pcap_insns, &pc);
        if (!insn) return 0;

        __u32 next_pc = pc + 1;
        switch (insn->code) {
        case BPF_LD | BPF_W | BPF_ABS:
            if (load_word(skb, insn->k, &a) < 0) return 0;
            break;
        case BPF_LD | BPF_H | BPF_ABS:
            if (load_half(skb, insn->k, &a) < 0) return 0;
            break;
        case BPF_LD | BPF_B | BPF_ABS: {
            __u8 value = 0;
            if (load_byte(skb, insn->k, &value) < 0) return 0;
            a = value;
            break;
        }
        case BPF_LD | BPF_W | BPF_IND: {
            __u32 off = x + insn->k;
            if (off < x || load_word(skb, off, &a) < 0) return 0;
            break;
        }
        case BPF_LD | BPF_H | BPF_IND: {
            __u32 off = x + insn->k;
            if (off < x || load_half(skb, off, &a) < 0) return 0;
            break;
        }
        case BPF_LD | BPF_B | BPF_IND: {
            __u32 off = x + insn->k;
            __u8 value = 0;
            if (off < x || load_byte(skb, off, &value) < 0) return 0;
            a = value;
            break;
        }
        case BPF_LDX | BPF_B | BPF_MSH: {
            __u8 value = 0;
            if (load_byte(skb, insn->k, &value) < 0) return 0;
            x = (__u32)(value & 0x0f) << 2;
            break;
        }
        case BPF_ALU | BPF_AND | BPF_K:
            a &= insn->k;
            break;
        case BPF_JMP | BPF_JA:
            next_pc = pc + 1 + insn->k;
            if (next_pc <= pc) return 0;
            pc = next_pc;
            continue;
        case BPF_JMP | BPF_JEQ | BPF_K:
            next_pc = pc + 1 + (a == insn->k ? insn->jt : insn->jf);
            if (next_pc <= pc) return 0;
            pc = next_pc;
            continue;
        case BPF_JMP | BPF_JGE | BPF_K:
            next_pc = pc + 1 + (a >= insn->k ? insn->jt : insn->jf);
            if (next_pc <= pc) return 0;
            pc = next_pc;
            continue;
        case BPF_JMP | BPF_JGT | BPF_K:
            next_pc = pc + 1 + (a > insn->k ? insn->jt : insn->jf);
            if (next_pc <= pc) return 0;
            pc = next_pc;
            continue;
        case BPF_JMP | BPF_JSET | BPF_K:
            next_pc = pc + 1 + ((a & insn->k) != 0 ? insn->jt : insn->jf);
            if (next_pc <= pc) return 0;
            pc = next_pc;
            continue;
        case BPF_RET | BPF_K:
            return insn->k;
        default:
            return 0;
        }

        pc = next_pc;
    }

    return 0;
}

static __always_inline int record_socket_owner(void *sk, __u8 l4_proto)
{
    struct flow_owner_key flow_key = {};
    struct flow_owner_value flow_value = {};
    const struct sock *sock = sk;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *leader = NULL;
    struct pid *pid = NULL;
    unsigned short family = 0;
    __u16 local_port = 0;
    __be16 remote_port = 0;
    int level = 0;

    if (!sk) return 0;

    // 记录当前执行上下文对应的宿主进程信息：
    // pid_tgid 用于保留宿主视角的进程身份；uid 用于按用户过滤；comm 用于按进程名过滤。
    flow_value.pid_tgid = bpf_get_current_pid_tgid();
    flow_value.uid = (__u32)bpf_get_current_uid_gid();
    // 先把容器字段置零：
    // 如果后面发现这是宿主机进程，或者 namespace 读取失败，就保持 0，避免输出脏值。
    flow_value.cr_pid = 0;
    flow_value.cr_id = 0;

    // 这里故意不取“当前线程”的 thread_pid，而是优先取线程组 leader 的 thread_pid。
    // 对 Go 这类多线程运行时，goroutine 可能落在不同内核线程上执行；
    // 如果直接读当前线程 pid，就会把同一进程打散成多个 cr_pid。
    leader = BPF_CORE_READ(task, group_leader);
    if (!leader) leader = task;

    // 读取线程组 leader 对应的 pid 结构体，得到稳定的“进程级” namespace pid。
    pid = BPF_CORE_READ(leader, thread_pid);
    if (pid) {
        // 读取 PID 结构体里的 level 字段：表示 PID namespace 的嵌套层级。
        // level=0 表示宿主机根 namespace；level>0 表示处在更深层的 namespace 中。
        level = BPF_CORE_READ(pid, level);
        if (level > 0) {
            // 读取当前 namespace 下的 PID，也就是容器视角看到的 pid。
            flow_value.cr_pid = BPF_CORE_READ(pid, numbers[level].nr);
            // 读取当前 PID namespace 的 inode 号，作为容器 namespace 的稳定标识。
            flow_value.cr_id = BPF_CORE_READ(pid, numbers[level].ns, ns.inum);
        }
        // level=0 时保持默认值 0：这里代表宿主机进程，不额外改写容器字段。
    }

    // comm 是进程名，后面 userspace 会把它作为 filter / 展示字段使用。
    if (bpf_get_current_comm(&flow_value.comm, sizeof(flow_value.comm)) < 0) return 0;

    // 这里只接受 TCP/UDP，其他 L4 协议直接丢弃。
    if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP) return 0;

    // 使用 CO-RE 直接读取 __sk_common，避免复制整块 sock_common 布局。
    if (BPF_CORE_READ_INTO(&family, sock, __sk_common.skc_family) < 0) return 0;
    if (BPF_CORE_READ_INTO(&local_port, sock, __sk_common.skc_num) < 0) return 0;
    if (BPF_CORE_READ_INTO(&remote_port, sock, __sk_common.skc_dport) < 0) return 0;

    flow_key.family = family;
    flow_key.l4_proto = l4_proto;
    flow_key.sport = local_port;
    flow_key.dport = bpf_ntohs(remote_port);

    // IPv4 场景：
    // skc_num 是本地端口，skc_dport / skc_rcv_saddr / skc_daddr 分别是对端端口、源地址和目的地址。
    if (family == AF_INET) {
        __be32 saddr4 = 0;
        __be32 daddr4 = 0;
        if (BPF_CORE_READ_INTO(&saddr4, sock, __sk_common.skc_rcv_saddr) < 0) return 0;
        if (BPF_CORE_READ_INTO(&daddr4, sock, __sk_common.skc_daddr) < 0) return 0;
        __builtin_memcpy(flow_key.saddr, &saddr4, 4);
        __builtin_memcpy(flow_key.daddr, &daddr4, 4);
        // 把“这个五元组属于谁”写入 BPF map，后续 userspace 会按相同 key 反查。
        bpf_map_update_elem(&flow_owner_map, &flow_key, &flow_value, BPF_ANY);
    // IPv6 场景：
    // 和 IPv4 的逻辑一致，只是地址长度扩展成 16 字节。
    } else if (family == AF_INET6) {
        struct in6_addr saddr6 = {};
        struct in6_addr daddr6 = {};
        if (BPF_CORE_READ_INTO(&saddr6, sock, __sk_common.skc_v6_rcv_saddr) < 0) return 0;
        if (BPF_CORE_READ_INTO(&daddr6, sock, __sk_common.skc_v6_daddr) < 0) return 0;
        __builtin_memcpy(flow_key.saddr, &saddr6, 16);
        __builtin_memcpy(flow_key.daddr, &daddr6, 16);
        bpf_map_update_elem(&flow_owner_map, &flow_key, &flow_value, BPF_ANY);
    }
    return 0;
}

// 探针1：跟踪 TCP 连接建立（客户端 connect）。
// 这个点能拿到“发起连接的一方”正在使用的 socket，因此适合记录客户端侧归属。
SEC("kprobe/tcp_connect")
int BPF_KPROBE(track_tcp_connect, void *sk) {
    if (!sk) return 0;
    return record_socket_owner(sk, IPPROTO_TCP);
}

// 探针2：跟踪 TCP 连接接受（inet_csk_accept 返回新建的连接 socket）。
// 这个点代表服务端 accept 之后拿到的新连接，因此适合记录服务端侧归属。
SEC("kretprobe/inet_csk_accept")
int track_tcp_accept(struct pt_regs *ctx) {
    void *new_sk = (void *)PT_REGS_RC(ctx);
    if (!new_sk) return 0;
    return record_socket_owner(new_sk, IPPROTO_TCP);
}

// tcp_sendmsg / udp_sendmsg 作为发送侧 owner 更新点。
// 发送路径上经常能拿到更接近“真正发包者”的上下文，因此这里作为补充更新点。
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(track_tcp_sendmsg, void *sk, void *msg, unsigned long size) {
    if (!sk) return 0;
    return record_socket_owner(sk, IPPROTO_TCP);
}
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(track_udp_sendmsg, void *sk, void *msg, unsigned long size) {
    if (!sk) return 0;
    return record_socket_owner(sk, IPPROTO_UDP);
}

static __always_inline int is_http_https_port(__u16 port)
{
    // 常见 HTTP/HTTPS 与代理端口直接走常量分支，避免循环展开。
    switch (port) {
    case 80:
    case 443:
    case 8000:
    case 8008:
    case 8080:
    case 8443:
    case 8888:
    case 12006: // zgg 内部网关特殊端口
        return 1;
    default:
        return 0;
    }
}

static __always_inline int is_vlan_proto(__u16 proto)
{
    // VLAN 封装会在 Ethernet 和真正的 IP 头之间插一层额外头部。
    return proto == ETH_P_8021Q || proto == ETH_P_8021AD;
}

static __always_inline int is_http_probe(const unsigned char *data, __u32 len)
{
    // 只看前 4 字节魔数，避免一长串字符比较分支。
    // 这里不直接做未对齐的 __u32 指针解引用，保持对 verifier 更友好。
    if (len < 4) return 0;
    __u32 magic = ((__u32)data[0] << 24) | ((__u32)data[1] << 16) |
                  ((__u32)data[2] << 8) | (__u32)data[3];

    switch (magic) {
    case HTTP_MAGIC4('G', 'E', 'T', ' '):
    case HTTP_MAGIC4('P', 'O', 'S', 'T'):
    case HTTP_MAGIC4('H', 'E', 'A', 'D'):
    case HTTP_MAGIC4('P', 'U', 'T', ' '):
    case HTTP_MAGIC4('D', 'E', 'L', 'E'):
    case HTTP_MAGIC4('O', 'P', 'T', 'I'):
    case HTTP_MAGIC4('P', 'A', 'T', 'C'):
    case HTTP_MAGIC4('C', 'O', 'N', 'N'):
    case HTTP_MAGIC4('T', 'R', 'A', 'C'):
    case HTTP_MAGIC4('H', 'T', 'T', 'P'):
        return 1;
    default:
        return 0;
    }
}

static __always_inline int is_tls_probe(const unsigned char *data, __u32 len)
{
    // 允许 handshake/ccs/alert/appdata 四类常见 TLS record，
    // 这样在非标准端口上也更容易把中途接入的 TLS 流量识别出来。
    if (len < 5) return 0;
    if (data[1] != 0x03 || data[2] > 0x04) return 0;
    return data[0] == 0x14 || data[0] == 0x15 || data[0] == 0x16 || data[0] == 0x17;
}

static __always_inline int is_quic_probe(const unsigned char *data, __u32 len)
{
    // QUIC Initial 包的高位通常会被置位，这里只做最粗的启发式判断。
    if (len < 1) return 0;
    return (data[0] & 0x80) != 0;
}

static __always_inline int pull_vlan_once(struct __sk_buff *skb, __u64 *offset, __u16 *proto)
{
    struct vlan_hdr_local vlan;

    if (*offset + sizeof(vlan) > (__u64)skb->len) return -1;
    if (bpf_skb_load_bytes(skb, *offset, &vlan, sizeof(vlan)) < 0) return -1;
    *proto = bpf_ntohs(vlan.encapsulated_proto);
    *offset += sizeof(vlan);
    return 0;
}

static __always_inline int skip_ipv6_extension_headers(struct __sk_buff *skb, __u64 *offset, __u8 *nexthdr)
{
#pragma unroll
    for (int i = 0; i < IPV6_MAX_EXT_HEADERS; ++i) {
        if (*nexthdr == IPPROTO_TCP || *nexthdr == IPPROTO_UDP) return 0;
        if (*nexthdr != IPPROTO_HOPOPTS && *nexthdr != IPPROTO_DSTOPTS &&
            *nexthdr != IPPROTO_ROUTING && *nexthdr != IPPROTO_FRAGMENT) {
            return -1;
        }

        struct ipv6_ext_hdr_local ext;
        __u32 ext_len;

        if (*offset + sizeof(ext) > (__u64)skb->len) return -1;
        if (bpf_skb_load_bytes(skb, *offset, &ext, sizeof(ext)) < 0) return -1;
        ext_len = (*nexthdr == IPPROTO_FRAGMENT) ? 8U : ( (__u32)ext.hdrlen + 1U) * 8U;
        if (*offset + ext_len > (__u64)skb->len) return -1;

        *offset += ext_len;
        *nexthdr = ext.nexthdr;
    }

    return (*nexthdr == IPPROTO_TCP || *nexthdr == IPPROTO_UDP) ? 0 : -1;
}

static __always_inline int payload_has_l7_signature(const unsigned char *data, __u32 len, __u8 l4_proto)
{
    // socket filter 不做 TCP 重组，但会在首个 64 字节内扫描少量偏移，
    // 用来覆盖以下场景：
    // 1. TLS 1.3 响应前面夹带 CCS；
    // 2. HTTP CONNECT / TLS 记录没有恰好落在 payload 第 0 字节；
    // 3. 非标准端口上的 HTTPS 隧道流量。
    if (len == 0) return 0;

#pragma unroll
    for (int i = 0; i < MAX_L7_SCAN_OFFSETS; ++i) {
        if ((__u32)i >= len) continue;
        __u32 remain = len - (__u32)i;
        const unsigned char *p = data + i;

        if (i < MAX_HTTP_SCAN_OFFSETS && is_http_probe(p, remain)) return 1;
        if (is_tls_probe(p, remain)) return 1;
        if (l4_proto == IPPROTO_UDP && is_quic_probe(p, remain)) return 1;
    }

    return 0;
}

static __always_inline int fill_tracked_flow_key(struct tracked_flow_key *key,
                                                 __u8 family, __u8 l4_proto,
                                                 const unsigned char *saddr,
                                                 const unsigned char *daddr,
                                                 __u16 sport, __u16 dport)
{
    // capture_prog 的 lookup/store 共用一份 key，减少重复初始化和地址拷贝。
    __builtin_memset(key, 0, sizeof(*key));
    key->family = family;
    key->l4_proto = l4_proto;
    key->sport = sport;
    key->dport = dport;
    if (family == AF_INET) {
        __builtin_memcpy(key->saddr, saddr, 4);
        __builtin_memcpy(key->daddr, daddr, 4);
    } else if (family == AF_INET6) {
        __builtin_memcpy(key->saddr, saddr, 16);
        __builtin_memcpy(key->daddr, daddr, 16);
    } else {
        return 0;
    }
    return 1;
}

static __always_inline int tracked_flow_lookup(const struct tracked_flow_key *key)
{
    // 如果这条流已经被确认是 HTTP/HTTPS/QUIC 相关流，就直接放行，不再重复判断。
    return bpf_map_lookup_elem(&tracked_flow_map, key) != NULL;
}

static __always_inline void tracked_flow_store(const struct tracked_flow_key *key)
{
    // 同时写正向和反向 key：这样请求方向和响应方向都能命中同一条已追踪流。
    // 一旦某个首包确认是目标流量，后续整条连接都可以绕过前缀探测，直接放行到 userspace。
    struct tracked_flow_key reverse = {};
    __u8 value = 1;

    reverse.family = key->family;
    reverse.l4_proto = key->l4_proto;
    reverse.sport = key->dport;
    reverse.dport = key->sport;

    if (key->family == AF_INET) {
        __builtin_memcpy(reverse.saddr, key->daddr, 4);
        __builtin_memcpy(reverse.daddr, key->saddr, 4);
    } else if (key->family == AF_INET6) {
        __builtin_memcpy(reverse.saddr, key->daddr, 16);
        __builtin_memcpy(reverse.daddr, key->saddr, 16);
    } else {
        return;
    }

    bpf_map_update_elem(&tracked_flow_map, key, &value, BPF_ANY);
    bpf_map_update_elem(&tracked_flow_map, &reverse, &value, BPF_ANY);
}

SEC("socket")
int capture_prog(struct __sk_buff *skb)
{
    // socket filter 主入口：先解析 L2/L3/L4，再决定这条流是否值得放进 userspace。
    // eBPF 侧的职责不是精确协议解析，而是尽量把明显无关的流量挡在内核里。
    __u32 config_key = 0;
    const struct capture_config *config = bpf_map_lookup_elem(&capture_config_map, &config_key);
    if (config) {
        if (config->ifindex != 0 && skb->ifindex != config->ifindex) return 0;
        // 如果 pcap_rules 存在， 是否转发完全由它决定；如果 pcap_rules 不存在，就继续走后续的协议特征判断逻辑。
        if (config->pcap_len > 0) return run_pcap_rules(skb, config->pcap_len);
    }

    // 下面的代码分步解析以太网、IP 和 TCP/UDP 头，提取五元组信息。
    // 之后会根据五元组判断这条流是否已经被确认是 HTTP/HTTPS/QUIC 相关流，如果没有就取 payload 前 64 字节做轻量特征扫描。
    struct ethhdr eth;
    __u64 offset = 0;
    __u16 h_proto;
    __u8 family = 0;
    __u8 l4_proto = 0;
    __u8 ipv6_nexthdr = 0;
    __u16 sport = 0;
    __u16 dport = 0;
    __u64 payload_offset = 0;
    __u32 skb_len = (__u32)skb->len;
    struct tracked_flow_key flow_key = {};
    unsigned char saddr[16] = {};
    unsigned char daddr[16] = {};

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) return 0;
    h_proto = bpf_ntohs(eth.h_proto);
    offset = sizeof(eth);

    // 显式处理两层 VLAN，减少循环结构带来的 verifier 成本。
    if (is_vlan_proto(h_proto)) {
        if (pull_vlan_once(skb, &offset, &h_proto) < 0) return 0;
        if (is_vlan_proto(h_proto)) {
            if (pull_vlan_once(skb, &offset, &h_proto) < 0) return 0;
        }
    }

    if (h_proto == ETH_P_IP) {
        // IPv4：读取 IP 头，确认上层是 TCP/UDP，再提取源/目的地址。
        // 这里保持“每走一步就做一次边界判断”，目的是让 verifier 更容易证明所有访问都安全。
        struct iphdr iph;
        __u32 ihl = 0;
        if (bpf_skb_load_bytes(skb, offset, &iph, sizeof(iph)) < 0) return 0;
        ihl = iph.ihl * 4;
        if (ihl < sizeof(iph)) return 0;
        if (iph.protocol != IPPROTO_TCP && iph.protocol != IPPROTO_UDP) return 0;
        family = AF_INET;
        l4_proto = iph.protocol;
        __builtin_memcpy(saddr, &iph.saddr, 4);
        __builtin_memcpy(daddr, &iph.daddr, 4);
        offset += ihl;
    } else if (h_proto == ETH_P_IPV6) {
        // IPv6：先读取基础头，再跳过常见扩展头，最后定位到 TCP/UDP。
        // IPv6 比 IPv4 更容易因为扩展头漏掉真实 L4 起点，所以这里专门做有限层数的扩展头跳转。
        struct ipv6hdr ip6;
        if (bpf_skb_load_bytes(skb, offset, &ip6, sizeof(ip6)) < 0) return 0;
        family = AF_INET6;
        ipv6_nexthdr = ip6.nexthdr;
        __builtin_memcpy(saddr, &ip6.saddr, 16);
        __builtin_memcpy(daddr, &ip6.daddr, 16);
        offset += sizeof(ip6);
        if (skip_ipv6_extension_headers(skb, &offset, &ipv6_nexthdr) < 0) return 0;
        l4_proto = ipv6_nexthdr;
    } else {
        return 0;
    }

    // 到这里 offset 已经指向 TCP/UDP 头。后面要做 payload 特征探测，
    // 所以需要继续跳过 L4 头，不能把 TCP/UDP 头字节当成 HTTP/TLS 前缀。
    if (l4_proto == IPPROTO_TCP) {
        // TCP payload 起点不是固定值，必须根据 doff 跳过 options 后再做协议前缀判断。
        struct tcphdr tcph;
        __u32 tcp_hdr_len = 0;
        if (offset + sizeof(tcph) > (__u64)skb->len) return 0;
        if (bpf_skb_load_bytes(skb, offset, &tcph, sizeof(tcph)) < 0) return 0;
        tcp_hdr_len = (__u32)tcph.doff * 4U;
        if (tcp_hdr_len < sizeof(tcph) || tcp_hdr_len > 60U) return 0;
        payload_offset = offset + tcp_hdr_len;
        if (payload_offset > (__u64)skb->len) return 0;
        sport = bpf_ntohs(tcph.source);
        dport = bpf_ntohs(tcph.dest);
    } else if (l4_proto == IPPROTO_UDP) {
        // UDP 头固定 8 字节，因此 payload 起点更简单，但仍然需要先做长度检查。
        struct udphdr udph;
        if (offset + sizeof(udph) > (__u64)skb->len) return 0;
        if (bpf_skb_load_bytes(skb, offset, &udph, sizeof(udph)) < 0) return 0;
        payload_offset = offset + sizeof(udph);
        if (payload_offset > (__u64)skb->len) return 0;
        sport = bpf_ntohs(udph.source);
        dport = bpf_ntohs(udph.dest);
    } else {
        return 0;
    }

    if (!fill_tracked_flow_key(&flow_key, family, l4_proto, saddr, daddr, sport, dport)) return 0;

    // 如果这条流已经在 tracked_flow_map 里，直接放行。
    if (tracked_flow_lookup(&flow_key)) return skb->len;

    // 常见 HTTP/HTTPS 端口优先直接放行，避免每个数据包都做 payload 扫描。
    if (is_http_https_port(sport) || is_http_https_port(dport)) {
        tracked_flow_store(&flow_key);
        return skb->len;
    }

    // 非典型端口时，再取 payload 前 64 字节做轻量窗口扫描。
    // 这一步仍然远比 userspace 解析便宜，但能覆盖更多代理/TLS 1.3 场景。
    // 这里保留 64/32/16/8/5 的固定分档，是为了兼顾 verifier 稳定性与足够的探测窗口。
    if (payload_offset + 5 > (__u64)skb_len) return 0;
    unsigned char probe[64] = {};
    __u32 probe_len = 5;
    if (payload_offset + 64 <= (__u64)skb_len) {
        probe_len = 64;
    } else if (payload_offset + 32 <= (__u64)skb_len) {
        probe_len = 32;
    } else if (payload_offset + 16 <= (__u64)skb_len) {
        probe_len = 16;
    } else if (payload_offset + 8 <= (__u64)skb_len) {
        probe_len = 8;
    }
    if (bpf_skb_load_bytes(skb, payload_offset, probe, probe_len) < 0) return 0;

    if (payload_has_l7_signature(probe, probe_len, l4_proto)) {
        // 命中后把双向五元组都写进 tracked_flow_map，后面同一连接的包就不需要重复扫描了。
        tracked_flow_store(&flow_key);
        return skb->len;
    }

    // 既不是典型端口，也没有命中窗口特征，就丢弃。
    return 0;
}

char LICENSE[] SEC("license") = "GPL";