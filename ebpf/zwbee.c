// Userspace 程序：读取 eBPF 上报的 TCP/UDP 负载，按 HTTP/HTTPS 进行解析后输出单行 JSON。
// 设计目标：
// 1. eBPF 侧只负责稳定地抓包和搬运原始负载
// 2. userspace 负责协议识别、HTTP 流缓冲、SNI 解析、进程/网段过滤
// 3. 每个事件只输出一次 JSON，避免控制台分段写入造成解析混乱

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
/* 
使用 libpcap-dev 提供的函数，由于依赖问题，已被禁用。
#define bpf_insn pcap_bpf_insn
#include <pcap/pcap.h>
#undef bpf_insn
*/
#include <linux/filter.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern unsigned char _binary_ebpf_capture_o_start[];
extern unsigned char _binary_ebpf_capture_o_end[];

#define CAP_PAYLOAD 4096
#define FLOW_BUCKETS 8192
#define COMM_LEN 16
#define FLOW_BUFFER_CAP 32768
#define SOCKET_CACHE_MAX_ITEMS 8192
#define SOCKET_CACHE_BUCKETS 2048
#define PROC_OWNER_MAX_ITEMS 65536
#define SOCKET_CACHE_REFRESH_MS 1000
#define FLOW_STATE_MAX_ITEMS 4096
#define PCAP_RULES_MAX_INSNS 256

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

struct event_t {
    uint64_t cookie;
    uint8_t family;
    uint8_t direction;
    uint8_t l4_proto;
    uint8_t pad;
    uint16_t sport;
    uint16_t dport;
    uint32_t payload_len;
    uint32_t cap_len;
    unsigned char saddr[16];
    unsigned char daddr[16];
    unsigned char payload[CAP_PAYLOAD];
} __attribute__((packed));

// 单条 CIDR 规则：
// deny 表示拒绝规则，family/prefix_len/addr 描述匹配范围。
struct cidr_rule {
    bool deny;
    int family;
    uint8_t prefix_len;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } addr;
};

// 一组 CIDR 规则：
// 规则会按命令行顺序保存，匹配时先看拒绝规则，再看允许规则。
struct cidr_set {
    struct cidr_rule *items;
    size_t len;
    size_t cap;
};

// /proc 扫描得到的 socket 拥有者信息：
// inode 是 socket 的稳定索引，pid/uid/cr_id/cr_pid/comm 用于恢复运行实体。
struct proc_owner {
    unsigned long long inode;
    pid_t pid;
    uid_t uid;
    uint64_t cr_id;
    uint32_t cr_pid;
    char comm[COMM_LEN];
};

// 最终用于输出和过滤的 socket 元数据：
// 这个结构体统一承接 BPF map 回填和 /proc 回填结果。
struct socket_meta {
    int family;
    int proto;
    unsigned char saddr[16];
    unsigned char daddr[16];
    uint16_t sport;
    uint16_t dport;
    unsigned long long inode;
    pid_t pid;
    uid_t uid;
    uint64_t cr_id;
    uint32_t cr_pid;
    char comm[COMM_LEN];
};

// BPF map key：
// 由协议族、方向、四元组组成，用来在内核侧快速定位流归属。
struct flow_owner_key {
    uint8_t family;
    uint8_t l4_proto;
    uint8_t pad[2];
    uint16_t sport;
    uint16_t dport;
    unsigned char saddr[16];
    unsigned char daddr[16];
};

// BPF map value：
// 保存抓包瞬间的进程身份和容器视角身份。
struct flow_owner_value {
    uint64_t pid_tgid;
    uint32_t uid;
    uint64_t cr_id;
    uint32_t cr_pid;
    char comm[COMM_LEN];
};

// BPF socket filter 的运行参数：
// ifindex 控制接口级过滤；pcap_len 表示当前装载了多少条 classic BPF 指令。
struct capture_config {
    uint32_t ifindex;
    uint32_t pcap_len;
};

// userspace 与 eBPF 共享的 classic BPF 指令布局。
struct pcap_rule_insn {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

// userspace socket 缓存：
// 这是对 /proc/net/* 和 /proc/<pid>/fd 的二次整理结果，供失败回退使用。
struct socket_cache {
    struct socket_meta *items;
    size_t *next_idx;
    size_t buckets[SOCKET_CACHE_BUCKETS];
    size_t len;
    size_t cap;
    size_t max_items;
    uint64_t last_refresh_ms;
};

// 可增长的字节缓冲区：
// TCP 负载可能分段到达，需要在 userspace 里先拼接再解析。
struct byte_buffer {
    unsigned char *data;
    size_t len;
    size_t cap;
};

// flow 状态 key：
// 同一条连接的双向数据需要区分方向，否则请求和响应会写进同一个状态槽。
struct flow_key {
    uint8_t family;
    uint8_t l4_proto;
    uint8_t direction;
    uint8_t pad;
    uint16_t sport;
    uint16_t dport;
    unsigned char saddr[16];
    unsigned char daddr[16];
};

// 单条流的运行状态：
// 这里保存 TCP 重组缓冲、最近一次元数据和 TLS/域名识别结果。
struct flow_state {
    struct flow_key key;
    struct byte_buffer tcp_buffer;
    uint64_t last_seen_ms;
    pid_t pid;
    uid_t uid;
    uint64_t cr_id;
    uint32_t cr_pid;
    char comm[COMM_LEN];
    bool tls_emitted;
    bool has_domain;
    char domain[256];
    struct flow_state *next;
};

// 命令行配置：
// 所有过滤条件、body 限制和接口选择都集中到这里，方便后续统一判断。
struct zwbee_config {
    const char *ifname;
    const char *pcap_rules;
    int ifindex;
    int direction_filter;
    bool have_pid_filter;
    pid_t pid_filter;
    bool have_cpid_filter;
    uint32_t cpid_filter;
    bool have_crid_filter;
    uint64_t crid_filter;
    bool have_comm_filter;
    char comm_filter[COMM_LEN];
    bool have_sport_filter;
    uint16_t sport_filter;
    bool have_dport_filter;
    uint16_t dport_filter;
    long long body_limit;
    struct cidr_set src_rules;
    struct cidr_set dst_rules;
};

// 进程级运行状态：
// 维护 flow 哈希桶、socket cache 和 BPF map fd。
struct zwbee_state {
    struct flow_state *flows[FLOW_BUCKETS];
    struct socket_cache sockets;
    int flow_owner_map_fd;
    uint64_t last_gc_ms;
    size_t flow_count;
};

// 回调上下文：
// 把 state 和 cfg 传入抓包回调，避免使用全局变量。
struct callback_ctx {
    struct zwbee_state *state;
    struct zwbee_config *cfg;
};

static volatile bool exiting = false;

static void sigint_handler(int sig)
{
    (void)sig;
    exiting = true;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static uint64_t epoch_ms(void)
{
    // 对外输出时间戳使用真实时钟；内部超时和 GC 则使用 monotonic 的 now_ms。
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}


static void iso8601_ms(uint64_t ms, char *out, size_t out_len)
{
    time_t secs = (time_t)(ms / 1000ULL);
    struct tm tm;
    char date_buf[32];
    char tz_buf[8];
    
    localtime_r(&secs, &tm);
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%dT%H:%M:%S", &tm);
    strftime(tz_buf, sizeof(tz_buf), "%z", &tm);
    
    if (strlen(tz_buf) == 5) {
        // 格式字符串补全最后一个%c，对应tz_buf[4]
        snprintf(out, out_len, "%s.%03llu%c%c%c:%c%c",
                 date_buf,
                 (unsigned long long)(ms % 1000ULL),
                 tz_buf[0],  // 符号：+/-
                 tz_buf[1],  // 小时第一位
                 tz_buf[2],  // 小时第二位
                 tz_buf[3],  // 分钟第一位
                 tz_buf[4]); // 分钟第二位 ✅ 现在占位符数量匹配
    } else {
        snprintf(out, out_len, "%s.%03llu%s",
                 date_buf,
                 (unsigned long long)(ms % 1000ULL),
                 tz_buf);
    }
}

static uint64_t rand64(void)
{
    // 组合多个 rand() 输出，得到一个分布稍好的 64 位伪随机数。
    uint64_t a = (uint64_t)rand();
    uint64_t b = (uint64_t)rand();
    uint64_t c = (uint64_t)rand();
    uint64_t d = (uint64_t)rand();
    return (a << 48) ^ (b << 32) ^ (c << 16) ^ d ^ (uint64_t)getpid();
}

static void make_record_id(char out[25], uint64_t ms)
{
    // 记录 ID 用时间戳前缀加随机/序列后缀，目标是“短、顺手、低碰撞”。
    static unsigned long long seq = 0;
    unsigned long long left = (unsigned long long)(ms & 0x7ffffffffffULL);
    unsigned long long right = ((unsigned long long)__sync_fetch_and_add(&seq, 1) ^ rand64()) & 0x1ffffffffffffULL;
    snprintf(out, 25, "%011llx%013llx", left, right);
    out[24] = '\0';
}

static uint64_t fnv1a64_update(uint64_t hash, const void *data, size_t len);

static void flow_key_hex(const struct event_t *e, pid_t pid, char out[17])
{
    uint64_t h = 14695981039346656037ULL;
    size_t len = e->family == AF_INET ? 4 : 16;
    char pid_buf[32];
    snprintf(pid_buf, sizeof(pid_buf), "%d", pid);

    // 做五元组规范化，保证同一条连接的正反向数据生成同一个 key。
    unsigned char left[24] = {0};
    unsigned char right[24] = {0};
    unsigned char a[24] = {0};
    unsigned char b[24] = {0};
    memcpy(a, e->saddr, len);
    memcpy(b, e->daddr, len);
    bool swap = false;
    int cmp = memcmp(a, b, len);
    if (cmp > 0 || (cmp == 0 && e->sport > e->dport)) swap = true;
    if (swap) {
        memcpy(left, e->daddr, len);
        memcpy(right, e->saddr, len);
        left[len] = (unsigned char)(e->dport >> 8);
        left[len + 1] = (unsigned char)e->dport;
        right[len] = (unsigned char)(e->sport >> 8);
        right[len + 1] = (unsigned char)e->sport;
    } else {
        memcpy(left, e->saddr, len);
        memcpy(right, e->daddr, len);
        left[len] = (unsigned char)(e->sport >> 8);
        left[len + 1] = (unsigned char)e->sport;
        right[len] = (unsigned char)(e->dport >> 8);
        right[len + 1] = (unsigned char)e->dport;
    }
    h = fnv1a64_update(h, left, len + 2);
    h = fnv1a64_update(h, right, len + 2);
    h = fnv1a64_update(h, &e->l4_proto, sizeof(e->l4_proto));
    h = fnv1a64_update(h, pid_buf, strlen(pid_buf));
    snprintf(out, 17, "%016llx", (unsigned long long)h);
    out[16] = '\0';
}

static void record_key_hex(const struct event_t *e, const struct socket_meta *meta, char out[17])
{
    // 优先用 cookie 生成 key；cookie 不可用时，再退回到五元组 + pid 的组合 hash。
    pid_t pid = meta && meta->pid > 0 ? meta->pid : 0;
    if (e->cookie) {
        uint64_t h = 14695981039346656037ULL;
        char pid_buf[32];
        uint64_t cookie = e->cookie;
        snprintf(pid_buf, sizeof(pid_buf), "%d", pid);
        h = fnv1a64_update(h, &cookie, sizeof(cookie));
        h = fnv1a64_update(h, pid_buf, strlen(pid_buf));
        snprintf(out, 17, "%016llx", (unsigned long long)h);
        out[16] = '\0';
        return;
    }
    flow_key_hex(e, pid, out);
}

static void emit_json_line(const char *json)
{
    // 所有输出都统一走这一层，保证前缀一致，也便于后续按行消费。
    flockfile(stdout);
    fputs("EBPF_CAPTURE: ", stdout);
    fputs(json, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    funlockfile(stdout);
}

static void buffer_free(struct byte_buffer *buf)
{
    // 释放并清空缓冲区，防止流被淘汰后继续持有旧内存。
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

static bool buffer_reserve(struct byte_buffer *buf, size_t need)
{
    // 指数扩容，减少频繁 realloc 带来的拷贝开销。
    if (need <= buf->cap) return true;
    size_t next_cap = buf->cap ? buf->cap : 1024;
    while (next_cap < need) next_cap *= 2;
    unsigned char *next = realloc(buf->data, next_cap);
    if (!next) return false;
    buf->data = next;
    buf->cap = next_cap;
    return true;
}

static bool buffer_append(struct byte_buffer *buf, const unsigned char *data, size_t len)
{
    if (len == 0) return true;

    // 对单条流的缓存做上限控制，避免慢连接把内存拖爆。
    if (buf->len + len > FLOW_BUFFER_CAP) {
        if (len >= FLOW_BUFFER_CAP) {
            data += len - FLOW_BUFFER_CAP;
            len = FLOW_BUFFER_CAP;
        }
        if (buf->len > FLOW_BUFFER_CAP - len) {
            size_t drop = buf->len + len - FLOW_BUFFER_CAP;
            if (drop >= buf->len) {
                buf->len = 0;
            } else {
                memmove(buf->data, buf->data + drop, buf->len - drop);
                buf->len -= drop;
            }
        }
    }

    if (!buffer_reserve(buf, buf->len + len)) return false;
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return true;
}

static void buffer_consume(struct byte_buffer *buf, size_t n)
{
    // 消费掉已解析前缀，把剩余内容前移，继续等待下一批字节。
    if (n == 0) return;
    if (n >= buf->len) {
        buf->len = 0;
        return;
    }
    memmove(buf->data, buf->data + n, buf->len - n);
    buf->len -= n;
}

static uint64_t fnv1a64(const void *data, size_t len)
{
    // 标准 FNV-1a 64 位哈希。
    const unsigned char *p = data;
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= p[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static uint64_t fnv1a64_update(uint64_t hash, const void *data, size_t len)
{
    // 在已有 hash 上继续滚动更新，便于把多个字段串成一个组合 key。
    const unsigned char *p = data;
    for (size_t i = 0; i < len; ++i) {
        hash ^= p[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static size_t socket_cache_hash_key(int family, int proto,
                                    const unsigned char *saddr,
                                    const unsigned char *daddr,
                                    uint16_t sport, uint16_t dport)
{
    // socket cache 的哈希只关注五元组和协议，目标是把回退查找成本压到近似 O(1)。
    size_t addr_len = family == AF_INET ? 4 : 16;
    uint64_t hash = 14695981039346656037ULL;
    hash = fnv1a64_update(hash, &family, sizeof(family));
    hash = fnv1a64_update(hash, &proto, sizeof(proto));
    hash = fnv1a64_update(hash, saddr, addr_len);
    hash = fnv1a64_update(hash, daddr, addr_len);
    hash = fnv1a64_update(hash, &sport, sizeof(sport));
    hash = fnv1a64_update(hash, &dport, sizeof(dport));
    return (size_t)(hash % SOCKET_CACHE_BUCKETS);
}

static void socket_cache_reset(struct socket_cache *cache)
{
    // reset 不只是 free 内存，还要清空桶头，避免后续 rebuild 时把旧链表串进来。
    free(cache->items);
    free(cache->next_idx);
    cache->items = NULL;
    cache->next_idx = NULL;
    cache->len = 0;
    cache->cap = 0;
    for (size_t i = 0; i < SOCKET_CACHE_BUCKETS; ++i) cache->buckets[i] = (size_t)-1;
}

static size_t flow_bucket(const struct flow_key *key)
{
    // 用 hash 结果把流分散到固定数量的桶里。
    return (size_t)(fnv1a64(key, sizeof(*key)) % FLOW_BUCKETS);
}

static struct flow_state *flow_find(struct zwbee_state *state, const struct flow_key *key)
{
    // 在指定桶链表里查找已有 flow。
    size_t bucket = flow_bucket(key);
    for (struct flow_state *flow = state->flows[bucket]; flow; flow = flow->next) {
        if (memcmp(&flow->key, key, sizeof(*key)) == 0) return flow;
    }
    return NULL;
}

static struct flow_state *flow_get(struct zwbee_state *state, const struct flow_key *key)
{
    // 先查找，查不到再新建；如果状态满了，先淘汰最老的 flow。
    struct flow_state *flow = flow_find(state, key);
    if (flow) return flow;

    if (state->flow_count >= FLOW_STATE_MAX_ITEMS) {
        struct flow_state *victim = NULL;
        struct flow_state **victim_link = NULL;
        for (size_t i = 0; i < FLOW_BUCKETS; ++i) {
            struct flow_state **pp = &state->flows[i];
            while (*pp) {
                struct flow_state *candidate = *pp;
                if (!victim || candidate->last_seen_ms < victim->last_seen_ms) {
                    victim = candidate;
                    victim_link = pp;
                }
                pp = &candidate->next;
            }
        }
        if (victim && victim_link) {
            *victim_link = victim->next;
            buffer_free(&victim->tcp_buffer);
            free(victim);
            if (state->flow_count > 0) state->flow_count--;
        }
    }

    flow = calloc(1, sizeof(*flow));
    if (!flow) return NULL;
    flow->key = *key;
    size_t bucket = flow_bucket(key);
    flow->next = state->flows[bucket];
    state->flows[bucket] = flow;
    state->flow_count++;
    return flow;
}

static void flow_gc(struct zwbee_state *state, uint64_t cutoff_ms)
{
    // 周期性清理过期流，避免长时间无流量的连接一直占着状态。
    for (size_t i = 0; i < FLOW_BUCKETS; ++i) {
        struct flow_state **pp = &state->flows[i];
        while (*pp) {
            struct flow_state *flow = *pp;
            if (flow->last_seen_ms < cutoff_ms) {
                *pp = flow->next;
                buffer_free(&flow->tcp_buffer);
                free(flow);
                if (state->flow_count > 0) state->flow_count--;
                continue;
            }
            pp = &flow->next;
        }
    }
}

static void cidr_set_free(struct cidr_set *set)
{
    // 释放 CIDR 规则列表。
    free(set->items);
    set->items = NULL;
    set->len = 0;
    set->cap = 0;
}

static bool cidr_set_push(struct cidr_set *set, const struct cidr_rule *rule)
{
    // 追加一条规则，容量不够时自动扩容。
    if (set->len == set->cap) {
        size_t next_cap = set->cap ? set->cap * 2 : 8;
        struct cidr_rule *next = realloc(set->items, next_cap * sizeof(*next));
        if (!next) return false;
        set->items = next;
        set->cap = next_cap;
    }
    set->items[set->len++] = *rule;
    return true;
}

static char *trim_ws(char *s)
{
    // 去掉首尾空白，方便解析命令行里的 CIDR 列表。
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return s;
}

static bool parse_cidr_rule(const char *token, bool deny, struct cidr_rule *rule)
{
    // 把单个 CIDR token 转成规则结构，同时记录它是 allow 还是 deny。
    memset(rule, 0, sizeof(*rule));
    rule->deny = deny;

    char *tmp = strdup(token);
    if (!tmp) return false;
    char *slash = strchr(tmp, '/');
    if (slash) *slash = '\0';
    char *addr_part = trim_ws(tmp);
    char *prefix_part = slash ? trim_ws(slash + 1) : NULL;

    if (strchr(addr_part, ':')) {
        rule->family = AF_INET6;
        rule->prefix_len = prefix_part ? (uint8_t)strtoul(prefix_part, NULL, 10) : 128;
        if (rule->prefix_len > 128) rule->prefix_len = 128;
        if (inet_pton(AF_INET6, addr_part, &rule->addr.v6) != 1) {
            free(tmp);
            return false;
        }
    } else {
        rule->family = AF_INET;
        rule->prefix_len = prefix_part ? (uint8_t)strtoul(prefix_part, NULL, 10) : 32;
        if (rule->prefix_len > 32) rule->prefix_len = 32;
        if (inet_pton(AF_INET, addr_part, &rule->addr.v4) != 1) {
            free(tmp);
            return false;
        }
    }

    free(tmp);
    return true;
}

static bool parse_cidr_list(const char *spec, struct cidr_set *set)
{
    // 逗号分隔的 CIDR 列表；前缀 ! 表示拒绝规则。
    if (!spec || !*spec) return true;
    char *tmp = strdup(spec);
    if (!tmp) return false;

    for (char *save = NULL, *tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        tok = trim_ws(tok);
        bool deny = false;
        if (*tok == '!') {
            deny = true;
            tok = trim_ws(tok + 1);
        }
        if (!*tok) continue;
        struct cidr_rule rule;
        if (!parse_cidr_rule(tok, deny, &rule) || !cidr_set_push(set, &rule)) {
            free(tmp);
            return false;
        }
    }

    free(tmp);
    return true;
}

static bool cidr_match_v4(const struct cidr_rule *rule, const unsigned char *addr)
{
    uint32_t want = ntohl(rule->addr.v4.s_addr);
    uint32_t got = ((uint32_t)addr[0] << 24) | ((uint32_t)addr[1] << 16) | ((uint32_t)addr[2] << 8) | (uint32_t)addr[3];
    uint32_t mask = rule->prefix_len == 0 ? 0 : (~0U << (32 - rule->prefix_len));
    return (want & mask) == (got & mask);
}

static bool cidr_match_v6(const struct cidr_rule *rule, const unsigned char *addr)
{
    int bits = rule->prefix_len;
    for (int i = 0; i < 16; ++i) {
        int remain = bits - i * 8;
        if (remain <= 0) break;
        uint8_t mask = remain >= 8 ? 0xff : (uint8_t)(0xff << (8 - remain));
        if ((rule->addr.v6.s6_addr[i] & mask) != (addr[i] & mask)) return false;
    }
    return true;
}

static bool cidr_set_accepts(const struct cidr_set *set, int family, const unsigned char *addr)
{
    // 规则优先级：拒绝规则先命中先拒绝；如果存在允许规则，则必须命中其中之一。
    bool has_allow = false;
    bool allow_hit = false;

    for (size_t i = 0; i < set->len; ++i) {
        const struct cidr_rule *rule = &set->items[i];
        if (rule->family != family) continue;
        bool hit = (family == AF_INET) ? cidr_match_v4(rule, addr) : cidr_match_v6(rule, addr);
        if (!hit) continue;
        if (rule->deny) return false;
        has_allow = true;
        allow_hit = true;
    }

    if (!has_allow) return true;
    return allow_hit;
}

static int hex_val(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool parse_proc_ipv4(const char *token, unsigned char out[4], uint16_t *port)
{
    char ip_hex[16] = {0};
    unsigned int p = 0;
    if (sscanf(token, "%8[0-9A-Fa-f]:%x", ip_hex, &p) != 2) return false;

    for (size_t i = 0; i < 4; ++i) {
        int hi = hex_val(ip_hex[i * 2]);
        int lo = hex_val(ip_hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[3 - i] = (unsigned char)((hi << 4) | lo);
    }
    *port = (uint16_t)p;
    return true;
}

static bool parse_proc_ipv6(const char *token, unsigned char out[16], uint16_t *port)
{
    char ip_hex[64] = {0};
    unsigned int p = 0;
    if (sscanf(token, "%32[0-9A-Fa-f]:%x", ip_hex, &p) != 2) return false;

    unsigned char raw[16] = {0};
    for (size_t i = 0; i < 16; ++i) {
        int hi = hex_val(ip_hex[i * 2]);
        int lo = hex_val(ip_hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        raw[i] = (unsigned char)((hi << 4) | lo);
    }

    for (size_t i = 0; i < 4; ++i) {
        out[i * 4 + 0] = raw[i * 4 + 3];
        out[i * 4 + 1] = raw[i * 4 + 2];
        out[i * 4 + 2] = raw[i * 4 + 1];
        out[i * 4 + 3] = raw[i * 4 + 0];
    }
    *port = (uint16_t)p;
    return true;
}

static bool parse_socket_token(int family, const char *token, unsigned char addr[16], uint16_t *port)
{
    // /proc/net 中的地址格式是十六进制、小端混排，需要单独解码。
    if (family == AF_INET) {
        unsigned char v4[4] = {0};
        if (!parse_proc_ipv4(token, v4, port)) return false;
        memset(addr, 0, 16);
        memcpy(addr, v4, 4);
        return true;
    }
    return parse_proc_ipv6(token, addr, port);
}

static int owner_cmp_inode(const void *a, const void *b)
{
    const struct proc_owner *lhs = a;
    const struct proc_owner *rhs = b;
    if (lhs->inode < rhs->inode) return -1;
    if (lhs->inode > rhs->inode) return 1;
    return 0;
}

static const struct proc_owner *owner_find(const struct proc_owner *owners, size_t len, unsigned long long inode)
{
    struct proc_owner needle = {.inode = inode};
    return bsearch(&needle, owners, len, sizeof(*owners), owner_cmp_inode);
}

static bool inode_owner_add(struct proc_owner **owners, size_t *len, size_t *cap,
                            unsigned long long inode, pid_t pid, uid_t uid,
                            uint64_t cr_id, uint32_t cr_pid, const char *comm)
{
    for (size_t i = 0; i < *len; ++i) {
        if ((*owners)[i].inode == inode) return true;
    }
    if (*len >= PROC_OWNER_MAX_ITEMS) return true;
    if (*len == *cap) {
        size_t next_cap = *cap ? *cap * 2 : 1024;
        struct proc_owner *next = realloc(*owners, next_cap * sizeof(**owners));
        if (!next) return false;
        *owners = next;
        *cap = next_cap;
    }
    (*owners)[*len].inode = inode;
    (*owners)[*len].pid = pid;
    (*owners)[*len].uid = uid;
    (*owners)[*len].cr_id = cr_id;
    (*owners)[*len].cr_pid = cr_pid;
    strncpy((*owners)[*len].comm, comm, COMM_LEN - 1);
    (*owners)[*len].comm[COMM_LEN - 1] = '\0';
    (*len)++;
    return true;
}

static bool read_uid_file(pid_t pid, uid_t *uid)
{
    // 从 /proc/<pid>/status 读取真实 UID，用作用户身份回填。
    // 这里直接读取内核导出的真实用户 ID，不做任何推断，避免把 euid/fsuid 之类的值混进来。
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return false;

    char line[256];
    bool ok = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Uid:", 4) != 0) continue;
        unsigned int real_uid = 0;
        if (sscanf(line + 4, "%u", &real_uid) == 1) {
            *uid = (uid_t)real_uid;
            ok = true;
        }
        break;
    }

    fclose(fp);
    return ok;
}

static bool read_cr_pid_file(pid_t pid, uint32_t *cr_pid)
{
    // 从 NSpid 行读取最内层 PID，也就是容器视角下的 pid。
    // NSpid 里可能包含多级 namespace 的 pid；最右侧那个值才是当前 namespace 看到的 pid。
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return false;

    char line[256];
    bool ok = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "NSpid:", 6) != 0) continue;
        char *cursor = line + 6;
        char *end = NULL;
        unsigned long long value = 0;
        while (*cursor) {
            while (*cursor == ' ' || *cursor == '\t') cursor++;
            if (*cursor == '\0' || *cursor == '\n') break;
            errno = 0;
            value = strtoull(cursor, &end, 10);
            if (errno || end == cursor) break;
            cursor = end;
            ok = true;
        }
        if (ok) {
            *cr_pid = (uint32_t)value;
        }
        break;
    }

    fclose(fp);
    return ok;
}

static bool read_cr_id_file(pid_t pid, uint64_t *cr_id)
{
    // 读取 /proc/<pid>/ns/pid 的 inode，作为容器 PID namespace 标识。
    // 这个 inode 对同一 namespace 是稳定的，适合做 cr_id 过滤键。
    char path[64];
    char link_target[128];
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);
    ssize_t n = readlink(path, link_target, sizeof(link_target) - 1);
    if (n <= 0) return false;
    link_target[n] = '\0';

    unsigned long long value = 0;
    if (sscanf(link_target, "pid:[%llu]", &value) != 1) return false;
    *cr_id = (uint64_t)value;
    return true;
}

static bool read_comm_file(pid_t pid, char comm[COMM_LEN])
{
    // 读取 /proc/<pid>/comm 作为进程名。
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return false;
    if (!fgets(comm, COMM_LEN, fp)) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    comm[strcspn(comm, "\n")] = '\0';
    return true;
}

static bool build_inode_owners(struct proc_owner **owners_out, size_t *owners_len_out)
{
    // 扫描 /proc：先拿到进程基础信息，再遍历 fd 收集 socket inode，形成 inode -> owner 映射。
    // 这一步是 userspace 兜底索引，目标是把“socket 属于谁”尽量恢复出来。
    DIR *proc = opendir("/proc");
    if (!proc) return false;

    struct proc_owner *owners = NULL;
    size_t owners_len = 0, owners_cap = 0;

    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        char *end = NULL;
        long pid_long = strtol(de->d_name, &end, 10);
        if (!end || *end != '\0' || pid_long <= 0) continue;
        pid_t pid = (pid_t)pid_long;

        char comm[COMM_LEN] = {0};
        if (!read_comm_file(pid, comm)) continue;

        uid_t uid = 0;
        if (!read_uid_file(pid, &uid)) continue;

        uint32_t cr_pid = 0;
        uint64_t cr_id = 0;
        if (!read_cr_pid_file(pid, &cr_pid)) continue;
        if (!read_cr_id_file(pid, &cr_id)) continue;

        char fd_dir[64];
        snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
        DIR *fds = opendir(fd_dir);
        if (!fds) continue;

        struct dirent *fd_de;
        while ((fd_de = readdir(fds)) != NULL) {
            if (fd_de->d_name[0] == '.') continue;
            char link_path[128];
            char link_target[128];
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir, fd_de->d_name);
            ssize_t n = readlink(link_path, link_target, sizeof(link_target) - 1);
            if (n <= 0) continue;
            link_target[n] = '\0';
            unsigned long long inode = 0;
            if (sscanf(link_target, "socket:[%llu]", &inode) == 1 && inode > 0) {
                if (!inode_owner_add(&owners, &owners_len, &owners_cap, inode, pid, uid, cr_id, cr_pid, comm)) {
                    closedir(fds);
                    closedir(proc);
                    free(owners);
                    return false;
                }
            }
        }
        closedir(fds);
    }

    closedir(proc);
    qsort(owners, owners_len, sizeof(*owners), owner_cmp_inode);
    *owners_out = owners;
    *owners_len_out = owners_len;
    return true;
}

static bool socket_cache_push(struct socket_cache *cache, const struct socket_meta *meta)
{
    // 把解析得到的 socket 元数据塞进 cache，后续用于回退匹配。
    if (cache->max_items > 0 && cache->len >= cache->max_items) {
        return true;
    }
    if (cache->len == cache->cap) {
        size_t next_cap = cache->cap ? cache->cap * 2 : 1024;
        struct socket_meta *next = malloc(next_cap * sizeof(*next));
        size_t *next_idx = malloc(next_cap * sizeof(*next_idx));
        if (!next || !next_idx) {
            free(next);
            free(next_idx);
            return false;
        }
        if (cache->items) memcpy(next, cache->items, cache->len * sizeof(*next));
        if (cache->next_idx) memcpy(next_idx, cache->next_idx, cache->len * sizeof(*next_idx));
        free(cache->items);
        free(cache->next_idx);
        cache->items = next;
        cache->next_idx = next_idx;
        cache->cap = next_cap;
    }
    size_t bucket = socket_cache_hash_key(meta->family, meta->proto,
                                          meta->saddr, meta->daddr,
                                          meta->sport, meta->dport);
    cache->items[cache->len] = *meta;
    cache->next_idx[cache->len] = cache->buckets[bucket];
    cache->buckets[bucket] = cache->len;
    cache->len++;
    return true;
}

static bool parse_proc_net_table(const char *path, int family, int proto,
                                 const struct proc_owner *owners, size_t owners_len,
                                 struct socket_cache *cache)
{
    // 从 /proc/net/tcp* 和 /proc/net/udp* 解析 socket 视图，补齐 address/port/inode 对应关系。
    // 这里拿到的是系统当前的 socket 快照，不是网络包本身；它主要用于 BPF map 缺失时的回填。
    FILE *fp = fopen(path, "r");
    if (!fp) return false;

    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    while ((nread = getline(&line, &cap, fp)) != -1) {
        (void)nread;
        char *save = NULL;
        char *tok = strtok_r(line, " \t\n", &save);
        if (!tok || !strchr(tok, ':')) continue;

        unsigned char local_addr[16] = {0};
        unsigned char remote_addr[16] = {0};
        uint16_t local_port = 0;
        uint16_t remote_port = 0;
        unsigned long long inode = 0;

        int column = 0;
        while ((tok = strtok_r(NULL, " \t\n", &save)) != NULL) {
            ++column;
            if (column == 1) {
                if (!parse_socket_token(family, tok, local_addr, &local_port)) goto next_line;
            } else if (column == 2) {
                if (!parse_socket_token(family, tok, remote_addr, &remote_port)) goto next_line;
            } else if (column == 9) {
                inode = strtoull(tok, NULL, 10);
            }
        }

        if (inode == 0) goto next_line;

        struct socket_meta meta;
        memset(&meta, 0, sizeof(meta));
        meta.family = family;
        meta.proto = proto;
        // 把本地地址、对端地址、本地端口、对端端口都留住，后面可以直接和 packet 里的五元组做比对。
        memcpy(meta.saddr, local_addr, 16);
        memcpy(meta.daddr, remote_addr, 16);
        meta.sport = local_port;
        meta.dport = remote_port;
        meta.inode = inode;

        const struct proc_owner *owner = owner_find(owners, owners_len, inode);
        if (owner) {
            // 如果 inode 能匹配到进程 owner，就把宿主 pid、容器 pid、namespace id 和 comm 一起补齐。
            meta.pid = owner->pid;
            meta.uid = owner->uid;
            meta.cr_id = owner->cr_id;
            meta.cr_pid = owner->cr_pid;
            strncpy(meta.comm, owner->comm, COMM_LEN - 1);
            meta.comm[COMM_LEN - 1] = '\0';
        }

        if (!socket_cache_push(cache, &meta)) {
            free(line);
            fclose(fp);
            return false;
        }

    next_line:
        ;
    }

    free(line);
    fclose(fp);
    return true;
}

static bool rebuild_socket_cache(struct socket_cache *cache)
{
    // 重新构建 socket cache：先整理 inode owner，再遍历各类 /proc/net 表项。
    // 这个步骤相当于重新建立一份“socket -> owner”的索引表，后面解析包时就能直接查。
    struct proc_owner *owners = NULL;
    size_t owners_len = 0;
    if (!build_inode_owners(&owners, &owners_len)) {
        free(owners);
        return false;
    }

    socket_cache_reset(cache);
    if (cache->max_items == 0) cache->max_items = SOCKET_CACHE_MAX_ITEMS;

    bool ok = true;
    ok &= parse_proc_net_table("/proc/net/tcp", AF_INET, IPPROTO_TCP, owners, owners_len, cache);
    ok &= parse_proc_net_table("/proc/net/tcp6", AF_INET6, IPPROTO_TCP, owners, owners_len, cache);
    ok &= parse_proc_net_table("/proc/net/udp", AF_INET, IPPROTO_UDP, owners, owners_len, cache);
    ok &= parse_proc_net_table("/proc/net/udp6", AF_INET6, IPPROTO_UDP, owners, owners_len, cache);

    free(owners);
    cache->last_refresh_ms = now_ms();
    return ok;
}

static const struct socket_meta *socket_cache_lookup_directional(const struct socket_cache *cache,
                                                                 const struct event_t *e)
{
    // 根据 direction 先做哈希定位，把查找复杂度从 O(n) 收敛到近似 O(1)。
    if (!cache->items || !cache->next_idx || cache->len == 0) return NULL;
    size_t addr_len = e->family == AF_INET ? 4 : 16;
    const unsigned char *saddr = e->direction == 1 ? e->saddr : e->daddr;
    const unsigned char *daddr = e->direction == 1 ? e->daddr : e->saddr;
    uint16_t sport = e->direction == 1 ? e->sport : e->dport;
    uint16_t dport = e->direction == 1 ? e->dport : e->sport;
    size_t bucket = socket_cache_hash_key(e->family, e->l4_proto, saddr, daddr, sport, dport);

    for (size_t idx = cache->buckets[bucket]; idx != (size_t)-1; idx = cache->next_idx[idx]) {
        const struct socket_meta *m = &cache->items[idx];
        if (m->family != e->family || m->proto != e->l4_proto) continue;
        if (m->sport != sport || m->dport != dport) continue;
        if (memcmp(m->saddr, saddr, addr_len) != 0) continue;
        if (memcmp(m->daddr, daddr, addr_len) != 0) continue;
        return m;
    }
    return NULL;
}

static const struct socket_meta *socket_cache_lookup_listener(const struct socket_cache *cache,
                                                              const struct event_t *e)
{
    // 查监听 socket：主要用于 accept 场景，把连接归到监听进程。
    if (e->l4_proto != IPPROTO_TCP) return NULL;

    uint16_t listen_port = e->direction == 0 ? e->dport : e->sport;

    for (size_t i = 0; i < cache->len; ++i) {
        const struct socket_meta *m = &cache->items[i];
        bool family_match = m->family == e->family || (e->family == AF_INET && m->family == AF_INET6);
        if (!family_match || m->proto != e->l4_proto) continue;
        if (m->sport != listen_port) continue;
        if (m->dport != 0) continue;
        return m;
    }
    return NULL;
}

static void flow_owner_key_from_event(const struct event_t *e, bool reverse,
                                      struct flow_owner_key *key)
{
    // 把 packet 事件转换成 BPF map lookup key，reverse 用来在请求/响应方向之间切换。
    memset(key, 0, sizeof(*key));
    key->family = e->family;
    key->l4_proto = e->l4_proto;

    size_t addr_len = e->family == AF_INET ? 4 : 16;
    if (reverse) {
        memcpy(key->saddr, e->daddr, addr_len);
        memcpy(key->daddr, e->saddr, addr_len);
        key->sport = e->dport;
        key->dport = e->sport;
    } else {
        memcpy(key->saddr, e->saddr, addr_len);
        memcpy(key->daddr, e->daddr, addr_len);
        key->sport = e->sport;
        key->dport = e->dport;
    }
}

static bool flow_owner_map_lookup(const struct zwbee_state *state,
                                  const struct event_t *e,
                                  struct socket_meta *meta)
{
    // 优先查 BPF 侧 map，失败后再走 userspace 缓存回填。
    // BPF 侧的信息通常最接近真实执行上下文，因此这里优先级最高。
    if (state->flow_owner_map_fd < 0) return false;

    struct flow_owner_key key;
    struct flow_owner_value value;

    if (e->direction == 1) {
        flow_owner_key_from_event(e, false, &key);
    } else {
        flow_owner_key_from_event(e, true, &key);
    }
    if (bpf_map_lookup_elem(state->flow_owner_map_fd, &key, &value) != 0) return false;

    memset(meta, 0, sizeof(*meta));
    meta->family = e->family;
    meta->proto = e->l4_proto;
    meta->sport = e->sport;
    meta->dport = e->dport;
    meta->pid = (pid_t)(value.pid_tgid >> 32);
    meta->uid = (uid_t)value.uid;
    meta->cr_id = value.cr_id;
    meta->cr_pid = value.cr_pid;
    strncpy(meta->comm, value.comm, COMM_LEN - 1);
    meta->comm[COMM_LEN - 1] = '\0';
    return true;
}

static const struct socket_meta *resolve_packet_meta(const struct zwbee_state *state,
                                                     const struct event_t *e,
                                                     struct socket_meta *scratch)
{
    // 元数据解析优先级：BPF map -> 监听 socket -> /proc socket cache。
    // 这个顺序是为了尽量先拿到最准确的归属，再退回到更慢但更稳的 userspace 快照。
    if (flow_owner_map_lookup(state, e, scratch)) return scratch;

    if (e->l4_proto == IPPROTO_TCP) {
        const struct socket_meta *listener = socket_cache_lookup_listener(&state->sockets, e);
        if (listener && listener->pid > 0) {
            *scratch = *listener;
            return scratch;
        }
    }

    const struct socket_meta *cached = socket_cache_lookup_directional(&state->sockets, e);
    if (cached) {
        *scratch = *cached;
        return scratch;
    }

    if (e->l4_proto == IPPROTO_TCP) {
        const struct socket_meta *listener = socket_cache_lookup_listener(&state->sockets, e);
        if (listener) {
            *scratch = *listener;
            return scratch;
        }
    }
    return NULL;
}

static void flow_reverse_key(const struct event_t *e, struct flow_key *key)
{
    // 反向 key 用于在请求/响应两个方向之间共享 owner 和 domain 等上下文。
    memset(key, 0, sizeof(*key));
    key->family = e->family;
    key->l4_proto = e->l4_proto;
    key->direction = e->direction == 0 ? 1 : 0;

    size_t addr_len = e->family == AF_INET ? 4 : 16;
    memcpy(key->saddr, e->daddr, addr_len);
    memcpy(key->daddr, e->saddr, addr_len);
    key->sport = e->dport;
    key->dport = e->sport;
}

static void json_escape_file(FILE *out, const unsigned char *data, size_t len)
{
    // JSON 字符串转义，避免控制字符破坏输出格式。
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = data[i];
        switch (c) {
        case '"': fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\b': fputs("\\b", out); break;
        case '\f': fputs("\\f", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        default:
            if (c < 0x20 || c > 0x7e) {
                fprintf(out, "\\u%04x", c);
            } else {
                fputc(c, out);
            }
        }
    }
}

static bool is_http_request_start(const unsigned char *data, size_t len)
{
    // 只做报文起始行识别，不完整时宁可继续缓存，也不要误判。
    if (len < 4) return false;
    return (!memcmp(data, "GET ", 4) || !memcmp(data, "POST", 4) || !memcmp(data, "HEAD", 4) ||
            !memcmp(data, "PUT ", 4) || !memcmp(data, "DELE", 4) || !memcmp(data, "OPTI", 4) ||
            !memcmp(data, "PATC", 4) || !memcmp(data, "CONN", 4) || !memcmp(data, "TRAC", 4));
}

static bool is_http_response_start(const unsigned char *data, size_t len)
{
    // HTTP 响应统一以 HTTP/ 开头。
    return len >= 5 && !memcmp(data, "HTTP/", 5);
}

static const unsigned char *find_bytes(const unsigned char *hay, size_t hay_len,
                                       const char *needle, size_t needle_len)
{
    if (needle_len == 0 || hay_len < needle_len) return NULL;
    for (size_t i = 0; i + needle_len <= hay_len; ++i) {
        if (memcmp(hay + i, needle, needle_len) == 0) return hay + i;
    }
    return NULL;
}

static size_t find_header_end(const unsigned char *data, size_t len)
{
    // HTTP header 和 body 的分隔符是空行，即 \r\n\r\n。
    const unsigned char *p = find_bytes(data, len, "\r\n\r\n", 4);
    if (!p) return 0;
    return (size_t)(p - data) + 4;
}

static void extract_header_value(const unsigned char *headers, size_t len, const char *name,
                                char *out, size_t out_len)
{
    // 从原始 header 块里提取指定头字段，例如 Host 或 Content-Length。
    out[0] = '\0';
    size_t name_len = strlen(name);
    for (size_t off = 0; off + name_len < len; ++off) {
        if (strncasecmp((const char *)headers + off, name, name_len) != 0) continue;
        const unsigned char *p = headers + off + name_len;
        while (p < headers + len && (*p == ' ' || *p == '\t' || *p == ':')) p++;
        const unsigned char *end = p;
        while (end < headers + len && *end != '\r' && *end != '\n') end++;
        size_t copy_len = (size_t)(end - p);
        if (copy_len >= out_len) copy_len = out_len - 1;
        memcpy(out, p, copy_len);
        out[copy_len] = '\0';
        return;
    }
}

static int parse_content_length_header(const unsigned char *headers, size_t len)
{
    // 解析 Content-Length，失败则返回 -1。
    const char *needle = "Content-Length:";
    const unsigned char *p = find_bytes(headers, len, needle, strlen(needle));
    if (!p) return -1;
    p += strlen(needle);
    while (p < headers + len && isspace(*p)) p++;
    int value = 0;
    bool found = false;

    while (p < headers + len && isdigit(*p)) {
        found = true;
        value = value * 10 + (*p - '0');
        p++;
    }
    return found ? value : -1;
}

static bool header_has_chunked_encoding(const unsigned char *headers, size_t len)
{
    // 判断 Transfer-Encoding 是否包含 chunked。
    const char *needle = "Transfer-Encoding:";
    const unsigned char *p = find_bytes(headers, len, needle, strlen(needle));
    if (!p) return false;
    p += strlen(needle);
    while (p < headers + len && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    while (p < headers + len && *p != '\r' && *p != '\n') {
        if (strncasecmp((const char *)p, "chunked", 7) == 0) return true;
        p++;
    }
    return false;
}

static bool parse_chunked_body(const unsigned char *data, size_t len, long long body_limit,
                               unsigned char **body_copy_out, size_t *body_len_out,
                               size_t *consumed_out)
{
    // chunked body 解析器：按块读取、按需保留、遇到不完整数据就返回 false。
    // 注意 consumed 表示“这条 HTTP 在流缓冲里应该前进多少字节”，不是仅仅表示 body 长度。
    *body_copy_out = NULL;
    *body_len_out = 0;
    *consumed_out = 0;

    size_t keep_limit = 0;
    if (body_limit < 0) {
        keep_limit = 0;
    } else if (body_limit == 0) {
        keep_limit = SIZE_MAX;
    } else {
        keep_limit = (size_t)body_limit;
    }

    unsigned char *keep = NULL;
    size_t keep_len = 0;
    size_t keep_cap = 0;
    size_t pos = 0;

    for (;;) {
        const unsigned char *line_end = find_bytes(data + pos, len - pos, "\r\n", 2);
        if (!line_end) {
            free(keep);
            return false;
        }

        size_t line_len = (size_t)(line_end - (data + pos));
        if (line_len == 0) {
            free(keep);
            return false;
        }

        char size_buf[32];
        size_t copy_len = line_len < sizeof(size_buf) - 1 ? line_len : sizeof(size_buf) - 1;
        memcpy(size_buf, data + pos, copy_len);
        size_buf[copy_len] = '\0';
        char *semi = strchr(size_buf, ';');
        if (semi) *semi = '\0';

        errno = 0;
        char *endptr = NULL;
        unsigned long chunk_size = strtoul(size_buf, &endptr, 16);
        if (endptr == size_buf || errno != 0) {
            free(keep);
            return false;
        }

        pos += line_len + 2;
        if (chunk_size == 0) {
            if (len - pos >= 2 && data[pos] == '\r' && data[pos + 1] == '\n') {
                pos += 2;
            } else {
                const unsigned char *trail_end = find_bytes(data + pos, len - pos, "\r\n\r\n", 4);
                if (!trail_end) {
                    free(keep);
                    return false;
                }
                pos = (size_t)(trail_end - data) + 4;
            }
            break;
        }

        if (len - pos < chunk_size + 2) {
            free(keep);
            return false;
        }

        size_t chunk_copy = 0;
        if (keep_limit > 0) {
            if (keep_limit == SIZE_MAX) {
                chunk_copy = (size_t)chunk_size;
            } else if (keep_len < keep_limit) {
                chunk_copy = (size_t)chunk_size;
                if (chunk_copy > keep_limit - keep_len) chunk_copy = keep_limit - keep_len;
            }
        }

        if (chunk_copy > 0) {
            if (keep_len + chunk_copy > keep_cap) {
                size_t next_cap = keep_cap ? keep_cap * 2 : 1024;
                while (next_cap < keep_len + chunk_copy) next_cap *= 2;
                unsigned char *next = realloc(keep, next_cap);
                if (!next) {
                    free(keep);
                    return false;
                }
                keep = next;
                keep_cap = next_cap;
            }
            memcpy(keep + keep_len, data + pos, chunk_copy);
            keep_len += chunk_copy;
        }

        pos += chunk_size;
        if (data[pos] != '\r' || data[pos + 1] != '\n') {
            free(keep);
            return false;
        }
        pos += 2;
    }

    *body_copy_out = keep;
    *body_len_out = keep_len;
    *consumed_out = pos;
    return true;
}

static bool parse_tls_clienthello(const unsigned char *data, uint32_t len,
                                  char *sni, size_t sni_len,
                                  char *alpn, size_t alpn_len,
                                  uint16_t *tls_version_out)
{
    // 解析 TLS ClientHello：提取 SNI、ALPN 和协商版本。
    // 这里只读明文握手层，所以即便 HTTPS 正文不可见，仍然可以恢复域名和 ALPN。
    sni[0] = '\0';
    alpn[0] = '\0';

    if (len < 5) return false;
    if (data[0] != 0x16) return false;

    uint16_t record_version = (uint16_t)((data[1] << 8) | data[2]);
    uint16_t record_len = (uint16_t)((data[3] << 8) | data[4]);
    if (tls_version_out) *tls_version_out = record_version;
    if ((uint32_t)record_len + 5U > len) return false;

    if (len < 9) return false;
    const unsigned char *p = data + 5;
    if (p[0] != 0x01) return false;
    uint32_t hello_len = ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    const unsigned char *hello_end = p + 4 + hello_len;
    if (hello_end > data + 5 + record_len) return false;

    if (5 + 4 + 2 + 32 > len) return false;
    const unsigned char *q = p + 4 + 2 + 32;
    if (q + 1 > hello_end) return false;

    uint8_t sid_len = q[0];
    q += 1 + sid_len;
    if (q + 2 > hello_end) return false;

    uint16_t cs_len = (uint16_t)((q[0] << 8) | q[1]);
    q += 2 + cs_len;
    if (q + 1 > hello_end) return false;

    uint8_t comp_len = q[0];
    q += 1 + comp_len;
    if (q + 2 > hello_end) return false;

    uint16_t ext_len = (uint16_t)((q[0] << 8) | q[1]);
    q += 2;
    const unsigned char *ext_end = q + ext_len;
    if (ext_end > hello_end) return false;

    while (q + 4 <= ext_end) {
        uint16_t ext_type = (uint16_t)((q[0] << 8) | q[1]);
        uint16_t ext_size = (uint16_t)((q[2] << 8) | q[3]);
        q += 4;
        if (q + ext_size > ext_end) break;

        if (ext_type == 0x0000) {
            const unsigned char *es = q;
            if (es + 2 <= q + ext_size) {
                es += 2;
                const unsigned char *es_end = q + ext_size;
                while (es + 3 <= es_end) {
                    uint8_t name_type = es[0];
                    uint16_t name_len = (uint16_t)((es[1] << 8) | es[2]);
                    es += 3;
                    if (es + name_len > es_end) break;
                    if (name_type == 0) {
                        size_t cp = name_len < sni_len - 1 ? name_len : sni_len - 1;
                        memcpy(sni, es, cp);
                        sni[cp] = '\0';
                    }
                    es += name_len;
                }
            }
        } else if (ext_type == 0x0010) {
            const unsigned char *es = q;
            if (es + 2 <= q + ext_size) {
                es += 2;
                const unsigned char *es_end = q + ext_size;
                if (es + 1 <= es_end) {
                    uint8_t proto_len = es[0];
                    if (es + 1 + proto_len <= es_end) {
                        size_t cp = proto_len < alpn_len - 1 ? proto_len : alpn_len - 1;
                        memcpy(alpn, es + 1, cp);
                        alpn[cp] = '\0';
                    }
                }
            }
        } else if (ext_type == 0x002b) {
            if (ext_size >= 3) {
                uint8_t versions_len = q[0];
                const unsigned char *versions = q + 1;
                const unsigned char *versions_end = versions + versions_len;
                uint16_t best = 0;
                if (versions_end > q + ext_size) versions_end = q + ext_size;
                while (versions + 1 < versions_end) {
                    uint16_t candidate = (uint16_t)((versions[0] << 8) | versions[1]);
                    if (candidate > best) best = candidate;
                    versions += 2;
                }
                if (best != 0 && tls_version_out) *tls_version_out = best;
            }
        }

        q += ext_size;
    }

    return true;
}

static bool parse_tls_serverhello(const unsigned char *data, uint32_t len,
                                  char *alpn, size_t alpn_len,
                                  uint16_t *tls_version_out)
{
    // 解析 TLS ServerHello：提取 ALPN 和协商版本。
    // response 侧没有 SNI，因此最终输出域名通常要靠 request 方向缓存下来的 domain 兜底。
    alpn[0] = '\0';
    if (len < 5 || data[0] != 0x16) return false;

    uint16_t record_version = (uint16_t)((data[1] << 8) | data[2]);
    uint16_t record_len = (uint16_t)((data[3] << 8) | data[4]);
    if (tls_version_out) *tls_version_out = record_version;
    if ((uint32_t)record_len + 5U > len) return false;

    if (len < 9) return false;
    const unsigned char *p = data + 5;
    if (p[0] != 0x02) return false;
    uint32_t hello_len = ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    const unsigned char *hello_end = p + 4 + hello_len;
    if (hello_end > data + 5 + record_len) return false;

    const unsigned char *q = p + 4;
    if (q + 2 + 32 + 1 > hello_end) return false;
    q += 2 + 32;
    uint8_t sid_len = q[0];
    q += 1 + sid_len;
    if (q + 2 + 1 + 2 > hello_end) return false;
    q += 2 + 1;
    uint16_t ext_len = (uint16_t)((q[0] << 8) | q[1]);
    q += 2;
    const unsigned char *ext_end = q + ext_len;
    if (ext_end > hello_end) return false;

    while (q + 4 <= ext_end) {
        uint16_t ext_type = (uint16_t)((q[0] << 8) | q[1]);
        uint16_t ext_size = (uint16_t)((q[2] << 8) | q[3]);
        q += 4;
        if (q + ext_size > ext_end) break;

        if (ext_type == 0x0010) {
            if (ext_size >= 3) {
                uint16_t list_len = (uint16_t)((q[0] << 8) | q[1]);
                const unsigned char *es = q + 2;
                const unsigned char *es_end = q + 2 + list_len;
                if (es_end > q + ext_size) es_end = q + ext_size;
                if (es + 1 <= es_end) {
                    uint8_t proto_len = es[0];
                    if (es + 1 + proto_len <= es_end) {
                        size_t cp = proto_len < alpn_len - 1 ? proto_len : alpn_len - 1;
                        memcpy(alpn, es + 1, cp);
                        alpn[cp] = '\0';
                    }
                }
            }
        } else if (ext_type == 0x002b) {
            if (ext_size >= 2) {
                uint16_t negotiated = (uint16_t)((q[0] << 8) | q[1]);
                if (tls_version_out) *tls_version_out = negotiated;
            }
        }

        q += ext_size;
    }

    return true;
}

static const char *tls_version_name(uint16_t v)
{
    // 把 TLS 版本号转换成可读字符串。
    switch (v) {
    case 0x0301: return "TLS 1.0";
    case 0x0302: return "TLS 1.1";
    case 0x0303: return "TLS 1.2";
    case 0x0304: return "TLS 1.3";
    default: return "";
    }
}

static const char *http_version_from_alpn(const char *alpn)
{
    // 根据 ALPN 推断 HTTP 版本描述。
    if (!alpn || !*alpn) return "";
    if (!strcmp(alpn, "h2")) return "HTTP/2";
    if (!strcmp(alpn, "h3")) return "HTTP/3";
    if (!strcmp(alpn, "http/1.1")) return "HTTP/1.1";
    if (!strcmp(alpn, "http/1.0")) return "HTTP/1.0";
    return alpn;
}

static int parse_quic_varint(const unsigned char *p, uint32_t len,
                             uint64_t *value, uint32_t *consumed)
{
    // QUIC 变长整数解码，用于跳过包头字段。
    if (len < 1) return 0;
    uint8_t lead = p[0] >> 6;
    uint32_t n = 1U << lead;
    if (n > len) return 0;
    uint64_t v = p[0] & 0x3f;
    for (uint32_t i = 1; i < n; ++i) v = (v << 8) | p[i];
    *value = v;
    *consumed = n;
    return 1;
}

static int find_quic_tls_payload(const unsigned char *data, uint32_t len,
                                 const unsigned char **out, uint32_t *out_len)
{
    // 从 QUIC Initial 包里尝试定位 TLS payload，不做完整解密，只做结构跳转。
    if (len < 6) return 0;
    if ((data[0] & 0x80) == 0) return 0;

    uint32_t pos = 1;
    if (pos + 4 > len) return 0;
    pos += 4;

    if (pos + 1 > len) return 0;
    uint8_t dcid_len = data[pos++];
    if (pos + dcid_len > len) return 0;
    pos += dcid_len;

    if (pos + 1 > len) return 0;
    uint8_t scid_len = data[pos++];
    if (pos + scid_len > len) return 0;
    pos += scid_len;

    uint64_t token_len = 0;
    uint32_t token_len_bytes = 0;
    if (!parse_quic_varint(data + pos, len - pos, &token_len, &token_len_bytes)) return 0;
    pos += token_len_bytes;
    if (pos + token_len > len) return 0;
    pos += (uint32_t)token_len;

    uint64_t payload_len = 0;
    uint32_t payload_len_bytes = 0;
    if (!parse_quic_varint(data + pos, len - pos, &payload_len, &payload_len_bytes)) return 0;
    pos += payload_len_bytes;
    if (pos > len) return 0;

    *out = data + pos;
    *out_len = len - pos;
    (void)payload_len;
    return 1;
}

struct http_message {
    bool response;
    char method[32];
    char path[1024];
    char status[256];
    char host[512];
    char version[64];
    size_t header_end;
    size_t body_len;
    size_t consumed;
    unsigned char *body_copy;
};

static void http_message_free(struct http_message *msg)
{
    // 释放 chunked body 解析时临时分配的 body_copy。
    free(msg->body_copy);
    msg->body_copy = NULL;
}

static bool parse_http_message(const unsigned char *data, size_t len, long long body_limit,
                               struct http_message *msg)
{
    // HTTP 报文解析主入口：识别请求/响应、解析头部、再根据 body 规则决定是否截取 body。
    // 这里的原则是：只要报文还不完整，就直接返回 false，让上层继续缓冲，不提前消费数据。
    memset(msg, 0, sizeof(*msg));

    if (len < 4) return false;
    bool is_resp = is_http_response_start(data, len);
    bool is_req = is_http_request_start(data, len);
    if (!is_resp && !is_req) return false;

    size_t header_end = find_header_end(data, len);
    if (header_end == 0) return false;

    const unsigned char *headers = data;
    size_t headers_len = header_end;
    size_t body_available = len - header_end;

    char *headers_copy = strndup((const char *)headers, headers_len);
    if (!headers_copy) return false;

    char *save = NULL;
    char *line = strtok_r(headers_copy, "\r\n", &save);
    if (!line) {
        free(headers_copy);
        return false;
    }

    if (is_resp) {
        msg->response = true;
        // 响应行一般形如 HTTP/1.1 200 OK，这里只拆版本和状态码，原因短语不作为结构化字段单独保存。
        char *sp1 = strchr(line, ' ');
        if (sp1) {
            size_t version_len = (size_t)(sp1 - line);
            if (version_len >= sizeof(msg->version)) version_len = sizeof(msg->version) - 1;
            memcpy(msg->version, line, version_len);
            msg->version[version_len] = '\0';
            while (*sp1 == ' ') sp1++;
            char *sp2 = strchr(sp1, ' ');
            size_t code_len = sp2 ? (size_t)(sp2 - sp1) : strlen(sp1);
            if (code_len >= sizeof(msg->status)) code_len = sizeof(msg->status) - 1;
            memcpy(msg->status, sp1, code_len);
            msg->status[code_len] = '\0';
        } else {
            strncpy(msg->version, line, sizeof(msg->version) - 1);
        }
    } else {
        // 请求行一般形如 METHOD SP PATH SP VERSION，这里只提取 method、path 和 version。
        char *sp1 = strchr(line, ' ');
        if (!sp1) {
            free(headers_copy);
            return false;
        }
        size_t method_len = (size_t)(sp1 - line);
        if (method_len >= sizeof(msg->method)) method_len = sizeof(msg->method) - 1;
        memcpy(msg->method, line, method_len);
        msg->method[method_len] = '\0';

        while (*sp1 == ' ') sp1++;
        char *sp2 = strchr(sp1, ' ');
        if (sp2) {
            size_t path_len = (size_t)(sp2 - sp1);
            if (path_len >= sizeof(msg->path)) path_len = sizeof(msg->path) - 1;
            memcpy(msg->path, sp1, path_len);
            msg->path[path_len] = '\0';
            strncpy(msg->version, sp2 + 1, sizeof(msg->version) - 1);
        }
    }

    int content_length = parse_content_length_header((const unsigned char *)headers, headers_len);
    bool chunked = header_has_chunked_encoding((const unsigned char *)headers, headers_len);
    extract_header_value((const unsigned char *)headers, headers_len, "Host:", msg->host, sizeof(msg->host));

    // 某些响应和请求天然没有 body，提前识别可以减少误判和等待。
    bool no_body_response = msg->response &&
        (strncmp(msg->status, "1", 1) == 0 || strncmp(msg->status, "204", 3) == 0 || strncmp(msg->status, "304", 3) == 0);
    bool no_body_request = !msg->response &&
        (!strcasecmp(msg->method, "GET") || !strcasecmp(msg->method, "HEAD") ||
         !strcasecmp(msg->method, "OPTIONS") || !strcasecmp(msg->method, "TRACE"));

    msg->header_end = header_end;
    msg->body_len = 0;
    msg->body_copy = NULL;

    if (!no_body_request && !no_body_response) {
        if (chunked) {
            // chunked body 需要先拼接块；如果 body_limit < 0，则只保留协议骨架，不保留 body。
            // 也就是说，这里仍然要判断“这条 HTTP 是否完整”，只是 body 内容不记录。
            if (body_limit < 0) {
                msg->body_len = 0;
                msg->consumed = header_end;
                free(headers_copy);
                return true;
            }

            size_t chunked_consumed = 0;
            if (parse_chunked_body(data + header_end, len - header_end, body_limit,
                                   &msg->body_copy, &msg->body_len, &chunked_consumed)) {
                msg->consumed = header_end + chunked_consumed;
                if (msg->consumed > len) msg->consumed = len;
                free(headers_copy);
                return true;
            }
            free(headers_copy);
            return false;
        }

        // 非 chunked 时，根据 Content-Length / 已见字节数 / body_limit 决定保留多少。
        // 如果 body 还没到齐，返回 false，把半包留在缓冲里，等下一次 TCP 分段继续拼。
        size_t body_to_keep = 0;
        if (body_limit < 0) {
            body_to_keep = 0;
        } else if (body_limit == 0) {
            if (content_length >= 0) {
                if (body_available < (size_t)content_length) {
                    free(headers_copy);
                    return false;
                }
                body_to_keep = (size_t)content_length;
            } else {
                body_to_keep = body_available;
            }
        } else {
            size_t target = body_available;
            if (content_length >= 0 && (size_t)content_length < target) target = (size_t)content_length;
            if ((size_t)body_limit < target) target = (size_t)body_limit;
            if (body_available < target) {
                free(headers_copy);
                return false;
            }
            body_to_keep = target;
        }

        msg->body_len = body_to_keep;
        if (content_length >= 0) {
            msg->consumed = header_end + (size_t)content_length;
        } else if (body_to_keep > 0) {
            msg->consumed = header_end + body_to_keep;
        } else {
            msg->consumed = header_end;
        }
        if (msg->consumed > len) msg->consumed = len;
    } else {
        msg->consumed = header_end;
    }

    free(headers_copy);
    return true;
}

static const char *transport_name(uint8_t proto)
{
    // 协议号转字符串。
    return proto == IPPROTO_UDP ? "udp" : "tcp";
}

static const char *family_name(int family)
{
    // 地址族转字符串。
    return family == AF_INET6 ? "ipv6" : "ipv4";
}

static void ip_to_string(int family, const unsigned char *addr, char *out, size_t out_len)
{
    // 把二进制地址转成可读字符串。
    if (!inet_ntop(family, addr, out, out_len)) {
        snprintf(out, out_len, "<invalid>");
    }
}

static bool emit_json_http(const struct event_t *e, const struct socket_meta *meta,
                           const struct http_message *msg,
                           const unsigned char *headers, size_t headers_len,
                           const unsigned char *body, size_t body_len)
{
    // HTTP 事件输出：把事件、元数据、headers/body 组装成一行 JSON。
    // 这层输出尽量保持字段顺序稳定，便于后续 grep、jq、日志平台和人工阅读。
    char *json = NULL;
    size_t json_len = 0;
    FILE *out = open_memstream(&json, &json_len);
    if (!out) return false;

    char src[INET6_ADDRSTRLEN] = {0};
    char dst[INET6_ADDRSTRLEN] = {0};
    char time_buf[32] = {0};
    char id_buf[25] = {0};
    char key_buf[17] = {0};
    uint64_t ms = epoch_ms();
    iso8601_ms(ms, time_buf, sizeof(time_buf));
    make_record_id(id_buf, ms);
    record_key_hex(e, meta, key_buf);
    ip_to_string(e->family, e->saddr, src, sizeof(src));
    ip_to_string(e->family, e->daddr, dst, sizeof(dst));

    fprintf(out, "{");
    fprintf(out, "\"id\":\""); json_escape_file(out, (const unsigned char *)id_buf, strlen(id_buf)); fprintf(out, "\",");
    fprintf(out, "\"ts\":%llu,", (unsigned long long)ms);
    fprintf(out, "\"time\":\""); json_escape_file(out, (const unsigned char *)time_buf, strlen(time_buf)); fprintf(out, "\",");
    fprintf(out, "\"key\":\""); json_escape_file(out, (const unsigned char *)key_buf, strlen(key_buf)); fprintf(out, "\",");
    fprintf(out, "\"family\":\"%s\",", family_name(e->family));
    fprintf(out, "\"transport\":\"%s\",", transport_name(e->l4_proto));
    fprintf(out, "\"direction\":\"%s\",", e->direction == 0 ? "ingress" : "egress");
    fprintf(out, "\"src_ip\":\""); json_escape_file(out, (const unsigned char *)src, strlen(src)); fprintf(out, "\",");
    fprintf(out, "\"src_port\":%u,", e->sport);
    fprintf(out, "\"dst_ip\":\""); json_escape_file(out, (const unsigned char *)dst, strlen(dst)); fprintf(out, "\",");
    fprintf(out, "\"dst_port\":%u,", e->dport);

    if (meta) {
        fprintf(out, "\"pid\":%d,", meta->pid);
        fprintf(out, "\"uid\":%u,", (unsigned int)meta->uid);
        fprintf(out, "\"cr_id\":%llu,", (unsigned long long)meta->cr_id);
        fprintf(out, "\"cr_pid\":%u,", meta->cr_pid);
        fprintf(out, "\"comm\":\""); json_escape_file(out, (const unsigned char *)meta->comm, strlen(meta->comm)); fprintf(out, "\",");
    } else {
        fprintf(out, "\"pid\":0,\"uid\":0,\"cr_id\":0,\"cr_pid\":0,\"comm\":\"\",");
    }

    fprintf(out, "\"domain\":\"");
    json_escape_file(out, (const unsigned char *)msg->host, strlen(msg->host));
    fprintf(out, "\",");
    fprintf(out, "\"proto\":\"http\",\"type\":\"");
    json_escape_file(out, (const unsigned char *)(msg->response ? "response" : "request"), msg->response ? 8 : 7);
    fprintf(out, "\",");
    fprintf(out, "\"http\":{");
    if (msg->response) {
        fprintf(out, "\"type\":\"response\",\"status\":\"");
        json_escape_file(out, (const unsigned char *)msg->status, strlen(msg->status));
        fprintf(out, "\",");
    } else {
        fprintf(out, "\"type\":\"request\",\"method\":\"");
        json_escape_file(out, (const unsigned char *)msg->method, strlen(msg->method));
        fprintf(out, "\",\"path\":\"");
        json_escape_file(out, (const unsigned char *)msg->path, strlen(msg->path));
        fprintf(out, "\",");
    }

    fprintf(out, "\"version\":\"");
    json_escape_file(out, (const unsigned char *)msg->version, strlen(msg->version));
    fprintf(out, "\",");
    fprintf(out, "\"payload_len\":%u,", e->payload_len);
    fprintf(out, "\"body_len\":%zu,", body_len);

    if (msg->host[0]) {
        fprintf(out, "\"host\":\"");
        json_escape_file(out, (const unsigned char *)msg->host, strlen(msg->host));
        fprintf(out, "\",");
    }

    fprintf(out, "\"headers_raw\":\"");
    json_escape_file(out, headers, headers_len);
    fprintf(out, "\"");

    if (body && body_len > 0) {
        fprintf(out, ",\"body\":\"");
        json_escape_file(out, body, body_len);
        fprintf(out, "\"");
    }

    fprintf(out, "}}\n");

    fclose(out);
    if (json && json_len > 0) {
        emit_json_line(json);
    }
    free(json);
    return true;
}

static bool emit_json_https(const struct event_t *e, const struct socket_meta *meta,
                            const char *type, const char *http_version, const char *tls_version,
                            const char *sni, const char *alpn, uint16_t record_version,
                            const unsigned char *payload, size_t payload_len,
                            const char *transport)
{
    // HTTPS 事件输出：保留握手元数据，不尝试解密 payload。
    // HTTPS 的正文通常是密文，所以这里重点保留的是握手层能直接观察到的明文元信息。
    char *json = NULL;
    size_t json_len = 0;
    FILE *out = open_memstream(&json, &json_len);
    if (!out) return false;

    char src[INET6_ADDRSTRLEN] = {0};
    char dst[INET6_ADDRSTRLEN] = {0};
    char time_buf[32] = {0};
    char id_buf[25] = {0};
    char key_buf[17] = {0};
    uint64_t ms = epoch_ms();
    iso8601_ms(ms, time_buf, sizeof(time_buf));
    make_record_id(id_buf, ms);
    record_key_hex(e, meta, key_buf);
    ip_to_string(e->family, e->saddr, src, sizeof(src));
    ip_to_string(e->family, e->daddr, dst, sizeof(dst));

    fprintf(out, "{");
    fprintf(out, "\"id\":\""); json_escape_file(out, (const unsigned char *)id_buf, strlen(id_buf)); fprintf(out, "\",");
    fprintf(out, "\"ts\":%llu,", (unsigned long long)ms);
    fprintf(out, "\"time\":\""); json_escape_file(out, (const unsigned char *)time_buf, strlen(time_buf)); fprintf(out, "\",");
    fprintf(out, "\"key\":\""); json_escape_file(out, (const unsigned char *)key_buf, strlen(key_buf)); fprintf(out, "\",");
    fprintf(out, "\"family\":\"%s\",", family_name(e->family));
    fprintf(out, "\"transport\":\"%s\",", transport);
    fprintf(out, "\"direction\":\"%s\",", e->direction == 0 ? "ingress" : "egress");
    fprintf(out, "\"src_ip\":\""); json_escape_file(out, (const unsigned char *)src, strlen(src)); fprintf(out, "\",");
    fprintf(out, "\"src_port\":%u,", e->sport);
    fprintf(out, "\"dst_ip\":\""); json_escape_file(out, (const unsigned char *)dst, strlen(dst)); fprintf(out, "\",");
    fprintf(out, "\"dst_port\":%u,", e->dport);

    if (meta) {
        fprintf(out, "\"pid\":%d,", meta->pid);
        fprintf(out, "\"uid\":%u,", (unsigned int)meta->uid);
        fprintf(out, "\"cr_id\":%llu,", (unsigned long long)meta->cr_id);
        fprintf(out, "\"cr_pid\":%u,", meta->cr_pid);
        fprintf(out, "\"comm\":\""); json_escape_file(out, (const unsigned char *)meta->comm, strlen(meta->comm)); fprintf(out, "\",");
    } else {
        fprintf(out, "\"pid\":0,\"uid\":0,\"cr_id\":0,\"cr_pid\":0,\"comm\":\"\",");
    }

    fprintf(out, "\"domain\":\"");
    json_escape_file(out, (const unsigned char *)sni, strlen(sni));
    fprintf(out, "\",");
    fprintf(out, "\"proto\":\"https\",\"type\":\"");
    json_escape_file(out, (const unsigned char *)type, strlen(type));
    fprintf(out, "\",");
    fprintf(out, "\"https\":{");
    fprintf(out, "\"type\":\"");
    json_escape_file(out, (const unsigned char *)type, strlen(type));
    fprintf(out, "\",");
    fprintf(out, "\"version\":\"");
    json_escape_file(out, (const unsigned char *)http_version, strlen(http_version));
    fprintf(out, "\",");
    fprintf(out, "\"tls_version\":\"");
    json_escape_file(out, (const unsigned char *)tls_version, strlen(tls_version));
    fprintf(out, "\",");
    fprintf(out, "\"domain\":\"");
    json_escape_file(out, (const unsigned char *)sni, strlen(sni));
    fprintf(out, "\",");
    fprintf(out, "\"payload_len\":%zu", payload_len);
    if (alpn && *alpn) {
        fprintf(out, ",\"alpn\":\"");
        json_escape_file(out, (const unsigned char *)alpn, strlen(alpn));
        fprintf(out, "\"");
    }
    if (record_version) {
        fprintf(out, ",\"tls_record_version\":%u", record_version);
    }
    fprintf(out, "}}\n");

    fclose(out);
    if (json && json_len > 0) {
        emit_json_line(json);
    }
    free(json);
    (void)payload;
    return true;
}

static bool looks_like_tls_record(const unsigned char *data, size_t len)
{
    // 通过 record layer 的 type/version 做轻量 TLS 识别。
    // 这里允许 handshake/ccs/alert/appdata 四类记录头，便于继续向后扫描真实握手消息。
    // 这里故意不做更严格的完整性判定，以便兼容从连接中途开始抓包的场景。
    if (len < 5 || data[1] != 0x03 || data[2] > 0x04) return false;
    return data[0] == 0x14 || data[0] == 0x15 || data[0] == 0x16 || data[0] == 0x17;
}

static ssize_t find_tls_handshake_record_offset(const unsigned char *data, size_t len, uint8_t handshake_type)
{
    // 某些服务端首包会在 ServerHello 前夹带 CCS 等兼容记录；
    // 这里按 TLS record 顺序向后走，直到找到目标握手类型，避免 response 因记录前缀不同而漏掉。
    if (len < 5) return -1;

    size_t max_scan = len - 5;
    if (max_scan > 128) max_scan = 128;

    for (size_t i = 0; i <= max_scan; ++i) {
        if (!looks_like_tls_record(data + i, len - i)) continue;

        size_t offset = i;
        for (size_t depth = 0; depth < 8 && offset + 5 <= len; ++depth) {
            const unsigned char *record = data + offset;
            if (!looks_like_tls_record(record, len - offset)) break;

            size_t record_len = (size_t)(((uint16_t)record[3] << 8) | record[4]);
            size_t total_len = 5 + record_len;
            if (offset + total_len > len) return -1;

            if (record[0] == 0x16 && record_len >= 4 && record[5] == handshake_type) {
                return (ssize_t)offset;
            }
            offset += total_len;
        }
    }
    return -1;
}

static bool parse_packet(const unsigned char *packet, size_t len, uint8_t direction,
                         struct event_t *e)
{
    // 原始二层包解析入口：逐层剥离以太网、VLAN、IP、TCP/UDP 头，只保留 payload。
    // userspace 这里不再做“是否目标协议”的粗筛；这部分已经提前在 capture_prog 里完成。
    memset(e, 0, sizeof(*e));
    e->direction = direction;

    if (len < sizeof(struct ethhdr)) return false;
    const unsigned char *cursor = packet;
    const unsigned char *end = packet + len;

    const struct ethhdr *eth = (const struct ethhdr *)cursor;
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    cursor += sizeof(*eth);

    if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
        struct vlan_hdr_local {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        };
        if (cursor + sizeof(struct vlan_hdr_local) > end) return false;
        const struct vlan_hdr_local *vh = (const struct vlan_hdr_local *)cursor;
        h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
        cursor += sizeof(*vh);
    }

    if (h_proto == ETH_P_IP) {
        if (cursor + sizeof(struct iphdr) > end) return false;
        const struct iphdr *iph = (const struct iphdr *)cursor;
        if (iph->ihl < 5) return false;
        size_t ip_hdr_len = (size_t)iph->ihl * 4;
        if (cursor + ip_hdr_len > end) return false;

        e->family = AF_INET;
        memcpy(e->saddr, &iph->saddr, 4);
        memcpy(e->daddr, &iph->daddr, 4);
        e->l4_proto = iph->protocol;
        cursor += ip_hdr_len;

        if (iph->protocol == IPPROTO_TCP) {
            if (cursor + sizeof(struct tcphdr) > end) return false;
            const struct tcphdr *tcph = (const struct tcphdr *)cursor;
            size_t tcp_hdr_len = (size_t)tcph->doff * 4;
            if (tcp_hdr_len < sizeof(*tcph) || cursor + tcp_hdr_len > end) return false;
            e->sport = bpf_ntohs(tcph->source);
            e->dport = bpf_ntohs(tcph->dest);
            cursor += tcp_hdr_len;
        } else if (iph->protocol == IPPROTO_UDP) {
            if (cursor + sizeof(struct udphdr) > end) return false;
            const struct udphdr *udph = (const struct udphdr *)cursor;
            e->sport = bpf_ntohs(udph->source);
            e->dport = bpf_ntohs(udph->dest);
            cursor += sizeof(*udph);
        } else {
            return false;
        }
    } else if (h_proto == ETH_P_IPV6) {
        if (cursor + sizeof(struct ipv6hdr) > end) return false;
        const struct ipv6hdr *ip6 = (const struct ipv6hdr *)cursor;

        e->family = AF_INET6;
        memcpy(e->saddr, &ip6->saddr, 16);
        memcpy(e->daddr, &ip6->daddr, 16);
        e->l4_proto = ip6->nexthdr;
        cursor += sizeof(*ip6);

        __u8 next = ip6->nexthdr;
        while (next == IPPROTO_HOPOPTS || next == IPPROTO_ROUTING ||
               next == IPPROTO_FRAGMENT || next == IPPROTO_AH ||
               next == IPPROTO_DSTOPTS) {
            if (cursor + sizeof(struct ipv6_opt_hdr) > end) return false;
            const struct ipv6_opt_hdr *opt = (const struct ipv6_opt_hdr *)cursor;
            size_t hdr_len = (size_t)(opt->hdrlen + 1) * 8;
            if (hdr_len < sizeof(*opt) || cursor + hdr_len > end) return false;
            next = opt->nexthdr;
            cursor += hdr_len;
        }

        e->l4_proto = next;
        if (next == IPPROTO_TCP) {
            if (cursor + sizeof(struct tcphdr) > end) return false;
            const struct tcphdr *tcph = (const struct tcphdr *)cursor;
            size_t tcp_hdr_len = (size_t)tcph->doff * 4;
            if (tcp_hdr_len < sizeof(*tcph) || cursor + tcp_hdr_len > end) return false;
            e->sport = bpf_ntohs(tcph->source);
            e->dport = bpf_ntohs(tcph->dest);
            cursor += tcp_hdr_len;
        } else if (next == IPPROTO_UDP) {
            if (cursor + sizeof(struct udphdr) > end) return false;
            const struct udphdr *udph = (const struct udphdr *)cursor;
            e->sport = bpf_ntohs(udph->source);
            e->dport = bpf_ntohs(udph->dest);
            cursor += sizeof(*udph);
        } else {
            return false;
        }
    } else {
        return false;
    }

    size_t payload_len = (size_t)(end - cursor);
    e->payload_len = (uint32_t)payload_len;
    e->cap_len = payload_len < CAP_PAYLOAD ? (uint32_t)payload_len : CAP_PAYLOAD;
    if (e->cap_len > 0) memcpy(e->payload, cursor, e->cap_len);
    return true;
}

static void process_tcp_flow(struct zwbee_state *state, struct zwbee_config *cfg,
                             const struct event_t *e, const struct socket_meta *meta);

static void process_udp_packet(const struct event_t *e, const struct socket_meta *meta);

static bool packet_matches_filters(const struct event_t *e, const struct socket_meta *meta,
                                   const struct zwbee_config *cfg);

static bool parse_port(const char *s, uint16_t *out);

static void handle_packet(struct callback_ctx *cb, const unsigned char *packet, size_t len, uint8_t direction)
{
    // 单包处理入口：解析 packet -> 回填元数据 -> 过滤 -> 分发到 TCP/UDP 处理器。
    // 它本身更像一个调度函数，把解析、回填、过滤和输出串在一起，而不是单独完成某一个协议逻辑。
    struct event_t e;
    if (!parse_packet(packet, len, direction, &e)) return;

    uint64_t now = now_ms();

    struct socket_meta meta;
    memset(&meta, 0, sizeof(meta));
    struct socket_meta fallback_meta;
    if (resolve_packet_meta(cb->state, &e, &fallback_meta)) {
        // 优先命中 BPF map 或现有 cache 时，可以完全跳过 /proc 重扫。
        meta = fallback_meta;
    } else if ((cb->state->sockets.last_refresh_ms == 0 ||
                now - cb->state->sockets.last_refresh_ms > SOCKET_CACHE_REFRESH_MS) &&
               rebuild_socket_cache(&cb->state->sockets) &&
               resolve_packet_meta(cb->state, &e, &fallback_meta)) {
        // 只有缓存过期或首次为空时才重建 socket 快照，避免每个包都去扫 /proc。
        meta = fallback_meta;
    }

    if (!packet_matches_filters(&e, &meta, cb->cfg)) return;

    if (e.l4_proto == IPPROTO_TCP) {
        process_tcp_flow(cb->state, cb->cfg, &e, &meta);
    } else if (e.l4_proto == IPPROTO_UDP) {
        process_udp_packet(&e, &meta);
    }

    if (cb->state->last_gc_ms == 0 || now - cb->state->last_gc_ms > 2000) {
        flow_gc(cb->state, now - 120000ULL);
        cb->state->last_gc_ms = now;
    }
}

static void drain_packet_socket(int sock, struct callback_ctx *cb)
{
    // 非阻塞循环读 packet socket，直到暂时没有数据可读。
    unsigned char packet[65536];
    struct sockaddr_ll from;
    socklen_t from_len = sizeof(from);

    for (;;) {
        ssize_t n = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&from, &from_len);
        if (n >= 0) {
            uint8_t direction = from.sll_pkttype == PACKET_OUTGOING ? 1 : 0;
            handle_packet(cb, packet, (size_t)n, direction);
            from_len = sizeof(from);
            continue;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == ENETDOWN || errno == ENOBUFS) break;
        perror("recvfrom");
        break;
    }
}

/* 
使用 libpcap-dev 提供的函数，由于依赖问题，已被禁用。
static bool compile_pcap_rules(const char *rules,
                               struct pcap_rule_insn out[PCAP_RULES_MAX_INSNS],
                               uint32_t *out_count)
{
    // userspace 负责把 pcap 表达式编译成 classic BPF，并筛掉当前内核解释器不支持的 opcode。
    // 这样既满足 pcaprules 走 classic BPF 指令的要求，也把 verifier 成本控制在可接受范围内。
    *out_count = 0;
    if (!rules || rules[0] == '\0') return true;

    struct bpf_program program = {};
    // 优先使用 pcap_compile_nopcap，避免依赖运行态 pcap 句柄；
    // 某些环境下如果它不可用或失败，再退回 pcap_open_dead + pcap_compile 取详细错误信息。
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
    int nopcap_rc = pcap_compile_nopcap(65535, DLT_EN10MB, &program, rules, 1, PCAP_NETMASK_UNKNOWN);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
    if (nopcap_rc != 0) {
        pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
        if (!pcap) {
            fprintf(stderr, "failed to create pcap compiler context\n");
            return false;
        }
        if (pcap_compile(pcap, &program, rules, 1, PCAP_NETMASK_UNKNOWN) != 0) {
            fprintf(stderr, "failed to compile -pcap-rules: %s\n", pcap_geterr(pcap));
            pcap_close(pcap);
            return false;
        }
        pcap_close(pcap);
    }

    bool ok = false;
    if (program.bf_len == 0 || program.bf_len > PCAP_RULES_MAX_INSNS) {
        fprintf(stderr, "-pcap-rules compiled to %u instructions, limit is %u\n",
                program.bf_len, PCAP_RULES_MAX_INSNS);
        goto out;
    }

    for (u_int i = 0; i < program.bf_len; ++i) {
        struct pcap_bpf_insn insn = program.bf_insns[i];
        switch (insn.code) {
        case BPF_LD | BPF_W | BPF_ABS:
        case BPF_LD | BPF_H | BPF_ABS:
        case BPF_LD | BPF_B | BPF_ABS:
        case BPF_LD | BPF_W | BPF_IND:
        case BPF_LD | BPF_H | BPF_IND:
        case BPF_LD | BPF_B | BPF_IND:
        case BPF_LDX | BPF_B | BPF_MSH:
        case BPF_JMP | BPF_JA:
        case BPF_JMP | BPF_JEQ | BPF_K:
        case BPF_JMP | BPF_JSET | BPF_K:
        case BPF_RET | BPF_K:
        case BPF_ALU | BPF_AND | BPF_K:
        caes BPF_JMP | BPF_JGE | BPF_K:
        case BPF_JMP | BPF_JGT | BPF_K
            out[i].code = insn.code;
            out[i].jt = insn.jt;
            out[i].jf = insn.jf;
            out[i].k = insn.k;
            break;
        default:
            fprintf(stderr, "unsupported classic BPF opcode 0x%x in -pcap-rules\n", insn.code);
            goto out;
        }
    }

    *out_count = (uint32_t)program.bf_len;
    ok = true;

out:
    pcap_freecode(&program);
    return ok;
}
*/

static bool parse_tcpdump_bpf_output(FILE *fp,
                                     struct pcap_rule_insn out[PCAP_RULES_MAX_INSNS],
                                     uint32_t *out_count)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread = getline(&line, &cap, fp);
    if (nread <= 0) {
        free(line);
        return false;
    }

    errno = 0;
    char *end = NULL;
    unsigned long count = strtoul(line, &end, 10);
    if (errno != 0 || end == line || count == 0 || count > PCAP_RULES_MAX_INSNS) {
        free(line);
        return false;
    }

    for (unsigned long i = 0; i < count; ++i) {
        nread = getline(&line, &cap, fp);
        if (nread <= 0) {
            free(line);
            return false;
        }

        unsigned int code = 0;
        unsigned int jt = 0;
        unsigned int jf = 0;
        unsigned long k = 0;
        if (sscanf(line, "%u %u %u %lu", &code, &jt, &jf, &k) != 4) {
            free(line);
            return false;
        }
        if (k > UINT32_MAX) {
            free(line);
            return false;
        }

        out[i] = (struct pcap_rule_insn){
            .code = (uint16_t)code,
            .jt = (uint8_t)jt,
            .jf = (uint8_t)jf,
            .k = (uint32_t)k,
        };
    }

    *out_count = (uint32_t)count;
    free(line);
    return true;
}

static bool compile_pcap_rules(const char *rules,
                               struct pcap_rule_insn out[PCAP_RULES_MAX_INSNS],
                               uint32_t *out_count)
{
    // 现在改为调用 tcpdump 生成 classic BPF，userspace 只负责把 stdout 读回来并校验格式。
    // 这样可以去掉 libpcap 头文件和链接依赖，同时保留 tcpdump 的表达式兼容性。
    *out_count = 0;
    if (!rules || rules[0] == '\0') return true;

    int pipefd[2] = {-1, -1};
    bool ok = true;
    if (pipe(pipefd) != 0) {
        perror("pipe");
        ok = false;
    }

    pid_t pid = -1;
    if (ok) {
        pid = fork();
        if (pid < 0) {
            perror("fork");
            close(pipefd[0]);
            close(pipefd[1]);
            pipefd[0] = -1;
            pipefd[1] = -1;
            ok = false;
        } else if (pid == 0) {
            (void)dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[0]);
            close(pipefd[1]);
            execlp("tcpdump", "tcpdump",
                   "-ddd",
                   "-s", "65535",
                   "-y", "EN10MB",
                   rules,
                   (char *)NULL);
            perror("execlp tcpdump");
            _exit(127);
        }
    }

    FILE *out_fp = NULL;
    if (ok) {
        close(pipefd[1]);
        pipefd[1] = -1;
        out_fp = fdopen(pipefd[0], "r");
        if (!out_fp) {
            perror("fdopen tcpdump output");
            close(pipefd[0]);
            pipefd[0] = -1;
            ok = false;
        }
    }

    if (ok) {
        ok = parse_tcpdump_bpf_output(out_fp, out, out_count);
    }

    if (out_fp) fclose(out_fp);
    else if (pipefd[0] >= 0) close(pipefd[0]);

    int wait_status = 0;
    if (pid > 0) {
        while (waitpid(pid, &wait_status, 0) < 0) {
            if (errno != EINTR) {
                perror("waitpid tcpdump");
                ok = false;
                break;
            }
        }
        if (ok && (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0)) {
            fprintf(stderr, "tcpdump failed to compile -pcap-rules: %s\n", rules);
            ok = false;
        }
    }
    return ok;
}
static bool configure_capture_program(struct bpf_object *obj, const struct zwbee_config *cfg)
{
    // 把 interface / pcaprules 两个参数写入 BPF map，供 capture_prog 在内核里读取。
    // 内核侧只需要知道“接口限制”和“pcap 指令”；更细的 pid/comm/CIDR 过滤仍放在 userspace。
    int config_fd = bpf_object__find_map_fd_by_name(obj, "capture_config_map");
    int pcap_fd = bpf_object__find_map_fd_by_name(obj, "pcap_insns");
    if (config_fd < 0 || pcap_fd < 0) {
        fprintf(stderr, "failed to find capture config maps\n");
        return false;
    }

    struct capture_config capture_cfg = {
        .ifindex = cfg->ifindex > 0 ? (uint32_t)cfg->ifindex : 0,
        .pcap_len = 0,
    };
    struct pcap_rule_insn insns[PCAP_RULES_MAX_INSNS];
    memset(insns, 0, sizeof(insns));
    if (!compile_pcap_rules(cfg->pcap_rules, insns, &capture_cfg.pcap_len)) return false;

    for (uint32_t i = 0; i < capture_cfg.pcap_len; ++i) {
        if (bpf_map_update_elem(pcap_fd, &i, &insns[i], BPF_ANY) != 0) {
            perror("bpf_map_update_elem(pcap_insns)");
            return false;
        }
    }

    uint32_t key = 0;
    if (bpf_map_update_elem(config_fd, &key, &capture_cfg, BPF_ANY) != 0) {
        perror("bpf_map_update_elem(capture_config_map)");
        return false;
    }
    return true;
}

static void process_tcp_flow(struct zwbee_state *state, struct zwbee_config *cfg,
                             const struct event_t *e, const struct socket_meta *meta)
{
    // TCP 主处理路径：按 flow 缓冲数据，再尝试 TLS/HTTP 解析，成功后输出 JSON。
    // 这部分是 userspace 的核心状态机：先把同一条连接的数据聚到一起，再决定它到底是 HTTP 还是 TLS。
    // 这里的 flow 是按方向保存的，因此 request 和 response 各有自己的缓冲；peer 负责跨方向共享上下文。
    struct flow_key key;
    memset(&key, 0, sizeof(key));
    key.family = e->family;
    key.l4_proto = e->l4_proto;
    key.direction = e->direction;
    key.sport = e->sport;
    key.dport = e->dport;
    memcpy(key.saddr, e->saddr, e->family == AF_INET ? 4 : 16);
    memcpy(key.daddr, e->daddr, e->family == AF_INET ? 4 : 16);

    struct flow_state *flow = flow_get(state, &key);
    if (!flow) return;
    flow->last_seen_ms = now_ms();

    // 抓到可用元数据时，先把它写进 flow，后续缺失时可以直接复用。
    // 这样做的目的是：一旦某个方向先识别到 owner，后面同一条流的另一侧也能共享这份身份信息。
    if (meta && meta->pid > 0) {
        flow->pid = meta->pid;
        flow->uid = meta->uid;
        flow->cr_id = meta->cr_id;
        flow->cr_pid = meta->cr_pid;
        strncpy(flow->comm, meta->comm, sizeof(flow->comm) - 1);
        flow->comm[sizeof(flow->comm) - 1] = '\0';
    }

    struct flow_key reverse_key;
    flow_reverse_key(e, &reverse_key);
    struct flow_state *peer = flow_find(state, &reverse_key);

    struct socket_meta peer_meta;
    memset(&peer_meta, 0, sizeof(peer_meta));
    // 当前方向没有拿到归属时，尝试借用对端已经解析到的进程信息。
    // 代理、复用连接、请求/响应分离等场景里，这个兜底能显著减少“这一包没有 owner”的情况。
    if (meta->pid <= 0 && peer && peer->pid > 0) {
        peer_meta.pid = peer->pid;
        peer_meta.uid = peer->uid;
        peer_meta.cr_id = peer->cr_id;
        peer_meta.cr_pid = peer->cr_pid;
        strncpy(peer_meta.comm, peer->comm, sizeof(peer_meta.comm) - 1);
        peer_meta.comm[sizeof(peer_meta.comm) - 1] = '\0';
        meta = &peer_meta;
    }

    // 先把当前包的 payload 拼到流缓冲里，再进行协议识别。
    // 如果这里失败，通常表示缓冲扩容或内存压力出了问题；当前包就不继续参与解析。
    if (!buffer_append(&flow->tcp_buffer, e->payload, e->cap_len)) return;

    // 先判定是否为 TLS，避免把 HTTPS 流量误按 HTTP 解析。
    // 一旦进入 TLS 分支，这条 flow 就会被视作加密会话，后续优先输出 TLS/SNI/ALPN 信息。
    // 这里允许缓冲前面有少量噪声前缀，以适应抓包从连接中途接入或首段不完整的情况。
    ssize_t req_off = !flow->tls_emitted ? find_tls_handshake_record_offset(flow->tcp_buffer.data, flow->tcp_buffer.len, 0x01) : -1;
    if (req_off >= 0) {
        // 只要当前缓冲里找到一个完整 ClientHello，就立即输出 HTTPS request，并消费当前方向缓冲。
        const unsigned char *tls_data = flow->tcp_buffer.data + req_off;
        size_t tls_len = flow->tcp_buffer.len - (size_t)req_off;
        char sni[256] = {0};
        char alpn[128] = {0};
        uint16_t ver = 0;
        if (parse_tls_clienthello(tls_data, (uint32_t)tls_len,
                                  sni, sizeof(sni), alpn, sizeof(alpn), &ver)) {
            if (sni[0]) {
                strncpy(flow->domain, sni, sizeof(flow->domain) - 1);
                flow->domain[sizeof(flow->domain) - 1] = '\0';
                flow->has_domain = true;
            }
            emit_json_https(e, meta, "request", http_version_from_alpn(alpn), tls_version_name(ver),
                            sni, alpn, ver, tls_data, tls_len, "tcp");
            flow->tls_emitted = true;
            buffer_consume(&flow->tcp_buffer, flow->tcp_buffer.len);
            return;
        }
    }

    ssize_t resp_off = !flow->tls_emitted ? find_tls_handshake_record_offset(flow->tcp_buffer.data, flow->tcp_buffer.len, 0x02) : -1;
    if (resp_off >= 0) {
        // ServerHello 侧重点是协商结果；没有域名时，优先借用对端 flow 已保存的 domain。
        const unsigned char *tls_data = flow->tcp_buffer.data + resp_off;
        size_t tls_len = flow->tcp_buffer.len - (size_t)resp_off;
        char sni[256] = {0};
        char alpn[128] = {0};
        uint16_t ver = 0;
        if (parse_tls_serverhello(tls_data, (uint32_t)tls_len,
                                  alpn, sizeof(alpn), &ver)) {
            if (!sni[0] && peer && peer->has_domain) {
                strncpy(sni, peer->domain, sizeof(sni) - 1);
                sni[sizeof(sni) - 1] = '\0';
            }
            emit_json_https(e, meta, "response", http_version_from_alpn(alpn), tls_version_name(ver),
                            sni, alpn, ver, tls_data, tls_len, "tcp");
            flow->tls_emitted = true;
            buffer_consume(&flow->tcp_buffer, flow->tcp_buffer.len);
            return;
        }
    }

    // HTTP 可能跨多个 TCP 包到达，所以这里循环尝试解析；不完整就保留缓冲继续等。
    // 循环的意思是：当前缓冲里如果已经包含多个完整 HTTP 报文，就尽量一次消费完。
    while (flow->tcp_buffer.len > 0) {
        struct http_message msg;
        if (!parse_http_message(flow->tcp_buffer.data, flow->tcp_buffer.len, cfg->body_limit, &msg)) {
            break;
        }

        if (msg.consumed == 0 || msg.consumed > flow->tcp_buffer.len) break;

        // 当前报文没有 Host 时，尝试继承对端已经识别出的域名。
        // 这个继承动作主要是为了 response 侧没有 Host 头时，仍然能保留同一条会话的域名上下文。
        if (!msg.host[0] && peer && peer->has_domain) {
            strncpy(msg.host, peer->domain, sizeof(msg.host) - 1);
            msg.host[sizeof(msg.host) - 1] = '\0';
        }

        if (msg.host[0]) {
            strncpy(flow->domain, msg.host, sizeof(flow->domain) - 1);
            flow->domain[sizeof(flow->domain) - 1] = '\0';
            flow->has_domain = true;
        }

        const unsigned char *body = NULL;
        size_t body_len = msg.body_len;
        if (msg.body_copy && msg.body_len > 0) {
            // chunked body 的内容已经解析并复制到临时缓冲，这里直接用临时副本输出即可。
            body = msg.body_copy;
        } else if (msg.body_len > 0 && msg.header_end + msg.body_len <= flow->tcp_buffer.len) {
            // 非 chunked body 且当前缓冲已经完整包含 body 时，直接引用原始缓冲，避免重复拷贝。
            body = flow->tcp_buffer.data + msg.header_end;
        }

        // 输出 HTTP 事件，然后消费掉已经成功解析的字节。
        // 消费后剩余部分要么是下一条 HTTP 报文，要么是下一段 TCP 分片的残留。
        emit_json_http(e, meta, &msg, flow->tcp_buffer.data, msg.header_end, body, body_len);
        http_message_free(&msg);
        buffer_consume(&flow->tcp_buffer, msg.consumed);
        flow->tls_emitted = false;
    }
}

static void process_udp_packet(const struct event_t *e, const struct socket_meta *meta)
{
    // UDP 侧主要看 QUIC Initial 中的 TLS ClientHello，不做完整 QUIC 解密。
    // 这里的目标只是从明文握手里提取 SNI/ALPN，给 HTTPS over UDP 留下可读上下文。
    // 当前实现只输出 request 侧信息，因为在不解密的前提下 response 侧几乎没有同等级别的可读元数据。
    if (e->cap_len < 6) return;
    const unsigned char *payload = e->payload;
    uint32_t payload_len = e->cap_len;
    const unsigned char *tls_data = payload;
    uint32_t tls_len = payload_len;
    if (!find_quic_tls_payload(payload, payload_len, &tls_data, &tls_len)) return;

    char sni[256] = {0};
    char alpn[128] = {0};
    uint16_t ver = 0;
    if (parse_tls_clienthello(tls_data, tls_len, sni, sizeof(sni), alpn, sizeof(alpn), &ver)) {
        emit_json_https(e, meta, "request", http_version_from_alpn(alpn), tls_version_name(ver),
                        sni, alpn, ver, e->payload, e->cap_len, "udp");
    }
}

static bool packet_matches_filters(const struct event_t *e, const struct socket_meta *meta,
                                   const struct zwbee_config *cfg)
{
    // 过滤顺序尽量从便宜到昂贵：方向、端口、网段、进程/容器属性。
    // 先做简单数值判断，可以尽早返回，减少后面元数据比对的开销。
    if (cfg->direction_filter >= 0 && e->direction != (uint8_t)cfg->direction_filter) return false;

    if (cfg->have_sport_filter && e->direction == 0 && e->sport != cfg->sport_filter) return false;
    if (cfg->have_dport_filter && e->direction == 1 && e->dport != cfg->dport_filter) return false;

    if (!cidr_set_accepts(&cfg->src_rules, e->family, e->saddr)) return false;
    if (!cidr_set_accepts(&cfg->dst_rules, e->family, e->daddr)) return false;

    if (cfg->have_pid_filter || cfg->have_cpid_filter || cfg->have_crid_filter || cfg->have_comm_filter) {
        // 一旦启用了进程类过滤，就必须先有 meta，否则无法判断 pid / cpid / crid / comm。
        if (!meta) return false;
        if (cfg->have_pid_filter && meta->pid != cfg->pid_filter) return false;
        if (cfg->have_cpid_filter && meta->cr_pid != cfg->cpid_filter) return false;
        if (cfg->have_crid_filter && meta->cr_id != cfg->crid_filter) return false;
        if (cfg->have_comm_filter && strncmp(meta->comm, cfg->comm_filter, COMM_LEN) != 0) return false;
    }

    return true;
}

static void usage(const char *prog)
{
    // 打印命令行帮助。
    // 这里把所有参数一次性列出来，方便用户直接复制命令行模板。
    fprintf(stderr,
            "Usage: %s [-interface iface] [-pcap-rules expr] [-direction ingress|egress] [-pid pid] [-cpid pid] [-crid id] [-comm comm] [-src spec] [-dst spec] [-sport port] [-dport port] [-max-body-size n]\n"
            "  -interface      zwbee interface\n"
            "  -pcap-rules     optional kernel-side pcap filter, empty by default, max 256 instructions\n"
            "  -direction      ingress | egress, default both\n"
            "  -pid            process pid filter\n"
            "  -cpid           container pid filter\n"
            "  -crid           container namespace id filter\n"
            "  -comm           process name filter (comm)\n"
            "  -src    source IP/CIDR list, !prefix means deny, deny wins\n"
            "  -dst    destination IP/CIDR list, !prefix means deny, deny wins\n"
            "  -sport  ingress only port filter\n"
            "  -dport  egress only port filter\n"
            "  -max-body-size  request/response body capture length, <0 no body, 0 unlimited, >0 truncated\n",
            prog);
}

static bool parse_long_long(const char *s, long long *out)
{
    char *end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno || !end || *end != '\0') return false;
    *out = v;
    return true;
}

static bool parse_port(const char *s, uint16_t *out)
{
    long long v = 0;
    if (!parse_long_long(s, &v)) return false;
    if (v < 0 || v > 65535) return false;
    *out = (uint16_t)v;
    return true;
}

static bool parse_args(int argc, char **argv, struct zwbee_config *cfg)
{
    // 解析命令行参数并填充 zwbee_config。
    // 这一层只做字符串到字段的映射，不做更深的业务判定。
    // 参数合法性尽量在入口处拦截，后面的运行逻辑默认拿到的配置已经是自洽的。
    memset(cfg, 0, sizeof(*cfg));
    cfg->direction_filter = -1;
    cfg->body_limit = -1;
    cfg->pcap_rules = "";

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(argv[0]);
            return false;
        } else if (!strcmp(arg, "-interface") && i + 1 < argc) {
            cfg->ifname = argv[++i];
        } else if (!strcmp(arg, "-pcap-rules") && i + 1 < argc) {
            cfg->pcap_rules = argv[++i];
        } else if (!strcmp(arg, "-direction") && i + 1 < argc) {
            const char *v = argv[++i];
            if (!strcmp(v, "ingress")) cfg->direction_filter = 0;
            else if (!strcmp(v, "egress")) cfg->direction_filter = 1;
            else {
                fprintf(stderr, "Invalid -direction value: %s\n", v);
                return false;
            }
        } else if (!strcmp(arg, "-pid") && i + 1 < argc) {
            long long pid = 0;
            if (!parse_long_long(argv[++i], &pid) || pid < 0) {
                fprintf(stderr, "Invalid pid\n");
                return false;
            }
            // pid 是宿主机视角的进程号。
            cfg->have_pid_filter = true;
            cfg->pid_filter = (pid_t)pid;
        } else if (!strcmp(arg, "-cpid") && i + 1 < argc) {
            long long cpid = 0;
            if (!parse_long_long(argv[++i], &cpid) || cpid < 0) {
                fprintf(stderr, "Invalid cpid\n");
                return false;
            }
            // cpid 是容器视角下的 PID。
            cfg->have_cpid_filter = true;
            cfg->cpid_filter = (uint32_t)cpid;
        } else if (!strcmp(arg, "-crid") && i + 1 < argc) {
            long long crid = 0;
            if (!parse_long_long(argv[++i], &crid) || crid < 0) {
                fprintf(stderr, "Invalid crid\n");
                return false;
            }
            // crid 是 PID namespace 的 inode 号，也就是容器 namespace 的身份标识。
            cfg->have_crid_filter = true;
            cfg->crid_filter = (uint64_t)crid;
        } else if (!strcmp(arg, "-comm") && i + 1 < argc) {
            strncpy(cfg->comm_filter, argv[++i], COMM_LEN - 1);
            cfg->comm_filter[COMM_LEN - 1] = '\0';
            cfg->have_comm_filter = true;
        } else if (!strcmp(arg, "-src") && i + 1 < argc) {
            if (!parse_cidr_list(argv[++i], &cfg->src_rules)) {
                fprintf(stderr, "Invalid -src specification\n");
                return false;
            }
        } else if (!strcmp(arg, "-dst") && i + 1 < argc) {
            if (!parse_cidr_list(argv[++i], &cfg->dst_rules)) {
                fprintf(stderr, "Invalid -dst specification\n");
                return false;
            }
        } else if (!strcmp(arg, "-sport") && i + 1 < argc) {
            if (!parse_port(argv[++i], &cfg->sport_filter)) {
                fprintf(stderr, "Invalid -sport value\n");
                return false;
            }
            cfg->have_sport_filter = true;
        } else if (!strcmp(arg, "-dport") && i + 1 < argc) {
            if (!parse_port(argv[++i], &cfg->dport_filter)) {
                fprintf(stderr, "Invalid -dport value\n");
                return false;
            }
            cfg->have_dport_filter = true;
        } else if (!strcmp(arg, "-max-body-size") && i + 1 < argc) {
            if (!parse_long_long(argv[++i], &cfg->body_limit)) {
                fprintf(stderr, "Invalid -max-body-size value\n");
                return false;
            }
        } else {
            fprintf(stderr, "Unknown argument: %s\n", arg);
            usage(argv[0]);
            return false;
        }
    }

    return true;
}

static bool open_and_attach_bpf(int sock_fd,
                                const struct zwbee_config *cfg,
                                struct bpf_object **obj_out,
                                struct bpf_link **tcp_connect_link_out,
                                struct bpf_link **tcp_accept_link_out,
                                struct bpf_link **tcp_sendmsg_link_out,
                                struct bpf_link **udp_sendmsg_link_out)
{
    // 直接从内存中的嵌入字节码打开 BPF 对象，避免依赖磁盘上的 ebpf_capture.o 文件。
    // 这样打包出来的 zwbee 就是一个自包含二进制，不需要额外分发 .o 文件。
    // zwbee 最终只依赖运行时库和内核能力，不依赖部署现场再去寻找外部 BPF 目标文件。
    size_t obj_size = (size_t)(_binary_ebpf_capture_o_end - _binary_ebpf_capture_o_start);
    struct bpf_object *obj = bpf_object__open_mem(_binary_ebpf_capture_o_start, obj_size, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open embedded ebpf_capture.o\n");
        return false;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load embedded ebpf_capture.o\n");
        bpf_object__close(obj);
        return false;
    }

    if (!configure_capture_program(obj, cfg)) {
        bpf_object__close(obj);
        return false;
    }

    // 下面这几个 kprobe/kretprobe 负责把“哪个进程在用这个 socket”持续写回 map。
    struct bpf_program *tcp_connect_prog = bpf_object__find_program_by_name(obj, "track_tcp_connect");
    struct bpf_program *tcp_accept_prog = bpf_object__find_program_by_name(obj, "track_tcp_accept");
    struct bpf_program *tcp_send_prog = bpf_object__find_program_by_name(obj, "track_tcp_sendmsg");
    struct bpf_program *udp_send_prog = bpf_object__find_program_by_name(obj, "track_udp_sendmsg");
    struct bpf_program *capture_prog = bpf_object__find_program_by_name(obj, "capture_prog");
    if (!tcp_connect_prog || !tcp_accept_prog ||
        !tcp_send_prog || !udp_send_prog || !capture_prog) {
        fprintf(stderr, "failed to find kprobe programs\n");
        bpf_object__close(obj);
        return false;
    }

    struct bpf_link *tcp_connect_link = bpf_program__attach_kprobe(tcp_connect_prog, false, "tcp_connect");
    if (libbpf_get_error(tcp_connect_link)) {
        fprintf(stderr, "failed to attach track_tcp_connect\n");
        bpf_object__close(obj);
        return false;
    }

    struct bpf_link *tcp_accept_link = bpf_program__attach_kprobe(tcp_accept_prog, true, "inet_csk_accept");
    if (libbpf_get_error(tcp_accept_link)) {
        fprintf(stderr, "failed to attach track_tcp_accept\n");
        bpf_link__destroy(tcp_connect_link);
        bpf_object__close(obj);
        return false;
    }

    struct bpf_link *tcp_send_link = bpf_program__attach_kprobe(tcp_send_prog, false, "tcp_sendmsg");
    if (libbpf_get_error(tcp_send_link)) {
        fprintf(stderr, "failed to attach track_tcp_sendmsg\n");
        bpf_link__destroy(tcp_accept_link);
        bpf_link__destroy(tcp_connect_link);
        bpf_object__close(obj);
        return false;
    }

    struct bpf_link *udp_send_link = bpf_program__attach_kprobe(udp_send_prog, false, "udp_sendmsg");
    if (libbpf_get_error(udp_send_link)) {
        fprintf(stderr, "failed to attach track_udp_sendmsg\n");
        bpf_link__destroy(tcp_send_link);
        bpf_link__destroy(tcp_accept_link);
        bpf_link__destroy(tcp_connect_link);
        bpf_object__close(obj);
        return false;
    }

    int prog_fd = bpf_program__fd(capture_prog);
    if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        perror("SO_ATTACH_BPF");
        bpf_link__destroy(udp_send_link);
        bpf_link__destroy(tcp_send_link);
        bpf_link__destroy(tcp_accept_link);
        bpf_link__destroy(tcp_connect_link);
        bpf_object__close(obj);
        return false;
    }

    *obj_out = obj;
    if (tcp_connect_link_out) *tcp_connect_link_out = tcp_connect_link;
    if (tcp_accept_link_out) *tcp_accept_link_out = tcp_accept_link;
    if (tcp_sendmsg_link_out) *tcp_sendmsg_link_out = tcp_send_link;
    if (udp_sendmsg_link_out) *udp_sendmsg_link_out = udp_send_link;
    return true;
}

int main(int argc, char **argv)
{
    // 程序主入口：解析参数、初始化 socket、装载 BPF、进入事件循环。
    // 整体流程可以理解成：先准备抓包环境，再把 BPF 和 packet socket 绑起来，最后持续消费事件。
    // 真正的数据主路径是：packet socket 收包 -> handle_packet -> 元数据回填/过滤 -> TCP/UDP 处理器 -> JSON 输出。
    struct zwbee_config cfg;
    if (!parse_args(argc, argv, &cfg)) return 1;

    signal(SIGINT, sigint_handler);

    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        perror("setrlimit");
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    if (cfg.ifname) {
        cfg.ifindex = (int)if_nametoindex(cfg.ifname);
        if (cfg.ifindex == 0) {
            fprintf(stderr, "Invalid interface: %s\n", cfg.ifname);
            close(sock);
            return 1;
        }
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = cfg.ifindex;
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind");
            close(sock);
            return 1;
        }
    }

    int sock_flags = fcntl(sock, F_GETFL, 0);
    if (sock_flags >= 0) {
        fcntl(sock, F_SETFL, sock_flags | O_NONBLOCK);
    }

    struct bpf_object *obj = NULL;
    struct bpf_link *tcp_connect_link = NULL;
    struct bpf_link *tcp_accept_link = NULL;
    struct bpf_link *tcp_sendmsg_link = NULL;
    struct bpf_link *udp_sendmsg_link = NULL;
    if (!open_and_attach_bpf(sock, &cfg,
                             &obj,
                             &tcp_connect_link,
                             &tcp_accept_link,
                             &tcp_sendmsg_link,
                             &udp_sendmsg_link)) {
        close(sock);
        return 1;
    }

    struct zwbee_state state;
    memset(&state, 0, sizeof(state));
    socket_cache_reset(&state.sockets);
    state.flow_owner_map_fd = bpf_object__find_map_fd_by_name(obj, "flow_owner_map");
    state.last_gc_ms = 0;
    state.sockets.max_items = SOCKET_CACHE_MAX_ITEMS;
    if (!rebuild_socket_cache(&state.sockets)) {
        fprintf(stderr, "warning: failed to build socket cache\n");
    }

    struct callback_ctx cb_ctx = { .state = &state, .cfg = &cfg };

    fprintf(stderr, "listening on %s%s%s, Ctrl-C to exit\n",
            cfg.ifname ? cfg.ifname : "all interfaces",
            cfg.pcap_rules[0] ? ", pcap filter: " : "",
            cfg.pcap_rules[0] ? cfg.pcap_rules : "");

    while (!exiting) {
        struct pollfd fds[1];
        memset(fds, 0, sizeof(fds));
        fds[0].fd = sock;
        fds[0].events = POLLIN;

        int ready = poll(fds, 1, 1000);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (fds[0].revents & POLLIN) {
            drain_packet_socket(sock, &cb_ctx);
        }
    }

    bpf_link__destroy(tcp_accept_link);
    bpf_link__destroy(tcp_connect_link);
    bpf_link__destroy(udp_sendmsg_link);
    bpf_link__destroy(tcp_sendmsg_link);
    bpf_object__close(obj);
    close(sock);

    socket_cache_reset(&state.sockets);
    for (size_t i = 0; i < FLOW_BUCKETS; ++i) {
        struct flow_state *flow = state.flows[i];
        while (flow) {
            struct flow_state *next = flow->next;
            buffer_free(&flow->tcp_buffer);
            free(flow);
            flow = next;
        }
    }
    cidr_set_free(&cfg.src_rules);
    cidr_set_free(&cfg.dst_rules);
    return 0;
}