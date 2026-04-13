package zobee

// kwbee 纯 golang 实现的 eBPF 监控
// 为保持项目的 "零" 依赖, 该部分内容不参与编译，仅作为案例代码存在

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/suisrc/zoo"
	"github.com/suisrc/zoo/zoc"
)

const (
	pcapSnapLen = 65535
)

//go:embed ebpf_capture.o
var embeddedCaptureObject []byte

var (
	G = struct {
		Config Config `json:"zobee"`
	}{
		Config: Config{
			MaxBodySize: -1,
		},
	}

	logn = zoc.Logn
)

// func init() { Load() } // 通过 init 函数注册服务， 以便在主程序中自动加载

func Load(hook Hook) {

	flag.BoolVar(&G.Config.Disabled, "e3disabled", true, "是否禁用 zobee")
	flag.StringVar(&G.Config.IfName, "e3ifname", "", "抓包网卡名称")
	flag.StringVar(&G.Config.PcapRules, "e3pcap", "", "pcap 过滤表达式")
	flag.StringVar(&G.Config.Direction, "e3direction", "", "流量方向: ingress|egress")
	flag.UintVar(&G.Config.PID, "e3pid", 0, "PID 过滤值")
	flag.UintVar(&G.Config.CPID, "e3cpid", 0, "容器 PID 过滤值")
	flag.Uint64Var(&G.Config.CRID, "e3crid", 0, "容器命名空间过滤值")
	flag.StringVar(&G.Config.Comm, "e3comm", "", "进程 comm 过滤")
	flag.StringVar(&G.Config.SrcSpec, "e3src", "", "源地址 CIDR 过滤")
	flag.StringVar(&G.Config.DstSpec, "e3dst", "", "目标地址 CIDR 过滤")
	flag.UintVar(&G.Config.Sport, "e3sport", 0, "源端口过滤值")
	flag.UintVar(&G.Config.Dport, "e3dport", 0, "目标端口过滤值")
	flag.Int64Var(&G.Config.MaxBodySize, "e3maxbodysize", -1, "HTTP body 保留上限，默认 -1")

	zoo.Register("14-zobee", &G, func(svc zoo.SvcKit) zoo.Closed {
		if G.Config.Disabled {
			zoc.Logn("[_zoobee_]: disabled")
			return nil
		}
		cfg := normalizeInitConfig(G.Config)
		if _, err := normalizeConfig(cfg); err != nil {
			svc.Engine().ServeStop("register zobee error by config,", err.Error())
			return nil
		}
		// 特别重要的地方， 增加钩子函数参数， 以便在主程序中处理事件
		srv, err := NewServer(cfg, hook)
		if err != nil {
			svc.Engine().ServeStop("register zobee error by server,", err.Error())
			return nil
		}
		svc.Engine().Servers.Add(srv)
		zoc.Logn("[_zoobee_]: registered", fmt.Sprintf("f=%s dir=%s", //
			zoc.If(cfg.IfName != "", cfg.IfName, "all"), //
			zoc.If(cfg.Direction != "", cfg.Direction, "both")))
		return nil
	})
}

func normalizeInitConfig(cfg Config) Config {
	cfg.IfName = strings.TrimSpace(cfg.IfName)
	cfg.PcapRules = strings.TrimSpace(cfg.PcapRules)
	cfg.Direction = strings.TrimSpace(cfg.Direction)
	cfg.Comm = strings.TrimSpace(cfg.Comm)
	cfg.SrcSpec = strings.TrimSpace(cfg.SrcSpec)
	cfg.DstSpec = strings.TrimSpace(cfg.DstSpec)
	return cfg
}

type Hook func(map[string]any)

type Event struct {
	Packet *PacketEvent
	Meta   *SocketMeta
	Record map[string]any
}

type Server struct {
	cfg    runtimeConfig
	hook   Hook
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	started bool
	closed  bool

	rawSock int
	objs    bpfObjects
	links   []link.Link
	state   monitorState
}

func NewServer(cfg Config, hook Hook) (zoo.Server, error) {
	rc, err := normalizeConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:     rc,
		hook:    hook,
		ctx:     ctx,
		cancel:  cancel,
		rawSock: -1,
		state: monitorState{
			flows:   make(map[flowKey]*flowState),
			sockets: socketCache{items: make(map[socketKey]SocketMeta)},
		},
	}, nil
}

func (s *Server) Name() string {
	return "(EBPFG)"
}

func (s *Server) Addr() string {
	if s.cfg.IfName != "" {
		return s.cfg.IfName
	}
	return "all interfaces"
}

func (s *Server) RunServe() {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()

	if err := s.run(); err != nil && !errors.Is(err, context.Canceled) {
		zoc.Exit(fmt.Sprintf("[_zoobee_]: server exit error: %v\n", err))
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	if s.rawSock >= 0 {
		_ = syscall.Close(s.rawSock)
		s.rawSock = -1
	}
	links, objs := s.links, s.objs
	s.links = nil
	s.mu.Unlock()
	closeLinks(links)
	_ = objs.Close()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}
