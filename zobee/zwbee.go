package zobee

// 内容由AI生成，暂未完成审核，仅供参考学习，请勿直接使用

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	capPayload          = 4096
	flowBufferCap       = 32768
	flowStateMaxItems   = 4096
	socketCacheMaxItems = 8192
	procOwnerMaxItems   = 65536
	socketCacheRefresh  = time.Second
	flowGCInterval      = 2 * time.Second
	flowIdleTimeout     = 120 * time.Second
	pcapRulesMaxInsns   = 256
	ethPAll             = 0x0003
	ethPIP              = 0x0800
	ethPIPv6            = 0x86DD
	ethP8021Q           = 0x8100
	ethP8021AD          = 0x88A8
	ipProtoTCP          = 6
	ipProtoUDP          = 17
	ipProtoHOPOPTS      = 0
	ipProtoRouting      = 43
	ipProtoFragment     = 44
	ipProtoAH           = 51
	ipProtoDSTOPTS      = 60
	packetOutgoing      = 4
	afINET              = 2
	afINET6             = 10
	commLen             = 16
)

type Config struct {
	Disabled    bool   `json:"disabled"`
	IfName      string `json:"ifname"`
	PcapRules   string `json:"pcaprules"`
	Direction   string `json:"direction"`
	PID         uint   `json:"pid"`
	CPID        uint   `json:"cpid"`
	CRID        uint64 `json:"crid"`
	Comm        string `json:"comm"`
	SrcSpec     string `json:"src"`
	DstSpec     string `json:"dst"`
	Sport       uint   `json:"sport"`
	Dport       uint   `json:"dport"`
	MaxBodySize int64  `json:"max_body_size"`
}

type PacketEvent struct {
	Cookie     uint64
	Family     uint8
	Direction  uint8
	L4Proto    uint8
	Sport      uint16
	Dport      uint16
	PayloadLen uint32
	CapLen     uint32
	Saddr      [16]byte
	Daddr      [16]byte
	Payload    []byte
}

type SocketMeta struct {
	Family int
	Proto  int
	Saddr  [16]byte
	Daddr  [16]byte
	Sport  uint16
	Dport  uint16
	Inode  uint64
	PID    int
	UID    uint32
	CRID   uint64
	CRPID  uint32
	Comm   string
}

type runtimeConfig struct {
	IfName          string
	IfIndex         int
	PcapRules       string
	DirectionFilter int
	HavePIDFilter   bool
	PIDFilter       int
	HaveCPIDFilter  bool
	CPIDFilter      uint32
	HaveCRIDFilter  bool
	CRIDFilter      uint64
	HaveCommFilter  bool
	CommFilter      string
	HaveSportFilter bool
	SportFilter     uint16
	HaveDportFilter bool
	DportFilter     uint16
	BodyLimit       int64
	SrcRules        []cidrRule
	DstRules        []cidrRule
}

type cidrRule struct {
	Deny      bool
	Family    int
	PrefixLen uint8
	Addr      [16]byte
}

type flowKey struct {
	Family    uint8
	L4Proto   uint8
	Direction uint8
	Pad       uint8
	Sport     uint16
	Dport     uint16
	Saddr     [16]byte
	Daddr     [16]byte
}

type flowState struct {
	Key        flowKey
	TCPBuffer  []byte
	LastSeen   time.Time
	PID        int
	UID        uint32
	CRID       uint64
	CRPID      uint32
	Comm       string
	TLSEmitted bool
	HasDomain  bool
	Domain     string
}

type socketKey struct {
	Family int
	Proto  int
	Saddr  [16]byte
	Daddr  [16]byte
	Sport  uint16
	Dport  uint16
}

type procOwner struct {
	Inode uint64
	PID   int
	UID   uint32
	CRID  uint64
	CRPID uint32
	Comm  string
}

type socketCache struct {
	items         map[socketKey]SocketMeta
	listenerItems []SocketMeta
	lastRefresh   time.Time
}

type monitorState struct {
	flows        map[flowKey]*flowState
	sockets      socketCache
	lastGC       time.Time
	recordSeq    atomic.Uint64
	flowOwnerMap *ebpf.Map
}

type httpMessage struct {
	Response  bool
	Method    string
	Path      string
	Status    string
	Host      string
	Version   string
	HeaderEnd int
	BodyLen   int
	Consumed  int
	BodyCopy  []byte
}

type flowOwnerKey struct {
	Family  uint8
	L4Proto uint8
	Pad     [2]byte
	Sport   uint16
	Dport   uint16
	Saddr   [16]byte
	Daddr   [16]byte
}

type flowOwnerValue struct {
	PIDTGID uint64
	UID     uint32
	CRID    uint64
	CRPID   uint32
	Comm    [commLen]byte
}

type captureConfig struct {
	IfIndex uint32
	PcapLen uint32
}

type pcapRuleInsn struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

type bpfObjects struct {
	CaptureProg     *ebpf.Program `ebpf:"capture_prog"`
	TrackTCPConnect *ebpf.Program `ebpf:"track_tcp_connect"`
	TrackTCPAccept  *ebpf.Program `ebpf:"track_tcp_accept"`
	TrackTCPSendmsg *ebpf.Program `ebpf:"track_tcp_sendmsg"`
	TrackUDPSendmsg *ebpf.Program `ebpf:"track_udp_sendmsg"`

	FlowOwnerMap     *ebpf.Map `ebpf:"flow_owner_map"`
	TrackedFlowMap   *ebpf.Map `ebpf:"tracked_flow_map"`
	CaptureConfigMap *ebpf.Map `ebpf:"capture_config_map"`
	PcapInsns        *ebpf.Map `ebpf:"pcap_insns"`
}

func (o *bpfObjects) Close() error {
	var first error
	closeOne := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	if o.CaptureProg != nil {
		closeOne(o.CaptureProg.Close())
	}
	if o.TrackTCPConnect != nil {
		closeOne(o.TrackTCPConnect.Close())
	}
	if o.TrackTCPAccept != nil {
		closeOne(o.TrackTCPAccept.Close())
	}
	if o.TrackTCPSendmsg != nil {
		closeOne(o.TrackTCPSendmsg.Close())
	}
	if o.TrackUDPSendmsg != nil {
		closeOne(o.TrackUDPSendmsg.Close())
	}
	if o.FlowOwnerMap != nil {
		closeOne(o.FlowOwnerMap.Close())
	}
	if o.TrackedFlowMap != nil {
		closeOne(o.TrackedFlowMap.Close())
	}
	if o.CaptureConfigMap != nil {
		closeOne(o.CaptureConfigMap.Close())
	}
	if o.PcapInsns != nil {
		closeOne(o.PcapInsns.Close())
	}
	return first
}

func (s *Server) run() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	if err := s.loadBPF(); err != nil {
		return err
	}
	defer s.cleanup()
	if err := s.rebuildSocketCache(); err != nil {
		logn("[_zoobee_]: warning: failed to build socket cache", err)
	}
	if s.cfg.PcapRules != "" {
		logn("[_zoobee_]: listening on", s.Addr(), "| pcap:", s.cfg.PcapRules)
	} else {
		logn("[_zoobee_]: listening on", s.Addr())
	}
	return s.readLoop()
}

func (s *Server) cleanup() {
	s.mu.Lock()
	if s.rawSock >= 0 {
		_ = syscall.Close(s.rawSock)
		s.rawSock = -1
	}
	links, objs := s.links, s.objs
	s.links = nil
	s.mu.Unlock()
	closeLinks(links)
	_ = objs.Close()
}

func (s *Server) loadBPF() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedCaptureObject))
	if err != nil {
		return fmt.Errorf("load embedded ebpf_capture.o: %w", err)
	}
	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	if err := s.configureCaptureProgram(&objs); err != nil {
		_ = objs.Close()
		return err
	}
	packetSock, err := openPacketSocket(s.cfg.IfIndex)
	if err != nil {
		_ = objs.Close()
		return err
	}
	if err := syscall.SetsockoptInt(packetSock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, objs.CaptureProg.FD()); err != nil {
		_ = syscall.Close(packetSock)
		_ = objs.Close()
		return fmt.Errorf("attach socket filter: %w", err)
	}
	links, err := attachProbeLinks(&objs)
	if err != nil {
		_ = syscall.Close(packetSock)
		_ = objs.Close()
		return err
	}
	s.mu.Lock()
	s.objs = objs
	s.links = links
	s.rawSock = packetSock
	s.state.flowOwnerMap = objs.FlowOwnerMap
	s.mu.Unlock()
	return nil
}

func attachProbeLinks(objs *bpfObjects) ([]link.Link, error) {
	bindings := []struct {
		name    string
		attach  func() (link.Link, error)
		message string
	}{
		{name: "tcp_connect", attach: func() (link.Link, error) { return link.Kprobe("tcp_connect", objs.TrackTCPConnect, nil) }, message: "attach tcp_connect"},
		{name: "inet_csk_accept", attach: func() (link.Link, error) { return link.Kretprobe("inet_csk_accept", objs.TrackTCPAccept, nil) }, message: "attach inet_csk_accept"},
		{name: "tcp_sendmsg", attach: func() (link.Link, error) { return link.Kprobe("tcp_sendmsg", objs.TrackTCPSendmsg, nil) }, message: "attach tcp_sendmsg"},
		{name: "udp_sendmsg", attach: func() (link.Link, error) { return link.Kprobe("udp_sendmsg", objs.TrackUDPSendmsg, nil) }, message: "attach udp_sendmsg"},
	}
	links := make([]link.Link, 0, len(bindings))
	for _, binding := range bindings {
		l, err := binding.attach()
		if err != nil {
			closeLinks(links)
			return nil, fmt.Errorf("%s: %w", binding.message, err)
		}
		links = append(links, l)
	}
	return links, nil
}

func (s *Server) configureCaptureProgram(objs *bpfObjects) error {
	insns, err := compilePcapRules(s.cfg.PcapRules)
	if err != nil {
		return err
	}
	key := uint32(0)
	cc := captureConfig{IfIndex: uint32(s.cfg.IfIndex), PcapLen: uint32(len(insns))}
	if err := objs.CaptureConfigMap.Update(key, cc, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update capture_config_map: %w", err)
	}
	for i, insn := range insns {
		idx := uint32(i)
		if err := objs.PcapInsns.Update(idx, insn, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update pcap_insns[%d]: %w", i, err)
		}
	}
	return nil
}

func (s *Server) readLoop() error {
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.ctx.Done():
			return context.Canceled
		default:
		}
		n, from, err := syscall.Recvfrom(s.rawSock, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			if s.ctx.Err() != nil {
				return context.Canceled
			}
			return fmt.Errorf("recvfrom: %w", err)
		}
		if n <= 0 {
			continue
		}
		direction := uint8(0)
		if sa, ok := from.(*syscall.SockaddrLinklayer); ok && sa.Pkttype == packetOutgoing {
			direction = 1
		}
		s.handlePacket(buf[:n], direction)
	}
}

func (s *Server) handlePacket(packet []byte, direction uint8) {
	var e PacketEvent
	if !parsePacket(packet, direction, &e) {
		return
	}
	now := time.Now()
	meta, ok := s.resolvePacketMeta(&e, now)
	if !ok {
		meta = SocketMeta{}
	}
	if !packetMatchesFilters(&e, &meta, s.cfg) {
		return
	}
	switch e.L4Proto {
	case ipProtoTCP:
		s.processTCPFlow(&e, &meta, now)
	case ipProtoUDP:
		s.processUDPPacket(&e, &meta)
	}
	if s.state.lastGC.IsZero() || now.Sub(s.state.lastGC) > flowGCInterval {
		s.flowGC(now.Add(-flowIdleTimeout))
		s.state.lastGC = now
	}
}

func (s *Server) resolvePacketMeta(e *PacketEvent, now time.Time) (SocketMeta, bool) {
	if meta, ok := s.flowOwnerMapLookup(e); ok {
		return meta, true
	}
	if meta, ok := s.socketCacheLookupListener(e); ok && meta.PID > 0 {
		return meta, true
	}
	if meta, ok := s.socketCacheLookupDirectional(e); ok {
		return meta, true
	}
	if s.state.sockets.lastRefresh.IsZero() || now.Sub(s.state.sockets.lastRefresh) > socketCacheRefresh {
		if err := s.rebuildSocketCache(); err == nil {
			if meta, ok := s.socketCacheLookupDirectional(e); ok {
				return meta, true
			}
		}
	}
	if meta, ok := s.socketCacheLookupListener(e); ok {
		return meta, true
	}
	return SocketMeta{}, false
}

func (s *Server) flowOwnerMapLookup(e *PacketEvent) (SocketMeta, bool) {
	if s.state.flowOwnerMap == nil {
		return SocketMeta{}, false
	}
	key := flowOwnerLookupKey(e)
	val := flowOwnerValue{}
	if err := s.state.flowOwnerMap.Lookup(key, &val); err != nil {
		return SocketMeta{}, false
	}
	return socketMetaFromOwnerValue(e, val), true
}

func (s *Server) socketCacheLookupDirectional(e *PacketEvent) (SocketMeta, bool) {
	meta, ok := s.state.sockets.items[directionalSocketKey(e)]
	return meta, ok
}

func (s *Server) socketCacheLookupListener(e *PacketEvent) (SocketMeta, bool) {
	if e.L4Proto != ipProtoTCP {
		return SocketMeta{}, false
	}
	listenPort := e.Dport
	if e.Direction == 1 {
		listenPort = e.Sport
	}
	for _, meta := range s.state.sockets.listenerItems {
		familyMatch := meta.Family == int(e.Family) || (e.Family == afINET && meta.Family == afINET6)
		if !familyMatch || meta.Proto != int(e.L4Proto) {
			continue
		}
		if meta.Sport != listenPort || meta.Dport != 0 {
			continue
		}
		return meta, true
	}
	return SocketMeta{}, false
}

func directionalSocketKey(e *PacketEvent) socketKey {
	key := socketKey{Family: int(e.Family), Proto: int(e.L4Proto)}
	copyDirectionalAddrs(e, key.Saddr[:], key.Daddr[:])
	if e.Direction == 1 {
		key.Sport = e.Sport
		key.Dport = e.Dport
	} else {
		key.Sport = e.Dport
		key.Dport = e.Sport
	}
	return key
}

func flowOwnerLookupKey(e *PacketEvent) flowOwnerKey {
	key := flowOwnerKey{Family: e.Family, L4Proto: e.L4Proto}
	copyDirectionalAddrs(e, key.Saddr[:], key.Daddr[:])
	if e.Direction == 1 {
		key.Sport = e.Sport
		key.Dport = e.Dport
	} else {
		key.Sport = e.Dport
		key.Dport = e.Sport
	}
	return key
}

func copyDirectionalAddrs(e *PacketEvent, saddr, daddr []byte) {
	addrLen := 4
	if e.Family == afINET6 {
		addrLen = 16
	}
	if e.Direction == 1 {
		copy(saddr[:addrLen], e.Saddr[:addrLen])
		copy(daddr[:addrLen], e.Daddr[:addrLen])
		return
	}
	copy(saddr[:addrLen], e.Daddr[:addrLen])
	copy(daddr[:addrLen], e.Saddr[:addrLen])
}

func socketMetaFromOwnerValue(e *PacketEvent, val flowOwnerValue) SocketMeta {
	return SocketMeta{
		Family: int(e.Family),
		Proto:  int(e.L4Proto),
		Sport:  e.Sport,
		Dport:  e.Dport,
		PID:    int(val.PIDTGID >> 32),
		UID:    val.UID,
		CRID:   val.CRID,
		CRPID:  val.CRPID,
		Comm:   string(bytes.TrimRight(val.Comm[:], "\x00")),
	}
}

func (s *Server) rebuildSocketCache() error {
	owners, err := buildInodeOwners()
	if err != nil {
		return err
	}
	cache := socketCache{items: make(map[socketKey]SocketMeta)}
	for _, table := range []struct {
		path   string
		family int
		proto  int
	}{{"/proc/net/tcp", afINET, ipProtoTCP}, {"/proc/net/tcp6", afINET6, ipProtoTCP}, {"/proc/net/udp", afINET, ipProtoUDP}, {"/proc/net/udp6", afINET6, ipProtoUDP}} {
		if err := parseProcNetTable(table.path, table.family, table.proto, owners, &cache); err != nil {
			return err
		}
	}
	cache.lastRefresh = time.Now()
	s.state.sockets = cache
	return nil
}

func buildInodeOwners() (map[uint64]procOwner, error) {
	owners := make(map[uint64]procOwner)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err != nil {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			continue
		}
		uid, ok1 := parseStatusUID(status)
		crpid, ok2 := parseStatusCRPID(status)
		crid, ok3 := readCRID(pid)
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if len(owners) >= procOwnerMaxItems {
				break
			}
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := parseSocketInode(target)
			if !ok {
				continue
			}
			if _, exists := owners[inode]; exists {
				continue
			}
			owners[inode] = procOwner{Inode: inode, PID: pid, UID: uid, CRID: crid, CRPID: crpid, Comm: strings.TrimSpace(string(comm))}
		}
	}
	return owners, nil
}

func parseProcNetTable(path string, family, proto int, owners map[uint64]procOwner, cache *socketCache) error {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localAddr, localPort, ok := parseSocketToken(family, fields[1])
		if !ok {
			continue
		}
		remoteAddr, remotePort, ok := parseSocketToken(family, fields[2])
		if !ok {
			continue
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		meta := SocketMeta{Family: family, Proto: proto, Sport: localPort, Dport: remotePort, Inode: inode}
		copy(meta.Saddr[:], localAddr[:])
		copy(meta.Daddr[:], remoteAddr[:])
		if owner, ok := owners[inode]; ok {
			meta.PID = owner.PID
			meta.UID = owner.UID
			meta.CRID = owner.CRID
			meta.CRPID = owner.CRPID
			meta.Comm = owner.Comm
		}
		key := socketKey{Family: family, Proto: proto, Saddr: meta.Saddr, Daddr: meta.Daddr, Sport: meta.Sport, Dport: meta.Dport}
		if len(cache.items) < socketCacheMaxItems {
			cache.items[key] = meta
		}
		if proto == ipProtoTCP && meta.Dport == 0 {
			cache.listenerItems = append(cache.listenerItems, meta)
		}
	}
	return s.Err()
}

func (s *Server) processTCPFlow(e *PacketEvent, meta *SocketMeta, now time.Time) {
	key := makeFlowKey(e)
	flow := s.flowGet(key, now)
	if flow == nil {
		return
	}
	if meta != nil && meta.PID > 0 {
		flow.PID = meta.PID
		flow.UID = meta.UID
		flow.CRID = meta.CRID
		flow.CRPID = meta.CRPID
		flow.Comm = meta.Comm
	}
	reverseKey := makeReverseFlowKey(e)
	peer := s.state.flows[reverseKey]
	effectiveMeta := meta
	if (effectiveMeta == nil || effectiveMeta.PID <= 0) && peer != nil && peer.PID > 0 {
		effectiveMeta = &SocketMeta{PID: peer.PID, UID: peer.UID, CRID: peer.CRID, CRPID: peer.CRPID, Comm: peer.Comm}
	}
	flow.TCPBuffer = bufferAppend(flow.TCPBuffer, e.Payload, flowBufferCap)
	reqOff := -1
	if !flow.TLSEmitted {
		reqOff = findTLSHandshakeRecordOffset(flow.TCPBuffer, 0x01)
	}
	if reqOff >= 0 {
		tlsData := flow.TCPBuffer[reqOff:]
		sni, alpn, ver, ok := parseTLSClientHello(tlsData)
		if ok {
			if sni != "" {
				flow.Domain = sni
				flow.HasDomain = true
			}
			s.emitHTTPS(e, effectiveMeta, "request", httpVersionFromALPN(alpn), tlsVersionName(ver), sni, alpn, ver, tlsData, "tcp")
			flow.TLSEmitted = true
			flow.TCPBuffer = flow.TCPBuffer[:0]
			return
		}
	}
	respOff := -1
	if !flow.TLSEmitted {
		respOff = findTLSHandshakeRecordOffset(flow.TCPBuffer, 0x02)
	}
	if respOff >= 0 {
		tlsData := flow.TCPBuffer[respOff:]
		alpn, ver, ok := parseTLSServerHello(tlsData)
		if ok {
			sni := ""
			if peer != nil && peer.HasDomain {
				sni = peer.Domain
			}
			s.emitHTTPS(e, effectiveMeta, "response", httpVersionFromALPN(alpn), tlsVersionName(ver), sni, alpn, ver, tlsData, "tcp")
			flow.TLSEmitted = true
			flow.TCPBuffer = flow.TCPBuffer[:0]
			return
		}
	}
	for len(flow.TCPBuffer) > 0 {
		msg, ok := parseHTTPMessage(flow.TCPBuffer, s.cfg.BodyLimit)
		if !ok || msg.Consumed == 0 || msg.Consumed > len(flow.TCPBuffer) {
			break
		}
		if msg.Host == "" && peer != nil && peer.HasDomain {
			msg.Host = peer.Domain
		}
		if msg.Host != "" {
			flow.Domain = msg.Host
			flow.HasDomain = true
		}
		var body []byte
		if len(msg.BodyCopy) > 0 {
			body = msg.BodyCopy
		} else if msg.BodyLen > 0 && msg.HeaderEnd+msg.BodyLen <= len(flow.TCPBuffer) {
			body = flow.TCPBuffer[msg.HeaderEnd : msg.HeaderEnd+msg.BodyLen]
		}
		s.emitHTTP(e, effectiveMeta, msg, flow.TCPBuffer[:msg.HeaderEnd], body)
		flow.TCPBuffer = bufferConsume(flow.TCPBuffer, msg.Consumed)
		flow.TLSEmitted = false
	}
}

func (s *Server) processUDPPacket(e *PacketEvent, meta *SocketMeta) {
	tlsData, ok := findQUICTLSPayload(e.Payload)
	if !ok {
		return
	}
	sni, alpn, ver, ok := parseTLSClientHello(tlsData)
	if !ok {
		return
	}
	s.emitHTTPS(e, meta, "request", httpVersionFromALPN(alpn), tlsVersionName(ver), sni, alpn, ver, e.Payload, "udp")
}

func (s *Server) emitHTTP(event *PacketEvent, meta *SocketMeta, msg httpMessage, headers, body []byte) {
	record := s.baseRecord(event, meta)
	record["domain"] = msg.Host
	record["proto"] = "http"
	typeVal := "request"
	if msg.Response {
		typeVal = "response"
	}
	record["type"] = typeVal
	httpPart := map[string]any{
		"type":        typeVal,
		"version":     msg.Version,
		"payload_len": event.PayloadLen,
		"body_len":    len(body),
		"headers_raw": string(headers),
	}
	if msg.Response {
		httpPart["status"] = msg.Status
	} else {
		httpPart["method"] = msg.Method
		httpPart["path"] = msg.Path
	}
	if msg.Host != "" {
		httpPart["host"] = msg.Host
	}
	if len(body) > 0 {
		httpPart["body"] = string(body)
	}
	record["http"] = httpPart
	s.emit(Event{Packet: event, Meta: meta, Record: record})
}

func (s *Server) emitHTTPS(event *PacketEvent, meta *SocketMeta, typ, httpVer, tlsVer, sni, alpn string, recordVersion uint16, payload []byte, transport string) {
	record := s.baseRecord(event, meta)
	record["domain"] = sni
	record["proto"] = "https"
	record["type"] = typ
	httpsPart := map[string]any{
		"type":               typ,
		"version":            httpVer,
		"tls_version":        tlsVer,
		"domain":             sni,
		"payload_len":        len(payload),
		"tls_record_version": recordVersion,
	}
	if alpn != "" {
		httpsPart["alpn"] = alpn
	}
	record["transport"] = transport
	record["https"] = httpsPart
	s.emit(Event{Packet: event, Meta: meta, Record: record})
}

func (s *Server) emit(ev Event) {
	if s.hook != nil {
		s.hook(ev.Record)
		return
	}
	bts, err := json.Marshal(ev.Record)
	if err != nil {
		logn("[_zoobee_]: marshal event error", err)
		return
	}
	fmt.Printf("EBPF_CAPTURE: %s\n", bts)
}

func (s *Server) baseRecord(e *PacketEvent, meta *SocketMeta) map[string]any {
	ms := time.Now()
	key := recordKeyHex(*e, meta)
	id := makeRecordID(&s.state.recordSeq, ms)
	record := map[string]any{
		"id":        id,
		"ts":        ms.UnixMilli(),
		"time":      ms.Format("2006-01-02T15:04:05.000-07:00"),
		"key":       key,
		"family":    familyName(int(e.Family)),
		"transport": transportName(int(e.L4Proto)),
		"direction": directionName(e.Direction),
		"src_ip":    ipToString(int(e.Family), e.Saddr),
		"src_port":  e.Sport,
		"dst_ip":    ipToString(int(e.Family), e.Daddr),
		"dst_port":  e.Dport,
	}
	if meta != nil {
		record["pid"] = meta.PID
		record["uid"] = meta.UID
		record["cr_id"] = meta.CRID
		record["cr_pid"] = meta.CRPID
		record["comm"] = meta.Comm
	} else {
		record["pid"] = 0
		record["uid"] = 0
		record["cr_id"] = 0
		record["cr_pid"] = 0
		record["comm"] = ""
	}
	return record
}

func flowKeyHex(e PacketEvent, pid int) string {
	h := fnv.New64a()
	addrLen := 4
	if e.Family == afINET6 {
		addrLen = 16
	}
	leftAddr := e.Saddr[:addrLen]
	rightAddr := e.Daddr[:addrLen]
	leftPort, rightPort := e.Sport, e.Dport
	if cmp := bytes.Compare(leftAddr, rightAddr); cmp > 0 || (cmp == 0 && leftPort > rightPort) {
		leftAddr, rightAddr = rightAddr, leftAddr
		leftPort, rightPort = rightPort, leftPort
	}
	_, _ = h.Write(leftAddr)
	_, _ = h.Write([]byte{byte(leftPort >> 8), byte(leftPort)})
	_, _ = h.Write(rightAddr)
	_, _ = h.Write([]byte{byte(rightPort >> 8), byte(rightPort)})
	_, _ = h.Write([]byte{e.L4Proto})
	_, _ = h.Write([]byte(strconv.Itoa(pid)))
	return fmt.Sprintf("%016x", h.Sum64())
}

func (s *Server) flowGet(key flowKey, now time.Time) *flowState {
	if flow, ok := s.state.flows[key]; ok {
		flow.LastSeen = now
		return flow
	}
	if len(s.state.flows) >= flowStateMaxItems {
		var oldestKey flowKey
		var oldest *flowState
		for k, flow := range s.state.flows {
			if oldest == nil || flow.LastSeen.Before(oldest.LastSeen) {
				oldest = flow
				oldestKey = k
			}
		}
		if oldest != nil {
			delete(s.state.flows, oldestKey)
		}
	}
	flow := &flowState{Key: key, LastSeen: now}
	s.state.flows[key] = flow
	return flow
}

func (s *Server) flowGC(cutoff time.Time) {
	for k, flow := range s.state.flows {
		if flow.LastSeen.Before(cutoff) {
			delete(s.state.flows, k)
		}
	}
}

func normalizeConfig(cfg Config) (runtimeConfig, error) {
	rc := runtimeConfig{
		IfName:    strings.TrimSpace(cfg.IfName),
		PcapRules: strings.TrimSpace(cfg.PcapRules),
		BodyLimit: cfg.MaxBodySize,
	}
	if rc.BodyLimit == 0 {
		rc.BodyLimit = -1
	}
	switch strings.TrimSpace(cfg.Direction) {
	case "", "both":
		rc.DirectionFilter = -1
	case "ingress":
		rc.DirectionFilter = 0
	case "egress":
		rc.DirectionFilter = 1
	default:
		return rc, fmt.Errorf("invalid direction: %s", cfg.Direction)
	}
	if rc.IfName != "" {
		iface, err := net.InterfaceByName(rc.IfName)
		if err != nil {
			return rc, err
		}
		rc.IfIndex = iface.Index
	}
	maxIntValue := uint(^uint(0) >> 1)
	if cfg.PID > maxIntValue {
		return rc, fmt.Errorf("pid out of range: %d", cfg.PID)
	}
	rc.HavePIDFilter = cfg.PID > 0
	rc.PIDFilter = int(cfg.PID)
	if cfg.CPID > uint(^uint32(0)) {
		return rc, fmt.Errorf("cpid out of range: %d", cfg.CPID)
	}
	rc.HaveCPIDFilter = cfg.CPID > 0
	rc.CPIDFilter = uint32(cfg.CPID)
	rc.HaveCRIDFilter = cfg.CRID > 0
	rc.CRIDFilter = cfg.CRID
	if comm := strings.TrimSpace(cfg.Comm); comm != "" {
		rc.HaveCommFilter = true
		rc.CommFilter = comm
	}
	if cfg.Sport > uint(^uint16(0)) {
		return rc, fmt.Errorf("sport out of range: %d", cfg.Sport)
	}
	rc.HaveSportFilter = cfg.Sport > 0
	rc.SportFilter = uint16(cfg.Sport)
	if cfg.Dport > uint(^uint16(0)) {
		return rc, fmt.Errorf("dport out of range: %d", cfg.Dport)
	}
	rc.HaveDportFilter = cfg.Dport > 0
	rc.DportFilter = uint16(cfg.Dport)
	var err error
	rc.SrcRules, err = parseCIDRList(strings.TrimSpace(cfg.SrcSpec))
	if err != nil {
		return rc, err
	}
	rc.DstRules, err = parseCIDRList(strings.TrimSpace(cfg.DstSpec))
	if err != nil {
		return rc, err
	}
	return rc, nil
}

func openPacketSocket(ifIndex int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return -1, err
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if ifIndex > 0 {
		sa := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifIndex}
		if err := syscall.Bind(fd, sa); err != nil {
			_ = syscall.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

func transportName(proto int) string {
	if proto == ipProtoUDP {
		return "udp"
	}
	return "tcp"
}

func familyName(family int) string {
	if family == afINET6 {
		return "ipv6"
	}
	return "ipv4"
}

func directionName(direction uint8) string {
	if direction == 0 {
		return "ingress"
	}
	return "egress"
}

func ipToString(family int, addr [16]byte) string {
	if family == afINET6 {
		return net.IP(addr[:16]).String()
	}
	return net.IP(addr[:4]).String()
}

func parsePacket(packet []byte, direction uint8, e *PacketEvent) bool {
	*e = PacketEvent{Direction: direction}
	if len(packet) < 14 {
		return false
	}
	offset := 0
	hProto := binary.BigEndian.Uint16(packet[12:14])
	offset += 14
	if hProto == ethP8021Q || hProto == ethP8021AD {
		if len(packet) < offset+4 {
			return false
		}
		hProto = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		offset += 4
	}
	switch hProto {
	case ethPIP:
		if len(packet) < offset+20 {
			return false
		}
		ihl := int(packet[offset]&0x0f) * 4
		if ihl < 20 || len(packet) < offset+ihl {
			return false
		}
		e.Family = afINET
		copy(e.Saddr[:4], packet[offset+12:offset+16])
		copy(e.Daddr[:4], packet[offset+16:offset+20])
		e.L4Proto = packet[offset+9]
		offset += ihl
		switch e.L4Proto {
		case ipProtoTCP:
			if len(packet) < offset+20 {
				return false
			}
			tcpHdrLen := int((packet[offset+12] >> 4) * 4)
			if tcpHdrLen < 20 || len(packet) < offset+tcpHdrLen {
				return false
			}
			e.Sport = binary.BigEndian.Uint16(packet[offset : offset+2])
			e.Dport = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			offset += tcpHdrLen
		case ipProtoUDP:
			if len(packet) < offset+8 {
				return false
			}
			e.Sport = binary.BigEndian.Uint16(packet[offset : offset+2])
			e.Dport = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			offset += 8
		default:
			return false
		}
	case ethPIPv6:
		if len(packet) < offset+40 {
			return false
		}
		e.Family = afINET6
		copy(e.Saddr[:16], packet[offset+8:offset+24])
		copy(e.Daddr[:16], packet[offset+24:offset+40])
		next := packet[offset+6]
		offset += 40
		for next == ipProtoHOPOPTS || next == ipProtoRouting || next == ipProtoFragment || next == ipProtoAH || next == ipProtoDSTOPTS {
			if len(packet) < offset+8 {
				return false
			}
			hdrLen := int(packet[offset+1]+1) * 8
			if next == ipProtoFragment {
				hdrLen = 8
			}
			if len(packet) < offset+hdrLen {
				return false
			}
			next = packet[offset]
			offset += hdrLen
		}
		e.L4Proto = next
		switch next {
		case ipProtoTCP:
			if len(packet) < offset+20 {
				return false
			}
			tcpHdrLen := int((packet[offset+12] >> 4) * 4)
			if tcpHdrLen < 20 || len(packet) < offset+tcpHdrLen {
				return false
			}
			e.Sport = binary.BigEndian.Uint16(packet[offset : offset+2])
			e.Dport = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			offset += tcpHdrLen
		case ipProtoUDP:
			if len(packet) < offset+8 {
				return false
			}
			e.Sport = binary.BigEndian.Uint16(packet[offset : offset+2])
			e.Dport = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			offset += 8
		default:
			return false
		}
	default:
		return false
	}
	if offset > len(packet) {
		return false
	}
	payload := packet[offset:]
	e.PayloadLen = uint32(len(payload))
	if len(payload) > capPayload {
		e.CapLen = capPayload
		e.Payload = append([]byte(nil), payload[:capPayload]...)
	} else {
		e.CapLen = uint32(len(payload))
		e.Payload = append([]byte(nil), payload...)
	}
	return true
}

func makeFlowKey(e *PacketEvent) flowKey {
	key := flowKey{Family: e.Family, L4Proto: e.L4Proto, Direction: e.Direction, Sport: e.Sport, Dport: e.Dport}
	if e.Family == afINET {
		copy(key.Saddr[:4], e.Saddr[:4])
		copy(key.Daddr[:4], e.Daddr[:4])
	} else {
		copy(key.Saddr[:16], e.Saddr[:16])
		copy(key.Daddr[:16], e.Daddr[:16])
	}
	return key
}

func makeReverseFlowKey(e *PacketEvent) flowKey {
	key := flowKey{Family: e.Family, L4Proto: e.L4Proto, Direction: 1 - e.Direction, Sport: e.Dport, Dport: e.Sport}
	if e.Family == afINET {
		copy(key.Saddr[:4], e.Daddr[:4])
		copy(key.Daddr[:4], e.Saddr[:4])
	} else {
		copy(key.Saddr[:16], e.Daddr[:16])
		copy(key.Daddr[:16], e.Saddr[:16])
	}
	return key
}

func bufferAppend(buf, data []byte, limit int) []byte {
	if len(data) == 0 {
		return buf
	}
	if len(data) >= limit {
		return append([]byte(nil), data[len(data)-limit:]...)
	}
	if len(buf)+len(data) > limit {
		drop := len(buf) + len(data) - limit
		buf = append([]byte(nil), buf[drop:]...)
	}
	return append(buf, data...)
}

func bufferConsume(buf []byte, n int) []byte {
	if n <= 0 {
		return buf
	}
	if n >= len(buf) {
		return buf[:0]
	}
	copy(buf, buf[n:])
	return buf[:len(buf)-n]
}

func parseHTTPMessage(data []byte, bodyLimit int64) (httpMessage, bool) {
	var msg httpMessage
	if len(data) < 4 {
		return msg, false
	}
	isResp := bytes.HasPrefix(data, []byte("HTTP/"))
	isReq := isHTTPRequestStart(data)
	if !isResp && !isReq {
		return msg, false
	}
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return msg, false
	}
	headerEnd += 4
	headers := data[:headerEnd]
	lines := bytes.Split(headers[:headerEnd-2], []byte("\r\n"))
	if len(lines) == 0 {
		return msg, false
	}
	first := string(lines[0])
	msg.Response = isResp
	if isResp {
		parts := strings.SplitN(first, " ", 3)
		if len(parts) < 2 {
			return msg, false
		}
		msg.Version = parts[0]
		msg.Status = parts[1]
	} else {
		parts := strings.SplitN(first, " ", 3)
		if len(parts) < 3 {
			return msg, false
		}
		msg.Method = parts[0]
		msg.Path = parts[1]
		msg.Version = parts[2]
	}
	msg.Host = extractHeaderValue(headers, "Host:")
	contentLength := parseContentLengthHeader(headers)
	chunked := headerHasChunkedEncoding(headers)
	bodyAvailable := len(data) - headerEnd
	noBodyResponse := msg.Response && (strings.HasPrefix(msg.Status, "1") || strings.HasPrefix(msg.Status, "204") || strings.HasPrefix(msg.Status, "304"))
	noBodyRequest := !msg.Response && (strings.EqualFold(msg.Method, "GET") || strings.EqualFold(msg.Method, "HEAD") || strings.EqualFold(msg.Method, "OPTIONS") || strings.EqualFold(msg.Method, "TRACE"))
	msg.HeaderEnd = headerEnd
	if !noBodyRequest && !noBodyResponse {
		if chunked {
			if bodyLimit < 0 {
				msg.Consumed = headerEnd
				return msg, true
			}
			bodyCopy, bodyLen, consumed, ok := parseChunkedBody(data[headerEnd:], bodyLimit)
			if !ok {
				return msg, false
			}
			msg.BodyCopy = bodyCopy
			msg.BodyLen = bodyLen
			msg.Consumed = headerEnd + consumed
			return msg, true
		}
		bodyToKeep := 0
		switch {
		case bodyLimit < 0:
			bodyToKeep = 0
		case bodyLimit == 0:
			if contentLength >= 0 {
				if bodyAvailable < contentLength {
					return msg, false
				}
				bodyToKeep = contentLength
			} else {
				bodyToKeep = bodyAvailable
			}
		default:
			target := bodyAvailable
			if contentLength >= 0 && contentLength < target {
				target = contentLength
			}
			if int(bodyLimit) < target {
				target = int(bodyLimit)
			}
			if bodyAvailable < target {
				return msg, false
			}
			bodyToKeep = target
		}
		msg.BodyLen = bodyToKeep
		if contentLength >= 0 {
			msg.Consumed = headerEnd + contentLength
		} else if bodyToKeep > 0 {
			msg.Consumed = headerEnd + bodyToKeep
		} else {
			msg.Consumed = headerEnd
		}
		if msg.Consumed > len(data) {
			msg.Consumed = len(data)
		}
	} else {
		msg.Consumed = headerEnd
	}
	return msg, true
}

func parseChunkedBody(data []byte, bodyLimit int64) ([]byte, int, int, bool) {
	keepLimit := 0
	if bodyLimit == 0 {
		keepLimit = int(^uint(0) >> 1)
	} else if bodyLimit > 0 {
		keepLimit = int(bodyLimit)
	}
	keep := make([]byte, 0)
	pos := 0
	for {
		lineEnd := bytes.Index(data[pos:], []byte("\r\n"))
		if lineEnd < 0 {
			return nil, 0, 0, false
		}
		line := string(data[pos : pos+lineEnd])
		if semi := strings.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}
		chunkSize, err := strconv.ParseUint(strings.TrimSpace(line), 16, 32)
		if err != nil {
			return nil, 0, 0, false
		}
		pos += lineEnd + 2
		if chunkSize == 0 {
			if len(data[pos:]) >= 2 && bytes.Equal(data[pos:pos+2], []byte("\r\n")) {
				pos += 2
			} else if trail := bytes.Index(data[pos:], []byte("\r\n\r\n")); trail >= 0 {
				pos += trail + 4
			} else {
				return nil, 0, 0, false
			}
			break
		}
		if len(data[pos:]) < int(chunkSize)+2 {
			return nil, 0, 0, false
		}
		if keepLimit > 0 && len(keep) < keepLimit {
			copyLen := int(chunkSize)
			if len(keep)+copyLen > keepLimit {
				copyLen = keepLimit - len(keep)
			}
			keep = append(keep, data[pos:pos+copyLen]...)
		}
		pos += int(chunkSize)
		if !bytes.Equal(data[pos:pos+2], []byte("\r\n")) {
			return nil, 0, 0, false
		}
		pos += 2
	}
	return keep, len(keep), pos, true
}

func isHTTPRequestStart(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return bytes.HasPrefix(data, []byte("GET ")) || bytes.HasPrefix(data, []byte("POST")) || bytes.HasPrefix(data, []byte("HEAD")) || bytes.HasPrefix(data, []byte("PUT ")) || bytes.HasPrefix(data, []byte("DELE")) || bytes.HasPrefix(data, []byte("OPTI")) || bytes.HasPrefix(data, []byte("PATC")) || bytes.HasPrefix(data, []byte("CONN")) || bytes.HasPrefix(data, []byte("TRAC"))
}

func extractHeaderValue(headers []byte, name string) string {
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		if bytes.HasPrefix(bytes.ToLower(line), bytes.ToLower([]byte(name))) {
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				return strings.TrimSpace(string(parts[1]))
			}
		}
	}
	return ""
}

func parseContentLengthHeader(headers []byte) int {
	v := extractHeaderValue(headers, "Content-Length:")
	if v == "" {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return -1
	}
	return n
}

func headerHasChunkedEncoding(headers []byte) bool {
	v := strings.ToLower(extractHeaderValue(headers, "Transfer-Encoding:"))
	return strings.Contains(v, "chunked")
}

func findTLSHandshakeRecordOffset(data []byte, handshakeType byte) int {
	if len(data) < 5 {
		return -1
	}
	maxScan := len(data) - 5
	if maxScan > 128 {
		maxScan = 128
	}
	for i := 0; i <= maxScan; i++ {
		if !looksLikeTLSRecord(data[i:]) {
			continue
		}
		offset := i
		for depth := 0; depth < 8 && offset+5 <= len(data); depth++ {
			record := data[offset:]
			if !looksLikeTLSRecord(record) {
				break
			}
			recordLen := int(binary.BigEndian.Uint16(record[3:5]))
			totalLen := 5 + recordLen
			if offset+totalLen > len(data) {
				return -1
			}
			if record[0] == 0x16 && recordLen >= 4 && record[5] == handshakeType {
				return offset
			}
			offset += totalLen
		}
	}
	return -1
}

func looksLikeTLSRecord(data []byte) bool {
	if len(data) < 5 || data[1] != 0x03 || data[2] > 0x04 {
		return false
	}
	switch data[0] {
	case 0x14, 0x15, 0x16, 0x17:
		return true
	default:
		return false
	}
}

func parseTLSClientHello(data []byte) (string, string, uint16, bool) {
	if len(data) < 9 || data[0] != 0x16 {
		return "", "", 0, false
	}
	recordVersion := binary.BigEndian.Uint16(data[1:3])
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen || data[5] != 0x01 {
		return "", "", 0, false
	}
	helloLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	helloEnd := 9 + helloLen
	if helloEnd > 5+recordLen || helloEnd > len(data) {
		return "", "", 0, false
	}
	q := 9 + 2 + 32
	if q+1 > helloEnd {
		return "", "", 0, false
	}
	sidLen := int(data[q])
	q += 1 + sidLen
	if q+2 > helloEnd {
		return "", "", 0, false
	}
	csLen := int(binary.BigEndian.Uint16(data[q : q+2]))
	q += 2 + csLen
	if q+1 > helloEnd {
		return "", "", 0, false
	}
	compLen := int(data[q])
	q += 1 + compLen
	if q+2 > helloEnd {
		return "", "", 0, false
	}
	extLen := int(binary.BigEndian.Uint16(data[q : q+2]))
	q += 2
	extEnd := q + extLen
	if extEnd > helloEnd {
		return "", "", 0, false
	}
	sni, alpn, best := "", "", recordVersion
	for q+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[q : q+2])
		extSize := int(binary.BigEndian.Uint16(data[q+2 : q+4]))
		q += 4
		if q+extSize > extEnd {
			break
		}
		body := data[q : q+extSize]
		switch extType {
		case 0x0000:
			if len(body) >= 5 {
				listLen := int(binary.BigEndian.Uint16(body[:2]))
				pos := 2
				limit := 2 + listLen
				if limit > len(body) {
					limit = len(body)
				}
				for pos+3 <= limit {
					nameType := body[pos]
					nameLen := int(binary.BigEndian.Uint16(body[pos+1 : pos+3]))
					pos += 3
					if pos+nameLen > limit {
						break
					}
					if nameType == 0 {
						sni = string(body[pos : pos+nameLen])
						break
					}
					pos += nameLen
				}
			}
		case 0x0010:
			if len(body) >= 3 {
				listLen := int(binary.BigEndian.Uint16(body[:2]))
				if 3 <= len(body) && 2+listLen <= len(body) {
					protoLen := int(body[2])
					if 3+protoLen <= len(body) {
						alpn = string(body[3 : 3+protoLen])
					}
				}
			}
		case 0x002b:
			if len(body) >= 3 {
				versionsLen := int(body[0])
				limit := 1 + versionsLen
				if limit > len(body) {
					limit = len(body)
				}
				for pos := 1; pos+1 < limit; pos += 2 {
					candidate := binary.BigEndian.Uint16(body[pos : pos+2])
					if candidate > best {
						best = candidate
					}
				}
			}
		}
		q += extSize
	}
	return sni, alpn, best, true
}

func parseTLSServerHello(data []byte) (string, uint16, bool) {
	if len(data) < 9 || data[0] != 0x16 {
		return "", 0, false
	}
	recordVersion := binary.BigEndian.Uint16(data[1:3])
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen || data[5] != 0x02 {
		return "", 0, false
	}
	helloLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	helloEnd := 9 + helloLen
	if helloEnd > 5+recordLen || helloEnd > len(data) {
		return "", 0, false
	}
	q := 9 + 2 + 32
	if q+1 > helloEnd {
		return "", 0, false
	}
	sidLen := int(data[q])
	q += 1 + sidLen
	if q+3 > helloEnd {
		return "", 0, false
	}
	q += 3
	if q+2 > helloEnd {
		return "", 0, false
	}
	extLen := int(binary.BigEndian.Uint16(data[q : q+2]))
	q += 2
	extEnd := q + extLen
	if extEnd > helloEnd {
		return "", 0, false
	}
	alpn, ver := "", recordVersion
	for q+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[q : q+2])
		extSize := int(binary.BigEndian.Uint16(data[q+2 : q+4]))
		q += 4
		if q+extSize > extEnd {
			break
		}
		body := data[q : q+extSize]
		switch extType {
		case 0x0010:
			if len(body) >= 3 {
				listLen := int(binary.BigEndian.Uint16(body[:2]))
				if 3 <= len(body) && 2+listLen <= len(body) {
					protoLen := int(body[2])
					if 3+protoLen <= len(body) {
						alpn = string(body[3 : 3+protoLen])
					}
				}
			}
		case 0x002b:
			if len(body) >= 2 {
				ver = binary.BigEndian.Uint16(body[:2])
			}
		}
		q += extSize
	}
	return alpn, ver, true
}

func findQUICTLSPayload(data []byte) ([]byte, bool) {
	if len(data) < 6 || (data[0]&0x80) == 0 {
		return nil, false
	}
	pos := 1 + 4
	if pos+1 > len(data) {
		return nil, false
	}
	dcidLen := int(data[pos])
	pos++
	if pos+dcidLen > len(data) {
		return nil, false
	}
	pos += dcidLen
	if pos+1 > len(data) {
		return nil, false
	}
	scidLen := int(data[pos])
	pos++
	if pos+scidLen > len(data) {
		return nil, false
	}
	pos += scidLen
	tokenLen, used, ok := parseQUICVarint(data[pos:])
	if !ok {
		return nil, false
	}
	pos += used
	if pos+int(tokenLen) > len(data) {
		return nil, false
	}
	pos += int(tokenLen)
	_, used, ok = parseQUICVarint(data[pos:])
	if !ok {
		return nil, false
	}
	pos += used
	if pos > len(data) {
		return nil, false
	}
	return data[pos:], true
}

func parseQUICVarint(data []byte) (uint64, int, bool) {
	if len(data) < 1 {
		return 0, 0, false
	}
	lead := data[0] >> 6
	n := 1 << lead
	if len(data) < int(n) {
		return 0, 0, false
	}
	v := uint64(data[0] & 0x3f)
	for i := 1; i < int(n); i++ {
		v = (v << 8) | uint64(data[i])
	}
	return v, int(n), true
}

func httpVersionFromALPN(alpn string) string {
	if alpn == "" {
		return ""
	}
	if alpn == "h2" {
		return "HTTP/2"
	}
	if alpn == "h3" {
		return "HTTP/3"
	}
	return alpn
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return ""
	}
}

func packetMatchesFilters(e *PacketEvent, meta *SocketMeta, cfg runtimeConfig) bool {
	if cfg.DirectionFilter >= 0 && int(e.Direction) != cfg.DirectionFilter {
		return false
	}
	if cfg.HaveSportFilter && e.Direction == 0 && e.Sport != cfg.SportFilter {
		return false
	}
	if cfg.HaveDportFilter && e.Direction == 1 && e.Dport != cfg.DportFilter {
		return false
	}
	if !cidrSetAccepts(cfg.SrcRules, int(e.Family), e.Saddr) || !cidrSetAccepts(cfg.DstRules, int(e.Family), e.Daddr) {
		return false
	}
	if cfg.HavePIDFilter || cfg.HaveCPIDFilter || cfg.HaveCRIDFilter || cfg.HaveCommFilter {
		if meta == nil {
			return false
		}
		if cfg.HavePIDFilter && meta.PID != cfg.PIDFilter {
			return false
		}
		if cfg.HaveCPIDFilter && meta.CRPID != cfg.CPIDFilter {
			return false
		}
		if cfg.HaveCRIDFilter && meta.CRID != cfg.CRIDFilter {
			return false
		}
		if cfg.HaveCommFilter && meta.Comm != cfg.CommFilter {
			return false
		}
	}
	return true
}

func parseStatusUID(status []byte) (uint32, bool) {
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		v, err := strconv.ParseUint(fields[1], 10, 32)
		return uint32(v), err == nil
	}
	return 0, false
}

func parseStatusCRPID(status []byte) (uint32, bool) {
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		v, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
		return uint32(v), err == nil
	}
	return 0, false
}

func readCRID(pid int) (uint64, bool) {
	target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "ns", "pid"))
	if err != nil {
		return 0, false
	}
	if !strings.HasPrefix(target, "pid:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "pid:["), "]"), 10, 64)
	return v, err == nil
}

func parseSocketInode(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
	return v, err == nil
}

func parseSocketToken(family int, token string) ([16]byte, uint16, bool) {
	var addr [16]byte
	parts := strings.Split(token, ":")
	if len(parts) != 2 {
		return addr, 0, false
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return addr, 0, false
	}
	if family == afINET {
		if len(parts[0]) != 8 {
			return addr, 0, false
		}
		raw, err := hexStringToBytes(parts[0])
		if err != nil || len(raw) != 4 {
			return addr, 0, false
		}
		addr[0], addr[1], addr[2], addr[3] = raw[3], raw[2], raw[1], raw[0]
		return addr, uint16(port), true
	}
	if len(parts[0]) != 32 {
		return addr, 0, false
	}
	raw, err := hexStringToBytes(parts[0])
	if err != nil || len(raw) != 16 {
		return addr, 0, false
	}
	for i := 0; i < 4; i++ {
		addr[i*4+0] = raw[i*4+3]
		addr[i*4+1] = raw[i*4+2]
		addr[i*4+2] = raw[i*4+1]
		addr[i*4+3] = raw[i*4+0]
	}
	return addr, uint16(port), true
}

func hexStringToBytes(s string) ([]byte, error) {
	buf := make([]byte, len(s)/2)
	for i := 0; i < len(buf); i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		buf[i] = byte(v)
	}
	return buf, nil
}

func makeRecordID(seq *atomic.Uint64, ts time.Time) string {
	return fmt.Sprintf("%011x%013x", ts.UnixMilli()&0x7ffffffffff, (seq.Add(1)^uint64(os.Getpid()))&0x1ffffffffffff)
}

func recordKeyHex(e PacketEvent, meta *SocketMeta) string {
	pid := 0
	if meta != nil {
		pid = meta.PID
	}
	if e.Cookie != 0 {
		h := fnv.New64a()
		cookie := [8]byte{}
		binary.LittleEndian.PutUint64(cookie[:], e.Cookie)
		_, _ = h.Write(cookie[:])
		_, _ = h.Write([]byte(strconv.Itoa(pid)))
		return fmt.Sprintf("%016x", h.Sum64())
	}
	return flowKeyHex(e, pid)
}

func parseCIDRList(spec string) ([]cidrRule, error) {
	if spec == "" {
		return nil, nil
	}
	items := []cidrRule{}
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		rule := cidrRule{}
		if strings.HasPrefix(token, "!") {
			rule.Deny = true
			token = strings.TrimSpace(token[1:])
		}
		ip, netw, err := net.ParseCIDR(token)
		if err != nil {
			parsed := net.ParseIP(token)
			if parsed == nil {
				return nil, err
			}
			ip = parsed
			bits := 32
			if parsed.To4() == nil {
				bits = 128
			}
			_, netw, _ = net.ParseCIDR(fmt.Sprintf("%s/%d", parsed.String(), bits))
		}
		if v4 := ip.To4(); v4 != nil {
			rule.Family = afINET
			prefix, _ := netw.Mask.Size()
			rule.PrefixLen = uint8(prefix)
			copy(rule.Addr[:4], v4)
		} else {
			rule.Family = afINET6
			prefix, _ := netw.Mask.Size()
			rule.PrefixLen = uint8(prefix)
			copy(rule.Addr[:16], ip.To16())
		}
		items = append(items, rule)
	}
	return items, nil
}

func cidrSetAccepts(rules []cidrRule, family int, addr [16]byte) bool {
	hasAllow := false
	allowHit := false
	for _, rule := range rules {
		if rule.Family != family {
			continue
		}
		hit := false
		if family == afINET {
			hit = cidrMatchV4(rule, addr)
		} else {
			hit = cidrMatchV6(rule, addr)
		}
		if !hit {
			continue
		}
		if rule.Deny {
			return false
		}
		hasAllow = true
		allowHit = true
	}
	if !hasAllow {
		return true
	}
	return allowHit
}

func cidrMatchV4(rule cidrRule, addr [16]byte) bool {
	want := binary.BigEndian.Uint32(rule.Addr[:4])
	got := binary.BigEndian.Uint32(addr[:4])
	mask := uint32(0)
	if rule.PrefixLen > 0 {
		mask = ^uint32(0) << (32 - rule.PrefixLen)
	}
	return want&mask == got&mask
}

func cidrMatchV6(rule cidrRule, addr [16]byte) bool {
	bits := int(rule.PrefixLen)
	for i := 0; i < 16; i++ {
		remain := bits - i*8
		if remain <= 0 {
			break
		}
		mask := byte(0xff)
		if remain < 8 {
			mask = byte(0xff << (8 - remain))
		}
		if rule.Addr[i]&mask != addr[i]&mask {
			return false
		}
	}
	return true
}
