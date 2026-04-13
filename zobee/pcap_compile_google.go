//go:build ignore
// +build ignore

package zobee

// // go:build cgo & // +build cgo
// cgo 版本的 pcap 规则编译器，依赖 gopacket/pcap 和 libpcap。
// 目前仅用于测试和性能对比，正式版本将使用 cgo 或 纯go + tcpdump 实现的编译器。

import (
	"fmt"
	"strings"
)

const (
	pcapSnapLen = 65535
)

func compilePcapRules(rules string) ([]pcapRuleInsn, error) {
	rules = strings.TrimSpace(rules)
	if rules == "" {
		return nil, nil
	}
	instructions, err := pcapgo..CompileBPFFilter(1, pcapSnapLen, rules)
	if err != nil {
		return nil, err
	}
	if len(instructions) > pcapRulesMaxInsns {
		return nil, fmt.Errorf("pcap instruction count %d invalid", len(instructions))
	}
	insns := make([]pcapRuleInsn, len(instructions))
	for i, insn := range instructions {
		insns[i] = pcapRuleInsn{
			Code: insn.Code,
			JT:   insn.Jt,
			JF:   insn.Jf,
			K:    insn.K,
		}
	}
	return insns, nil
}
