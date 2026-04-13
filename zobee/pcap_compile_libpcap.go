//go:build ignore
// +build ignore

package zobee

// // go:build cgo & // +build cgo
// 通过 cgo 调用 libpcap 编译 pcap 规则， 需要 CGO_ENABLED=1 和 libpcap 开发包支持

/*
#cgo linux LDFLAGS: -lpcap
#include <stdlib.h>
#include <pcap/pcap.h>
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

const (
	pcapLinkTypeEthernet = 1
	pcapSnapLen          = 65535
)

func compilePcapRules(rules string) ([]pcapRuleInsn, error) {
	rules = strings.TrimSpace(rules)
	if rules == "" {
		return nil, nil
	}
	handle := C.pcap_open_dead(C.int(pcapLinkTypeEthernet), C.int(pcapSnapLen))
	if handle == nil {
		return nil, fmt.Errorf("pcap_open_dead failed")
	}
	defer C.pcap_close(handle)

	expr := C.CString(rules)
	defer C.free(unsafe.Pointer(expr))

	var program C.struct_bpf_program
	if rc := C.pcap_compile(handle, &program, expr, 1, C.PCAP_NETMASK_UNKNOWN); rc != 0 {
		errText := C.pcap_geterr(handle)
		if errText == nil {
			return nil, fmt.Errorf("pcap_compile failed")
		}
		return nil, fmt.Errorf("compile -pcap-rules via libpcap: %s", C.GoString(errText))
	}
	defer C.pcap_freecode(&program)

	count := int(program.bf_len)
	if count <= 0 || count > pcapRulesMaxInsns {
		return nil, fmt.Errorf("pcap instruction count %d invalid", count)
	}
	if program.bf_insns == nil {
		return nil, fmt.Errorf("pcap_compile returned nil instructions")
	}

	cbpf := unsafe.Slice(program.bf_insns, count)
	insns := make([]pcapRuleInsn, 0, count)
	for _, insn := range cbpf {
		insns = append(insns, pcapRuleInsn{
			Code: uint16(insn.code),
			JT:   uint8(insn.jt),
			JF:   uint8(insn.jf),
			K:    uint32(insn.k),
		})
	}
	return insns, nil
}
