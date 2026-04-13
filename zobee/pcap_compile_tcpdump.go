package zobee

// 通过调用系统 tcpdump 命令编译 pcap 规则，不需要 cgo，也不需要 libpcap 开发包，但运行环境必须安装 tcpdump。
// apt install -y tcpdump | apk add --no-cache tcpdump

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	pcapLinkTypeEthernet = 1
	pcapSnapLen          = 65535
)

var tcpdumpInsnRe = regexp.MustCompile(`\{\s*([^}]*)\s*\}`)

func compilePcapRules(rules string) ([]pcapRuleInsn, error) {
	rules = strings.TrimSpace(rules)
	if rules == "" {
		return nil, nil
	}
	// tcpdump -dd 输出 BPF 指令，格式通常是：
	// { op, jt, jf, k },
	cmd := exec.Command("tcpdump", "-dd", "-s", strconv.Itoa(pcapSnapLen), rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tcpdump -dd failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	lines := bytes.Split(out, []byte{'\n'})
	insns := make([]pcapRuleInsn, 0, 32)

	for _, line := range lines {
		s := strings.TrimSpace(string(line))
		if s == "" {
			continue
		}

		m := tcpdumpInsnRe.FindStringSubmatch(s)
		if m == nil {
			continue
		}

		fields := strings.Split(m[1], ",")
		if len(fields) < 4 {
			return nil, fmt.Errorf("unexpected tcpdump output: %q", s)
		}

		parseNum := func(v string) (uint64, error) {
			v = strings.TrimSpace(v)
			if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
				return strconv.ParseUint(v[2:], 16, 64)
			}
			return strconv.ParseUint(v, 10, 64)
		}

		op, err := parseNum(fields[0])
		if err != nil {
			return nil, fmt.Errorf("parse op %q: %w", fields[0], err)
		}
		jt, err := parseNum(fields[1])
		if err != nil {
			return nil, fmt.Errorf("parse jt %q: %w", fields[1], err)
		}
		jf, err := parseNum(fields[2])
		if err != nil {
			return nil, fmt.Errorf("parse jf %q: %w", fields[2], err)
		}
		k, err := parseNum(fields[3])
		if err != nil {
			return nil, fmt.Errorf("parse k %q: %w", fields[3], err)
		}

		insns = append(insns, pcapRuleInsn{
			Code: uint16(op),
			JT:   uint8(jt),
			JF:   uint8(jf),
			K:    uint32(k),
		})
	}

	if len(insns) == 0 {
		return nil, fmt.Errorf("no instructions parsed from tcpdump output")
	}
	if len(insns) > pcapRulesMaxInsns {
		return nil, fmt.Errorf("pcap instruction count %d invalid", len(insns))
	}

	return insns, nil
}
