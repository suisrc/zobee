package zabee

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	_ "embed"
	_ "unsafe"

	"github.com/suisrc/zoo"
	"github.com/suisrc/zoo/zoc"
	"github.com/suisrc/zoo/zoe/proc"
)

//go:embed zwbee
var embeddedCaptureBin []byte

type Hook func(map[string]any)

var (
	G = struct {
		Config Config `json:"zabee"`
	}{}

	LOG_PRE = []byte("EBPF_CAPTURE: ")
)

type Config struct {
	Disabled bool     `json:"disabled"`
	Command  string   `json:"command"`
	CmdArgs  []string `json:"cmdargs"`
}

func Load(hook Hook) {

	flag.BoolVar(&G.Config.Disabled, "b2disabled", true, "是否禁用zabee")
	flag.StringVar(&G.Config.Command, "b2command", "./zwbee", "命令")
	flag.Var(zoc.NewStrArr(&G.Config.CmdArgs, []string{"-cpid", "<pid>"}), "b2cmdargs", "参数")

	zoo.Register("14-zabee", &G, func(svc zoo.SvcKit) zoo.Closed {
		if G.Config.Disabled {
			zoc.Logn("[_zaabee_]: disabled")
			return nil
		}
		// 优先使用 command 中的参数， 如果参数不存在，在使用 args 中的参数
		cmd, args := proc.ParseCmd(G.Config.Command)
		if len(args) == 0 {
			args = G.Config.CmdArgs
		}
		hdl := &Server{hook: hook}
		hdl.process = proc.NewProcess(hdl, cmd, FixCmdArgs(args)...)
		svc.Engine().Servers.Add(hdl)

		if cmd == "./zwbee" {
			// 判断当前文件夹中是否哟 zwbee 命令，如果没有，使用 embeddedCaptureBin 中的内容创建
			if _, err := os.Stat("./zwbee"); os.IsNotExist(err) {
				if err := os.WriteFile("./zwbee", embeddedCaptureBin, 0755); err != nil {
					svc.Engine().ServeStop("register zabee error by binary not found and created fail,", err.Error())
					return nil
				}
				zoc.Logn("[_zaabee_]: zwbee binary created")
				return func() {
					_ = os.Remove("./zwbee") // 删除创建的 zwbee 命令， 忽略错误
				}
			}
		}
		return nil
	})
}

// FixCmdArgs 替换命令行参数中的占位符，例如 <pid> 替换为当前进程的 PID
var FixCmdArgs = func(args []string) []string {
	for i, arg := range args {
		switch arg {
		case "<pid>":
			args[i] = fmt.Sprintf("%d", os.Getpid())
		}
	}
	return args
}

var _ zoo.Server = (*Server)(nil)

type Server struct {
	hook    Hook
	process proc.Process
}

func (hdl *Server) Name() string {
	return "(ZABEE)"
}

func (hdl *Server) Addr() string {
	str := hdl.process.String()
	if len(str) < 36 {
		return str
	}
	return str[:36] + "..."
}

func (hdl *Server) RunServe() {
	if err := hdl.process.Serve(); err != nil {
		zoc.Exit(fmt.Sprintf("[_zaabee_]: process exit error: %s\n", err))
	}
}

func (hdl *Server) Shutdown(ctx context.Context) error {
	_ = hdl.process.Stop(0) // 发送 SIGTERM 信号，等待进程退出, 忽略错误
	return nil
}

func (hdl *Server) Write(p []byte) (n int, err error) {
	if len(p) == 0 || bytes.Equal(p, []byte{'\n'}) {
		return len(p), nil // 忽略空行和换行符
	}
	if hdl.hook != nil && bytes.HasPrefix(p, LOG_PRE) {
		record := make(map[string]any)
		if err := json.Unmarshal(p[len(LOG_PRE):], &record); err == nil {
			hdl.hook(record)
			return len(p), nil
		}
		zoc.Logn("[_zaabee_]: invalid record by json, ", string(p))
	}
	zoc.Logn("[_zaabee_]:", string(p))
	return len(p), nil
}
