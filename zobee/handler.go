package zabee

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	_ "embed"
	_ "unsafe"

	"github.com/suisrc/zoo"
	"github.com/suisrc/zoo/zoc"
	"github.com/suisrc/zoo/zoe/log"
	"github.com/suisrc/zoo/zoe/proc"
)

//go:embed zwbee
var embedCaptureBin []byte

type Hook func(map[string]any)

var (
	G = struct {
		Config Config `json:"zobee"`
	}{}
)

type Config struct {
	Disabled bool     `json:"disabled"`
	Command  string   `json:"command"` // 命令，默认为 ./zwbee，支持替换为 ./memfd 来使用内存文件
	CmdArgs  []string `json:"cmdargs"` // 命令行参数，优先级低于 Command 中的参数
	Logger   string   `json:"logger"`  // 日志发送地址
	LogTty   bool     `json:"logtty"`  // 日志是否输出到终端
	LogFmt   bool     `json:"logfmt"`  // 针对默认的json格式， 是否格式化， 默认不格式化输出一行
}

func Load(hook Hook) {

	flag.BoolVar(&G.Config.Disabled, "e3disabled", true, "是否禁用zobee")
	flag.StringVar(&G.Config.Command, "e3command", "./zwbee", "命令")
	flag.Var(zoc.NewStrArr(&G.Config.CmdArgs, []string{"-cpid", "<pid>"}), "e3cmdargs", "参数")

	zoo.Register("14-zobee", &G, func(svc zoo.SvcKit) zoo.Closed { return Register(svc, &G.Config, hook) })
}

func Register(svc zoo.SvcKit, conf *Config, hook Hook) zoo.Closed {
	if conf == nil {
		conf = &G.Config
	}
	if conf.Disabled {
		zoc.Logn("[_zoobee_]: disabled")
		return nil
	}
	if hook == nil && conf.Logger != "" {
		// 使用 logger 配置构建默认的 hook
		hook = NewDefaultHook("[_traffic]:", conf, nil)
	}
	// 优先使用 command 中的参数， 如果参数不存在，在使用 args 中的参数
	comm, args := proc.ParseCmd(conf.Command)
	if len(args) == 0 {
		args = conf.CmdArgs
	}
	hdl := &Server{comm: comm, args: args, hook: hook}
	svc.Engine().Servers.Add(hdl)
	return nil
}

// NewDefaultHook 根据 Logger 配置创建一个默认的 Hook，支持多种日志输出方式
func NewDefaultHook(pkey string, conf *Config, conv func(map[string]any) ([]byte, error)) Hook {
	if conf.Logger == "" {
		return nil
	}
	if conv == nil {
		if conf.LogFmt {
			conv = func(record map[string]any) ([]byte, error) { return json.MarshalIndent(record, "", "  ") }
		} else {
			conv = func(record map[string]any) ([]byte, error) { return json.Marshal(record) }
		}
	}
	address := conf.Logger
	if strings.HasPrefix(address, "stdout://") {
		return func(record map[string]any) {
			if bts, err := conv(record); err == nil {
				zoc.Logn(pkey, string(bts))
			} else {
				zoc.Logn("[_zoobee_]: convert record to bytes error, ", err.Error())
			}
		}
	}
	if strings.HasPrefix(address, "file://") {
		writer := log.NewFileWriter(address[7:], 0, conf.LogTty)
		return func(record map[string]any) {
			if bts, err := conv(record); err == nil {
				writer.Write(append(bts, '\n')) // 文件中每条记录占一行
			} else {
				zoc.Logn("[_zoobee_]: convert record to bytes error, ", err.Error())
			}
		}
	}
	// 其他情况，默认使用 syslog 输出
	network := ""
	if strings.HasPrefix(address, "udp://") {
		network, address = "udp", address[6:]
	} else if strings.HasPrefix(address, "tcp://") {
		network, address = "tcp", address[6:]
	}
	writer := log.NewSyslogWriter(address, network, 0, conf.LogTty)
	return func(record map[string]any) {
		if bts, err := conv(record); err == nil {
			writer.Write(bts)
		} else {
			zoc.Logn("[_zoobee_]: convert record to bytes error, ", err.Error())
		}
	}
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
	comm   string
	args   []string
	hook   Hook
	proc   proc.Process
	closer io.Closer
}

func (hdl *Server) Name() string {
	return "(ZABEE)"
}

func (hdl *Server) Addr() string {
	return hdl.comm + " ...(args)"
}

func (hdl *Server) RunServe() {
	if hdl.proc == nil {
		comm := hdl.comm
		switch hdl.comm {
		case "./zwbee":
			// 判断当前文件夹中是否哟 zwbee 命令，如果没有，使用 embeddedCaptureBin 中的内容创建
			if _, err := os.Stat("./zwbee"); os.IsNotExist(err) {
				if err := os.WriteFile("./zwbee", embedCaptureBin, 0755); err != nil {
					zoc.Exit("[_zoobee_]: write binary to ./zwbee error,", err.Error())
				}
				zoc.Logn("[_zoobee_]: zwbee binary write to ./zwbee")
				// defer os.Remove("./zwbee") // 释放命令，不删除, 这个与 ./memfd 不同
			}
		case "./memfd":
			// 使用 内存 利用Linux的 memfd_create 系统调用创建内核级匿名内存文件，完全不需要磁盘IO。
			fd, err := MemfdCreate("zwbee", MFD_CLOEXEC)
			if err != nil {
				zoc.Exit("[_zoobee_]: create binary by memfd_create error,", err.Error())
			}
			// 将嵌入式二进制写入内存文件
			if _, err := MemfdWrite(fd, embedCaptureBin); err != nil {
				_ = MemfdClose(fd)
				zoc.Exit("[_zoobee_]: write binary to memfd error,", err.Error())
			}
			// 获取内存文件的文件描述符路径
			comm = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)
			// 更新命令为内存文件路径
			zoc.Logn("[_zoobee_]: zwbee binary loaded into memory via memfd")
			// 运行完成后关闭内存文件
			// defer unix.Close(fd)
			defer func() {
				MemfdClose(fd)
				zoc.Logn("[_zoobee_]: zwbee binary in memfd closed")
			}()
		}
		hdl.proc = proc.NewProcess(comm, FixCmdArgs(hdl.args)...)
	}
	// 创建管道，作为进程的 stdout 和 stderr，扫描器从管道的读端读取数据，直到进程退出或管道关闭
	pr, pw, err := os.Pipe()
	if err != nil {
		zoc.Exit(fmt.Sprintf("[_zoobee_]: create pipe error: %s\n", err))
	}
	// defer pr.Close(); defer pw.Close()
	wait, err := hdl.proc.Execute(pw, hdl)
	if err != nil {
		zoc.Exit(fmt.Sprintf("[_zoobee_]: process start error: %s\n", err))
	}
	pid := hdl.proc.Pid()
	zoc.Logn("[_zoobee_]: ---------------- process started, pid=", pid)
	hdl.closer = pr // 将管道的读端作为 closer， 在 Shutdown 中关闭它，通知扫描器进程退出
	go func() {
		wait() // 等待进程退出, 更新进程状态
		if hdl.closer != nil {
			_ = hdl.closer.Close()
			hdl.closer = nil
		}
	}()
	hdl.scanToHook(pr) // 扫描进程输出，直到进程退出或管道关闭
	zoc.Logn("[_zoobee_]: ---------------- process exited, pid=", pid)
}

func (hdl *Server) scanToHook(pr io.ReadCloser) {
	ePreKey := []byte("EBPF_CAPTURE: ")
	scaner := bufio.NewScanner(pr)
	for scaner.Scan() {
		line := scaner.Bytes()
		if len(line) == 0 || bytes.Equal(line, []byte{'\n'}) {
			continue // 忽略空行和换行符
		}
		if hdl.hook != nil && bytes.HasPrefix(line, ePreKey) {
			record := make(map[string]any)
			if err := json.Unmarshal(line[len(ePreKey):], &record); err == nil {
				hdl.hook(record)
				continue
			}
			zoc.Logn("[_zoobee_]: invalid record by json, ", string(line))
		} else {
			zoc.Logn("[_zoobee_]:", string(line))
		}
	}
}

func (hdl *Server) Shutdown(ctx context.Context) error {
	if hdl.closer != nil {
		_ = hdl.closer.Close()
		hdl.closer = nil
	}
	_ = hdl.proc.Stop(0) // 发送 SIGTERM 信号，等待进程退出, 忽略错误
	return nil
}

func (hdl *Server) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	zoc.Logn("[_zoobee_]: ", string(p))
	return len(p), nil
}
