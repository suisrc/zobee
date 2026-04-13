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

	_ "embed"
	_ "unsafe"

	"github.com/suisrc/zoo"
	"github.com/suisrc/zoo/zoc"
	"github.com/suisrc/zoo/zoe/proc"
	"golang.org/x/sys/unix"
)

//go:embed zwbee
var embedCaptureBin []byte

type Hook func(map[string]any)

var (
	G = struct {
		Config Config `json:"zabee"`
	}{}
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
		comm, args := proc.ParseCmd(G.Config.Command)
		if len(args) == 0 {
			args = G.Config.CmdArgs
		}
		hdl := &Server{comm: comm, args: args, hook: hook}
		svc.Engine().Servers.Add(hdl)
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
					zoc.Exit("[_zaabee_]: write binary to ./zwbee error,", err.Error())
				}
				zoc.Logn("[_zaabee_]: zwbee binary write to ./zwbee")
				// defer os.Remove("./zwbee") // 释放命令，不删除, 这个与 ./memfd 不同
			}
		case "./memfd":
			// 使用 内存 利用Linux的 memfd_create 系统调用创建内核级匿名内存文件，完全不需要磁盘IO。
			fd, err := unix.MemfdCreate("zwbee", unix.MFD_CLOEXEC)
			if err != nil {
				zoc.Exit("[_zaabee_]: create binary by memfd_create error,", err.Error())
			}
			// 将嵌入式二进制写入内存文件
			if _, err := unix.Write(fd, embedCaptureBin); err != nil {
				_ = unix.Close(fd)
				zoc.Exit("[_zaabee_]: write binary to memfd error,", err.Error())
			}
			// 获取内存文件的文件描述符路径
			comm = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)
			// 更新命令为内存文件路径
			zoc.Logn("[_zaabee_]: zwbee binary loaded into memory via memfd")
			// 运行完成后关闭内存文件
			// defer unix.Close(fd)
			defer func() {
				unix.Close(fd)
				zoc.Logn("[_zaabee_]: zwbee binary in memfd closed")
			}()
		}
		hdl.proc = proc.NewProcess(comm, FixCmdArgs(hdl.args)...)
	}
	// 创建管道，作为进程的 stdout 和 stderr，扫描器从管道的读端读取数据，直到进程退出或管道关闭
	pr, pw, err := os.Pipe()
	if err != nil {
		zoc.Exit(fmt.Sprintf("[_zaabee_]: create pipe error: %s\n", err))
	}
	// defer pr.Close(); defer pw.Close()
	wait, err := hdl.proc.Execute(pw, hdl)
	if err != nil {
		zoc.Exit(fmt.Sprintf("[_zaabee_]: process start error: %s\n", err))
	}
	pid := hdl.proc.Pid()
	zoc.Logn("[_zaabee_]: ---------------- process started, pid=", pid)
	hdl.closer = pr // 将管道的读端作为 closer， 在 Shutdown 中关闭它，通知扫描器进程退出
	go func() {
		wait() // 等待进程退出, 更新进程状态
		if hdl.closer != nil {
			_ = hdl.closer.Close()
			hdl.closer = nil
		}
	}()
	hdl.scanToHook(pr) // 扫描进程输出，直到进程退出或管道关闭
	zoc.Logn("[_zaabee_]: ---------------- process exited, pid=", pid)
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
			zoc.Logn("[_zaabee_]: invalid record by json, ", string(line))
		} else {
			zoc.Logn("[_zaabee_]:", string(line))
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
	zoc.Logn("[_zaabee_]: ", string(p))
	return len(p), nil
}
