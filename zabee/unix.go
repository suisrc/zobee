package zabee

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	MFD_CLOEXEC = 0x01 // unix.MFD_CLOEXEC
)

func MemfdCreate(name string, flags int) (fd int, err error) {
	// return unix.MemfdCreate(name, flags)

	var p0 *byte
	p0, err = syscall.BytePtrFromString(name)
	if err != nil {
		return
	}
	// 动态获取系统调用号，不同架构自动适配
	var sysno uintptr
	switch runtime.GOARCH {
	case "amd64":
		sysno = 319
	case "arm64":
		sysno = 279
	case "386":
		sysno = 356
	case "arm":
		sysno = 385
	case "mips64":
		sysno = 314
	default:
		return 0, fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
	// 调用系统调用创建内存文件
	r0, _, e1 := syscall.Syscall(sysno, uintptr(unsafe.Pointer(p0)), uintptr(flags), 0)
	fd = int(r0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}

func MemfdWrite(fd int, data []byte) (int, error) {
	return syscall.Write(fd, data)
}

func MemfdClose(fd int) error {
	return syscall.Close(fd)
}
