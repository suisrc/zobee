CLANG ?= clang
LD ?= ld
UNAME_R := $(shell uname -r)

# 自动检测发行版
OS_ID := $(shell grep -oP '^ID=\K\w+' /etc/os-release 2>/dev/null || echo "unknown")

# 通用内核头文件路径
KERNEL_HEADERS_BASE := 
# Alpine的内核头文件路径不同
ifeq ($(OS_ID), alpine)
	KERNEL_HEADERS := /usr/include
	# Alpine默认没有内核版本号子目录，如果安装了linux-dev包直接用/usr/include
else
	KERNEL_HEADERS := /usr/src/linux-headers-$(UNAME_R)
endif

# 自动检测架构，避免硬编码x86
ARCH := $(shell uname -m)
ifeq ($(ARCH), x86_64)
	TARGET_ARCH := x86
	ARCH_INCLUDE := $(KERNEL_HEADERS)/arch/x86/include/generated/uapi
	TRIPLET_INCLUDE := /usr/include/x86_64-linux-gnu
else ifeq ($(ARCH), aarch64)
	TARGET_ARCH := arm64
	ARCH_INCLUDE := $(KERNEL_HEADERS)/arch/arm64/include/generated/uapi
	TRIPLET_INCLUDE := /usr/include/aarch64-linux-gnu
else ifeq ($(ARCH), armv7l)
	TARGET_ARCH := arm
	ARCH_INCLUDE := $(KERNEL_HEADERS)/arch/arm/include/generated/uapi
	TRIPLET_INCLUDE := /usr/include/arm-linux-gnueabihf
else
	TARGET_ARCH := $(ARCH)
	ARCH_INCLUDE :=
	TRIPLET_INCLUDE := /usr/include/$(ARCH)-linux-gnu
endif

# 如果上面计算的路径不存在，则回退到 /usr/include，保证编译能找到头文件
ifeq ($(wildcard $(ARCH_INCLUDE)),)
	ARCH_INCLUDE := /usr/include
endif
ifeq ($(wildcard $(TRIPLET_INCLUDE)),)
	TRIPLET_INCLUDE := /usr/include
endif

# BPF编译通用参数
BPF_CFLAGS = -O2 -target bpf -g -D__TARGET_ARCH_$(TARGET_ARCH) -I$(ARCH_INCLUDE) -I$(TRIPLET_INCLUDE)

all: ebpf_capture.o ebpf_capture_blob.o zwbee

ebpf_capture.o: ebpf_capture.c
	$(CLANG) $(BPF_CFLAGS) -c ebpf_capture.c -o ebpf_capture.o && cp -f ebpf_capture.o ../zobee/ebpf_capture.o

ebpf_capture_blob.o: ebpf_capture.o
	$(LD) -r -z noexecstack -b binary ebpf_capture.o -o ebpf_capture_blob.o

# zwbee 现在不再链接 libpcap(-lpcap)；-pcap-rules 由运行时调用 tcpdump -ddd 编译。
# 如果后续要做全静态，只需要保证 tcpdump 可用，zwbee 本身无需再引入 libpcap 依赖。
zwbee: zwbee.c ebpf_capture_blob.o
	$(CLANG) -O2 -static -o zwbee zwbee.c ebpf_capture_blob.o -lbpf -lelf -lz && cp -f zwbee ../zabee/zwbee

clean:
	rm -f ebpf_capture.o ebpf_capture_blob.o zwbee

syncc:
	cp -f ebpf_capture.o ../zobee/ebpf_capture.o && cp -f zwbee ../zabee/zwbee

# 依赖安装提示
depends:
ifeq ($(OS_ID), alpine)
	@echo "Alpine依赖安装命令："
	@echo "apk add clang llvm lld linux-headers bpftool libbpf-dev elfutils-dev zlib-dev"
else
	@echo "Debian/Ubuntu依赖安装命令："
	@echo "apt install clang llvm libbpf-dev linux-headers-$(UNAME_R) libelf-dev zlib1g-dev"
endif