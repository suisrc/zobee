CLANG ?= clang
LD ?= ld
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)
BPF_CFLAGS = -O2 -target bpf -g \
-D__TARGET_ARCH_x86 \
-I$(KERNEL_HEADERS)/arch/x86/include/generated/uapi \
-I/usr/include/x86_64-linux-gnu

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
