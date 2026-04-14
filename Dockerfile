FROM golang:1.25-alpine3.23 AS build

RUN apk add --no-cache git \
  build-base \
  clang \
  llvm \
  lld \
  linux-headers \
  libbpf-dev \
  elfutils-dev \
  elfutils-libelf \
  libpcap-dev \
  pkgconf \
  openssl-dev \
  zlib-dev \
  zlib-static \
  zstd-dev \
  zstd-static \
  git \
  make \
  bpftool \
  iproute2

# RUN ls -l /usr/lib/ | grep libz

WORKDIR /opt
COPY . .
RUN cd ebpf && make
RUN CGO_ENABLED=0 go build -o app -ldflags '-w -extldflags "-static"' .

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata tcpdump

WORKDIR /opt
COPY --from=build /opt/app /opt/app

# alpine 对应的 中间产物， 用于嵌入到最终镜像中
COPY --from=build /opt/ebpf/zwbee /opt/zwbee
COPY --from=build /opt/ebpf/ebpf_capture.o /opt/ebpf_capture.o

ENTRYPOINT ["./app"]
