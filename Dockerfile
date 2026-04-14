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
  git \
  make \
  bpftool \
  iproute2

RUN ls -l /usr/lib/ | grep libz

WORKDIR /opt
COPY . .
RUN cd ebpf && make
RUN CGO_ENABLED=0 go build -o app -ldflags '-w -extldflags "-static"' .

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata tcpdump

WORKDIR /opt
COPY --from=build /opt/app /opt/app

ENTRYPOINT ["./app"]
