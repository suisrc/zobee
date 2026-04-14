FROM golang:1.25-alpine3.23 AS build

RUN apk add --no-cache git \
  clang \
  llvm \
  libbpf-dev \
  elfutils-dev \
  libpcap-dev \
  elfutils-libelf \
  pkgconf \
  openssl-dev \
  zlib-dev \
  git \
  make \
  bpftool \
  iproute2

WORKDIR /opt
COPY . .
RUN cd ebpf && make
RUN CGO_ENABLED=0 go build -o app -ldflags '-w -extldflags "-static"' .

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata tcpdump

WORKDIR /opt
COPY --from=build /opt/app /opt/app

ENTRYPOINT ["./app"]
