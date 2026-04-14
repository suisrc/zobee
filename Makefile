.PHONY: start build

NOW = $(shell date -u '+%Y%m%d%I%M%S')

APP = $(shell cat vname)

all: build

# 初始化mod
init:
	go mod init ${APP}

tidy:
	go mod tidy

# -eng rdx/mux/map
main:
	go run main.go -eng map -local -dual -c zoo.test.toml

build:
	CGO_ENABLED=0 go build -ldflags '-w -extldflags "-static"' -o ./dist/$(APP)

# go env -w GOPROXY=https://proxy.golang.com.cn,direct
# http://mvn.res.local/repository/go https://nexus.vsc.sims-cn.com/repository/go
proxy:
	go env -w GO111MODULE=on
	go env -w GOPROXY=https://nexus.vsc.sims-cn.com/repository/go,direct
	go env -w GOSUMDB=sum.golang.google.cn

# -tpl ./tmpl
tenv:
	ZOO_PRIONT="true" go run main.go -local -debug -port 81

tbin:
	dist/$(APP) -local -port 81 -c zoo.test.toml

hver:
	go run main.go version

hello:
	go run main.go hello

push:
	git push --set-upstream origin $b

sync:
	cp -f ebpf/ebpf_capture.o zobee/ebpf_capture.o && cp -f ebpf/zwbee zobee/zwbee

git:
	@if [ -z "$(tag)" ]; then \
		echo "error: 'tag' not specified! Please specify the 'tag' using 'make git tag=(version)";\
		exit 1; \
	fi
	git add zobee/ebpf_capture.o zabee/zwbee -f && git commit -m "add ebpf_capture.o and zwbee" && \
	git tag -a $(tag) -m "${tag}" && git push origin $(tag) && git reset --hard HEAD~1
