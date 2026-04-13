package main

import (
	_ "embed"

	_ "zobee/cmd"
	// app "zobee/zobee"
	app "zobee/zabee"

	"github.com/suisrc/zoo"
	"github.com/suisrc/zoo/zoc"
	_ "github.com/suisrc/zoo/zoe/log"
	_ "github.com/suisrc/zoo/zoe/rdx"
)

//go:embed vname
var app_ []byte

//go:embed version
var ver_ []byte

// //go:embed www/* www/**/*
// var www_ embed.FS

func main() {
	app.Load(nil)
	zoo.HttpServeDef = false // 标记是否启动默认 HTTP 服务, 一些特殊的服务，可以代码方式关闭
	zoo.Execute("KIT", zoc.BtsStr(app_), zoc.BtsStr(ver_), "(https://github.com/suisrc/zdemo.git)")
}
