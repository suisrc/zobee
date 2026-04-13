package cmd_test

import "testing"

// go test -v cmd/custom_test.go -run Test_hello

func Test_hello(t *testing.T) {
	t.Log("hello world!")
}
