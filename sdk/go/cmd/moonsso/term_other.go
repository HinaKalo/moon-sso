//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows)

package main

import (
	"errors"
	"os"
)

func isTerminal(*os.File) bool { return false }

func readPassword(*os.File) (string, error) {
	return "", errors.New("此平台不支持隐藏输入，请使用 --with-token 从标准输入读取")
}
