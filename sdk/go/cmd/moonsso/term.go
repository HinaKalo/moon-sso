package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
)

// interactive reports whether stdin is a terminal a person can type into.
func (a *app) interactive() bool {
	f, ok := a.stdin.(*os.File)
	return ok && isTerminal(f)
}

// readSecret prompts on stderr and reads a line from the terminal without echo.
func (a *app) readSecret(prompt string) (string, error) {
	f := a.stdin.(*os.File)
	fmt.Fprint(a.stderr, prompt)
	s, err := readPassword(f)
	fmt.Fprintln(a.stderr)
	if err != nil {
		return "", fmt.Errorf("读取输入失败：%v", err)
	}
	return strings.TrimSpace(s), nil
}

// readRawLine reads one line byte by byte from a terminal whose echo is off.
// On Ctrl-C the terminal state is restored before exiting.
func readRawLine(f *os.File, restore func()) (string, error) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	defer func() {
		signal.Stop(sig)
		close(done)
	}()
	go func() {
		select {
		case <-sig:
			restore()
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-done:
		}
	}()
	var buf []byte
	var b [1]byte
	for {
		n, err := f.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			if b[0] != '\r' {
				buf = append(buf, b[0])
			}
			if len(buf) > 64<<10 {
				return "", errors.New("输入过长")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				break
			}
			return "", err
		}
	}
	return string(buf), nil
}

// readLine reads one line from stdin (with echo).
func (a *app) readLine() (string, error) {
	line, err := a.in.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readSource reads a file, or stdin for "-".
func (a *app) readSource(name string) ([]byte, error) {
	if name == "-" {
		b, err := io.ReadAll(io.LimitReader(a.in, 8<<20))
		if err != nil {
			return nil, fmt.Errorf("读取标准输入失败：%v", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败：%v", err)
	}
	return b, nil
}

// canConfirm refuses destructive commands without --yes when nobody can
// answer the confirmation prompt. Call it before sending any request.
func (a *app) canConfirm(yes bool, topic string) error {
	if yes || a.interactive() {
		return nil
	}
	return usagef(topic, "非交互模式下执行此操作需要加 --yes")
}

// confirm asks the user to type expect exactly.
func (a *app) confirm(yes bool, warning, expect string) error {
	if yes {
		return nil
	}
	fmt.Fprintln(a.stderr, warning)
	fmt.Fprintf(a.stderr, "请输入 %s 以确认：", expect)
	line, err := a.readLine()
	if err != nil {
		fmt.Fprintln(a.stderr)
		return errors.New("已取消")
	}
	if strings.TrimSpace(line) != expect {
		return errors.New("输入不一致，已取消")
	}
	return nil
}
