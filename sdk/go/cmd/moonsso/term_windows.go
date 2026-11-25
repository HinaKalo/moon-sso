//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func isTerminal(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// readPassword reads a line from the console with echo disabled.
func readPassword(f *os.File) (string, error) {
	h := windows.Handle(f.Fd())
	var old uint32
	if err := windows.GetConsoleMode(h, &old); err != nil {
		return "", err
	}
	mode := old&^windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_LINE_INPUT
	if err := windows.SetConsoleMode(h, mode); err != nil {
		return "", err
	}
	restore := func() { _ = windows.SetConsoleMode(h, old) }
	defer restore()
	return readRawLine(f, restore)
}
