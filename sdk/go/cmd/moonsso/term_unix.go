//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlReadTermios)
	return err == nil
}

// readPassword reads a line with echo disabled, keeping canonical mode and
// signal generation so that editing and Ctrl-C still work.
func readPassword(f *os.File) (string, error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return "", err
	}
	t := *old
	t.Lflag &^= unix.ECHO
	t.Lflag |= unix.ICANON | unix.ISIG
	t.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &t); err != nil {
		return "", err
	}
	restore := func() { _ = unix.IoctlSetTermios(fd, ioctlWriteTermios, old) }
	defer restore()
	return readRawLine(f, restore)
}
