//go:build linux

package sockopt

import (
	"golang.org/x/sys/unix"
)

// TCPNotSentLowat is the TCP_NOTSENT_LOWAT option number.
const TCPNotSentLowat = unix.TCP_NOTSENT_LOWAT

const tcpCongestion = unix.TCP_CONGESTION

func withSocket(f func(fd int) error) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return f(fd)
}

func trySetInt(opt, value int) error {
	return withSocket(func(fd int) error { return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, opt, value) })
}

func trySetString(opt int, value string) error {
	return withSocket(func(fd int) error { return unix.SetsockoptString(fd, unix.IPPROTO_TCP, opt, value) })
}

func setInt(fd, opt, value int) error { return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, opt, value) }
