//go:build !linux

package sockopt

import "errors"

// TCPNotSentLowat is not set outside Linux.
const TCPNotSentLowat = -1

const tcpCongestion = -1

var errUnsupported = errors.New("not supported on this system")

func trySetInt(int, int) error       { return errUnsupported }
func trySetString(int, string) error { return errUnsupported }

func setInt(int, int, int) error { return errUnsupported }
