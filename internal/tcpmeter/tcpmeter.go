// Package tcpmeter moves bytes over TCP one direction at a time, against a
// local server: an upload the server swallows and acknowledges, or a download
// it sends. A proxy's speed limit shows in how long each takes. The
// served-node test and its separate mihomo client run the same exchange.
package tcpmeter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	opUpload   = 'U'
	opDownload = 'D'
)

// Serve answers one connection. A request is an operation and a length:
// for an upload the server reads that many bytes and answers "ok"; for a
// download it writes that many. It returns when the client closes.
func Serve(conn net.Conn) error {
	defer conn.Close()
	head := make([]byte, 9)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	size := int64(binary.BigEndian.Uint64(head[1:]))
	switch head[0] {
	case opUpload:
		if _, err := io.CopyN(io.Discard, conn, size); err != nil {
			return err
		}
		if _, err := conn.Write([]byte("ok")); err != nil {
			return err
		}
	case opDownload:
		chunk := make([]byte, 16<<10)
		for size > 0 {
			n := int64(len(chunk))
			if size < n {
				n = size
			}
			if _, err := conn.Write(chunk[:n]); err != nil {
				return err
			}
			size -= n
		}
	default:
		return fmt.Errorf("unknown operation %q", head[0])
	}
	_, err := io.Copy(io.Discard, conn)
	return err
}

func request(conn net.Conn, op byte, size int) error {
	head := make([]byte, 9)
	head[0] = op
	binary.BigEndian.PutUint64(head[1:], uint64(size))
	_, err := conn.Write(head)
	return err
}

// Upload sends size bytes through conn and waits for the server to say it
// has them all. It returns how long that took.
func Upload(conn net.Conn, size int) (time.Duration, error) {
	_ = conn.SetDeadline(time.Now().Add(time.Minute))
	if err := request(conn, opUpload, size); err != nil {
		return 0, err
	}
	start := time.Now()
	chunk := make([]byte, 16<<10)
	for left := size; left > 0; {
		n := len(chunk)
		if left < n {
			n = left
		}
		if _, err := conn.Write(chunk[:n]); err != nil {
			return time.Since(start), err
		}
		left -= n
	}
	ack := make([]byte, 2)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return time.Since(start), err
	}
	if string(ack) != "ok" {
		return time.Since(start), errors.New("the server did not acknowledge the upload")
	}
	return time.Since(start), nil
}

// Download asks the server for size bytes through conn and reads them. It
// returns how long that took.
func Download(conn net.Conn, size int) (time.Duration, error) {
	_ = conn.SetDeadline(time.Now().Add(time.Minute))
	start := time.Now()
	if err := request(conn, opDownload, size); err != nil {
		return 0, err
	}
	if _, err := io.CopyN(io.Discard, conn, int64(size)); err != nil {
		return time.Since(start), err
	}
	return time.Since(start), nil
}
