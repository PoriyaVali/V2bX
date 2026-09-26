package sing

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/conf"
)

// echoServer accepts connections on loopback and echoes what it reads.
func echoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startBox runs the real sing core with a SOCKS inbound and a DNS that
// answers rebind.test with 127.0.0.1 - the shape of a DNS-rebinding name.
func startBox(t *testing.T, allowPrivate bool) int {
	t.Helper()
	socksPort := freeTCPPort(t)
	cfg := fmt.Sprintf(`{
	  "dns": {"servers": [{"type": "hosts", "tag": "h", "predefined": {"rebind.test": "127.0.0.1"}}]},
	  "inbounds": [{"type": "mixed", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": %d}],
	  "outbounds": [{"type": "direct", "tag": "direct"}]
	}`, socksPort)
	path := filepath.Join(t.TempDir(), "sing_origin.json")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	sc := conf.NewSingConfig()
	sc.OriginalPath = path
	sc.LogConfig.Disabled = true
	sc.AllowPrivateDestinations = allowPrivate
	core, err := New(&conf.CoreConfig{Type: "sing", SingConfig: sc})
	if err != nil {
		t.Fatalf("new sing core: %v", err)
	}
	if err := core.Start(); err != nil {
		t.Fatalf("start sing core: %v", err)
	}
	t.Cleanup(func() { _ = core.Close() })
	return socksPort
}

// reachable asks the SOCKS inbound for host:port and reports whether a byte
// sent through comes back from the echo server.
func reachable(t *testing.T, socksPort int, host string, port int) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return false
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		return false
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return false
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil || head[1] != 0 {
		return false
	}
	var skip int
	switch head[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return false
		}
		skip = int(l[0]) + 2
	}
	if _, err := io.ReadFull(c, make([]byte, skip)); err != nil {
		return false
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		return false
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil {
		return false
	}
	return string(got) == "ping"
}

func TestPrivateDestinations_RefusedByDefault(t *testing.T) {
	echo := echoServer(t)
	socks := startBox(t, false)
	if reachable(t, socks, "127.0.0.1", echo) {
		t.Fatal("a subscriber reached the node's loopback by address")
	}
	if reachable(t, socks, "rebind.test", echo) {
		t.Fatal("a subscriber reached the node's loopback through a name that resolves to it")
	}
}

// The control: the same harness does get through when the operator opts out,
// so the refusals above are the rules at work and not a broken test.
func TestPrivateDestinations_AllowedWhenOptedOut(t *testing.T) {
	echo := echoServer(t)
	socks := startBox(t, true)
	if !reachable(t, socks, "127.0.0.1", echo) {
		t.Fatal("opted out, but loopback by address is still refused")
	}
	if !reachable(t, socks, "rebind.test", echo) {
		t.Fatal("opted out, but loopback by name is still refused")
	}
}
