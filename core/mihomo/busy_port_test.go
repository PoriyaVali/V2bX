package mihomo

import (
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	vCore "github.com/PoriyaVali/V2bX/core"
)

// A node whose port another program holds fails with the reason. For HTTP,
// the listener that failed to bind came back as a typed nil, and closing it
// panicked: one busy port took down the process and every node on it.
func TestBusyPortIsAnErrorNotACrash(t *testing.T) {
	for _, protocol := range []string{"http", "socks5", "mieru", "shadowquic", "sudoku", "snell"} {
		t.Run(protocol, func(t *testing.T) {
			c, info, _ := fixture(t, protocol, nil)
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Common.ServerPort))
			var holder io.Closer
			var e error
			if protocol == "shadowquic" {
				holder, e = net.ListenPacket("udp", address)
			} else {
				holder, e = net.Listen("tcp", address)
			}
			if e != nil {
				t.Fatal(e)
			}
			defer holder.Close()
			_, e = c.AddUsers(&vCore.AddUsersParams{Tag: t.Name(), Users: []panel.UserInfo{subscriber}, NodeInfo: info})
			if e == nil || !strings.Contains(e.Error(), "already in use") {
				t.Fatalf("adding users on a busy port returned %v", e)
			}
		})
	}
}
