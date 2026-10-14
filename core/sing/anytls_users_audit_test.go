//go:build soak

package sing

import (
	"crypto/sha256"
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	vCore "github.com/PoriyaVali/V2bX/core"
)

// Opens real TLS sessions carrying valid AnyTLS authentication, while panel
// user updates preserve the connecting user and churn a different user.
func TestAnyTLSUsersReloadDuringAuthentication(t *testing.T) {
	r := startSoakRig(t)
	user := "0e6d2c64-0000-4000-8000-000000000001"
	password := sha256.Sum256([]byte(user))
	auth := append(password[:], 0, 0) // padding length zero
	info := &panel.NodeInfo{Type: "anytls"}
	churn := []panel.UserInfo{{Id: 8, Uuid: "b99c6c1e-5d7a-4c55-9b0e-6f2d7e8a9c10"}}
	var stop atomic.Bool
	var authenticated atomic.Int64
	var wg sync.WaitGroup
	defer func() {
		stop.Store(true)
		wg.Wait()
	}()
	for worker := 0; worker < 2; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(r.serverPort), &tls.Config{ServerName: "node.test", InsecureSkipVerify: true})
				if err != nil {
					continue
				}
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if _, err := conn.Write(auth); err == nil {
					authenticated.Add(1)
				}
				_ = conn.Close()
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := r.server.AddUsers(&vCore.AddUsersParams{Tag: r.tag, Users: churn, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
		if err := r.server.DelUsers(churn, r.tag, info); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if authenticated.Load() == 0 {
		t.Fatal("no TLS authentication payloads sent")
	}
	t.Logf("sent %d valid AnyTLS authentication payloads over real TLS", authenticated.Load())
}
