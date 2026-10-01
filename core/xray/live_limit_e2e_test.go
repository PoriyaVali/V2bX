package xray

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/limiter"
)

// The dispatcher must install a live wrapper even when the initial plan is
// unlimited. Change the plan after the real shadowsocks connection is open.
func TestXrayEstablishedConnectionPicksUpSpeedLimit(t *testing.T) {
	_, tag, port := xrayNode(t, 0)
	conn, ok := dialThrough(t, port, echoServer(t))
	if !ok {
		t.Fatal("initial unlimited connection failed")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	l, err := limiter.GetLimiter(tag)
	if err != nil {
		t.Fatal(err)
	}
	l.UpdateUserLimits(tag, []panel.UserInfo{{Id: 1, Uuid: e2eUUID, SpeedLimit: 1}})
	payload := bytes.Repeat([]byte("x"), 128*1024)
	written := make(chan error, 1)
	started := time.Now()
	go func() {
		_, err := conn.Write(payload)
		written <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("limited connection changed the payload")
	}
	if elapsed := time.Since(started); elapsed < 150*time.Millisecond {
		t.Fatalf("existing connection ignored 1 Mbit/s plan: 128 KiB echoed in %v", elapsed)
	}
}
