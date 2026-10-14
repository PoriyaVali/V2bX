//go:build soak

package sing

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
)

func TestAnyTLSNodeRetirementClosesStreamAndRebuildsSameTag(t *testing.T) {
	r := startSoakRig(t)
	echo := listen(t, func(conn net.Conn) { defer conn.Close(); _, _ = io.Copy(conn, conn) })
	old, err := socksConnect(r.socksPort, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	_ = old.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := old.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(old, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	if r.trackedOpen() != 1 || anytlsSessionsHeld(t, r) != 1 {
		t.Fatal("real AnyTLS session/stream was not established")
	}
	type result struct {
		traffic []panel.UserTraffic
		err     error
	}
	done := make(chan result, 1)
	go func() { traffic, err := r.server.RetireNode(r.tag); done <- result{traffic, err} }()
	select {
	case retired := <-done:
		if retired.err != nil || len(retired.traffic) != 1 || retired.traffic[0].UID != 1 || retired.traffic[0].Upload != 5 || retired.traffic[0].Download != 5 {
			t.Fatalf("final AnyTLS sample = %+v, %v", retired.traffic, retired.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AnyTLS retirement did not join the live transport/copy operations")
	}
	if r.trackedOpen() != 0 {
		t.Fatal("retired AnyTLS stream remains tracked")
	}
	_ = old.SetDeadline(time.Now().Add(time.Second))
	_, _ = old.Write([]byte("old"))
	if _, err := old.Read(make([]byte, 3)); err == nil {
		t.Fatal("retired AnyTLS stream still transfers data")
	}

	cert, key := writeSelfSigned(t, t.TempDir())
	common := panel.CommonNode{ServerPort: r.serverPort, ServerName: "node.test"}
	info := &panel.NodeInfo{Id: 1, Type: "anytls", Security: panel.Tls, Common: &common, AnyTls: &panel.AnyTlsNode{CommonNode: common}}
	options := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions(), CertConfig: &conf.CertConfig{CertMode: "file", CertFile: cert, KeyFile: key}}
	decoyOff := false
	options.SingOptions.DecoySite = &decoyOff
	if err := r.server.AddNode(r.tag, info, options); err != nil {
		t.Fatal(err)
	}
	if _, err := r.server.AddUsers(&vCore.AddUsersParams{Tag: r.tag, NodeInfo: info, Users: []panel.UserInfo{{Id: 9, Uuid: "0e6d2c64-0000-4000-8000-000000000001"}}}); err != nil {
		t.Fatal(err)
	}
	fresh, err := socksConnect(r.socksPort, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	_ = fresh.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fresh.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(fresh, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	traffic, err := r.server.GetUserTrafficSlice(r.tag, true)
	if err != nil || len(traffic) != 1 || traffic[0].UID != 9 || traffic[0].Upload != 5 || traffic[0].Download != 5 {
		t.Fatalf("fresh generation AnyTLS sample = %+v, %v", traffic, err)
	}
}
