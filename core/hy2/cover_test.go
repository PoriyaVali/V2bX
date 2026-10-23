package hy2

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/decoy"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/PoriyaVali/V2bX/limiter"
)

func TestHy2_DefaultCoverOwnsTCPAndRetiresWithUDP(t *testing.T) {
	r := newHyRig(t)
	r.addNode(t, "public-cover")
	cert, _ := os.ReadFile(r.opts.CertConfig.CertFile)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "node.test"}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(r.infos["public-cover"].Common.ServerPort))
	response, err := client.Get("https://" + address + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 200 || !strings.Contains(string(body), "<title>") {
		t.Fatal("owned HTTPS site was not served")
	}
	if err := r.h.DelNode("public-cover"); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("public HTTPS outlived UDP node")
	}
}

func TestHy2_CoverTCPConflictKeepsExistingServiceAndUDP(t *testing.T) {
	r := newHyRig(t)
	existing, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	hy := &panel.Hysteria2Node{}
	hy.ServerPort = existing.Addr().(*net.TCPAddr).Port
	r.infos["occupied"] = &panel.NodeInfo{Type: "hysteria2", Hysteria2: hy, Common: &hy.CommonNode, Security: panel.Tls}
	user := panel.UserInfo{Id: 9, Uuid: "still-authenticated"}
	limiter.AddLimiter("occupied", &conf.LimitConfig{}, []panel.UserInfo{user}, map[int]int{})
	r.addNode(t, "occupied", user)
	if r.h.node("occupied").cover != nil || !authOK(r.h, "occupied", user.Uuid) {
		t.Fatal("TCP conflict disrupted the UDP node")
	}
	udp, err := net.ListenPacket("udp", existing.Addr().String())
	if err == nil {
		udp.Close()
		t.Fatal("UDP listener was not retained")
	}
	if err := r.h.DelNode("occupied"); err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", existing.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("existing TCP service was closed: %v", err)
	}
	c.Close()
}

func TestHy2_CoverTCPCanBeDisabled(t *testing.T) {
	r := newHyRig(t)
	disabled := false
	r.opts.Decoy = &decoy.Config{ServeTCP: &disabled}
	r.addNode(t, "no-tcp")
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(r.infos["no-tcp"].Common.ServerPort))
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("disabled cover still holds TCP: %v", err)
	}
	tcp.Close()
	if r.h.node("no-tcp").cover != nil {
		t.Fatal("disabled cover was created")
	}
}
