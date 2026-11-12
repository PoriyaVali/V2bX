package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PoriyaVali/V2bX/common/smartdns"
	"github.com/miekg/dns"
)

// TestEveryCoreResolvesThroughTheForwarder gives the process a DNS forwarder
// whose only resolver knows a name nothing else does, and asks a node on each
// core to connect a user to that name. The connection is made only if the
// core resolved it through the forwarder.
func TestEveryCoreResolvesThroughTheForwarder(t *testing.T) {
	// A name per core: the forwarder keeps an answer it has.
	const zone = ".smartdns.test."
	var asked atomic.Int64
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		if !strings.HasSuffix(q.Name, zone) {
			resp.Rcode = dns.RcodeNameError
		} else if q.Qtype == dns.TypeA {
			asked.Add(1)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   net.IPv4(127, 0, 0, 1),
			})
		}
		_ = w.WriteMsg(resp)
	})
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: ln, Handler: handler}} {
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	if _, err := smartdns.Enable(smartdns.Config{Servers: []string{pc.LocalAddr().String()}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(smartdns.Disable)

	nodes := ledgerNodes(t)
	cert := servedCertificate(t)
	mihomo := buildMihomoClient(t)
	_, echoPort, _ := net.SplitHostPort(servedEcho(t))
	// What install.sh puts in /etc/V2bX: a DNS section naming the machine's
	// resolver.
	origin := filepath.Join(t.TempDir(), "sing_origin.json")
	installed, err := os.ReadFile("../example/sing_origin.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(origin, installed, 0o600); err != nil {
		t.Fatal(err)
	}
	for i, c := range []struct{ node, core, singOrigin string }{
		{node: "vless/tcp-tls", core: "xray"},
		{node: "vless/tcp-tls", core: "sing"},
		{node: "vless/tcp-tls", core: "sing", singOrigin: origin},
		{node: "vless/tcp-tls", core: "mihomo"},
		{node: "hysteria2/plain", core: "hysteria2"},
		{node: "mieru/tcp", core: "mihomo"},
	} {
		t.Run(fmt.Sprintf("%s/%s/%d", c.node, c.core, i), func(t *testing.T) {
			servedSingOrigin = c.singOrigin
			defer func() { servedSingOrigin = "" }()
			n, ok := nodes[c.node]
			if !ok {
				t.Fatalf("served.json has no %s node", c.node)
			}
			before := asked.Load()
			target := net.JoinHostPort(fmt.Sprintf("echo-%d%s", i, strings.TrimSuffix(zone, ".")), echoPort)
			port, err := startServedNode(t, n, c.core, cert)
			if notInThisBuild(err) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatalf("the node did not start: %v", err)
			}
			if err := runClash(t, mihomo, clashProfile(t, n.Clash, port), target); err != nil {
				t.Fatalf("a name only the forwarder's resolver knows was not reached: %v", err)
			}
			if asked.Load() == before {
				t.Fatal("the name was reached without the forwarder's resolver being asked")
			}
		})
	}
}
