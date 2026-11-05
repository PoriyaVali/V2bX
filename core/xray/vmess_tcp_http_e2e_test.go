package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// VMess over TCP with V2Ray's HTTP header, from the TCP template of Irboard's
// VMess form as the node is served it, reached by both client families as
// Irboard configures them. Setup used to give such a node sing-box, whose own
// HTTP transport neither of them reaches; it now gives it this core.
func TestVMessOverTCPWithAnHTTPHeader(t *testing.T) {
	limiter.Init()
	tag := "e2e-vmess-tcp-http"
	users := []panel.UserInfo{{Id: 1, Uuid: e2eUUID}}
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	t.Cleanup(func() { limiter.DeleteLimiter(tag) })
	c, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: conf.NewXrayConfig()})
	if err != nil {
		t.Fatal(err)
	}
	x := c.(*Xray)
	if err := x.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })
	port, echo := freePort(t), echoServer(t)
	v := &panel.VAllssNode{Network: "tcp", NetworkSettings: json.RawMessage(
		`{"header":{"type":"http","request":{"path":["/"],"headers":{"Host":["www.baidu.com","www.bing.com"]}}}}`)}
	v.ServerPort = port
	info := &panel.NodeInfo{Type: "vmess", Security: panel.None, VAllss: v, Common: &v.CommonNode}
	opts := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}
	opts.XrayOptions.DisableSniffing = true
	if err := x.AddNode(tag, info, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := x.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	if err := x.removeOutbound(tag); err != nil {
		t.Fatal(err)
	}
	allow := json.RawMessage(`{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}`)
	ob, err := (&coreConf.OutboundDetourConfig{Protocol: "freedom", Tag: tag, Settings: &allow}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := x.addOutbound(ob); err != nil {
		t.Fatal(err)
	}

	// Xray-based clients, from Irboard's vmess:// link: type=http, the first
	// Host, path /. Also with the header v2rayN writes in full.
	for _, header := range []string{
		`{"type":"http","request":{"path":["/"],"headers":{"Host":["www.baidu.com"]}}}`,
		`{"type":"http","request":{"version":"1.1","method":"GET","path":["/"],"headers":{"Host":["www.baidu.com"],"User-Agent":["Mozilla/5.0"],"Accept-Encoding":["gzip, deflate"],"Connection":["keep-alive"],"Pragma":"no-cache"}}}`,
	} {
		raw := fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"security":"auto"}]}]},"streamSettings":{"network":"tcp","tcpSettings":{"header":%s}}}]}`, port, e2eUUID, header)
		var cfg coreConf.Config
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			t.Fatal(err)
		}
		pb, err := cfg.Build()
		if err != nil {
			t.Fatal(err)
		}
		client, err := core.New(pb)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Start(); err != nil {
			t.Fatal(err)
		}
		host, p, _ := net.SplitHostPort(echo)
		pn, _ := strconv.Atoi(p)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		conn, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(pn)))
		if err != nil {
			t.Fatal(err)
		}
		if err := echoThrough(conn); err != nil {
			t.Errorf("Xray client, header %s: %v", header, err)
		}
		conn.Close()
		cancel()
		client.Close()
	}

	// mihomo-based clients, from Irboard's Clash Meta profile.
	profile := fmt.Sprintf(`{"name":"vm","type":"vmess","server":"127.0.0.1","port":%d,"uuid":%q,"alterId":0,"cipher":"auto","udp":true,"network":"http","http-opts":{"headers":{"Host":["www.baidu.com","www.bing.com"]},"path":["/"]}}`, port, e2eUUID)
	file := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(file, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(mihomoClient(t), file, echo).CombinedOutput(); err != nil {
		t.Errorf("mihomo client: %v: %s", err, strings.TrimSpace(string(out)))
	}
}
