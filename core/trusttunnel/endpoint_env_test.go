package trusttunnel

import (
	"net"
	"slices"
	"testing"

	"github.com/PoriyaVali/V2bX/common/smartdns"
)

// The endpoint resolves with the C library. While V2bX's forwarder is asking
// the resolvers over TCP, glibc is told to as well.
func TestEndpointEnvAsksOverTCPWithTheForwarder(t *testing.T) {
	env := []string{"PATH=/bin", "RES_OPTIONS=timeout:2"}
	if got := endpointEnv(env); !slices.Equal(got, env) {
		t.Fatalf("without a forwarder: %v", got)
	}
	// Nothing listens there: the mode alone decides.
	gone, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := gone.LocalAddr().String()
	_ = gone.Close()
	if _, err := smartdns.Enable(smartdns.Config{Mode: smartdns.ModeAuto, Servers: []string{addr}}); err != nil {
		t.Fatal(err)
	}
	if got := endpointEnv(env); !slices.Equal(got, env) {
		smartdns.Disable()
		t.Fatalf("with UDP not known to be lossy: %v", got)
	}
	smartdns.Disable()
	if _, err := smartdns.Enable(smartdns.Config{Mode: smartdns.ModeTCP, Servers: []string{addr}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(smartdns.Disable)
	want := []string{"PATH=/bin", "RES_OPTIONS=timeout:2 use-vc"}
	if got := endpointEnv(env); !slices.Equal(got, want) {
		t.Fatalf("over TCP: %v, want %v", got, want)
	}
	if got := endpointEnv([]string{"PATH=/bin"}); !slices.Equal(got, []string{"PATH=/bin", "RES_OPTIONS=use-vc"}) {
		t.Fatalf("over TCP, no options set: %v", got)
	}
	already := []string{"RES_OPTIONS=use-vc"}
	if got := endpointEnv(already); !slices.Equal(got, already) {
		t.Fatalf("already set: %v", got)
	}
}
