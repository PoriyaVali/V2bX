// mihomoclient dials one Clash Meta proxy, as a mihomo-based client reads it
// from a subscription, and echoes through it:
//
//	mihomoclient PROFILE.json TARGET [udp|udp-refused SECOND]
//
// PROFILE.json holds one entry of a profile's proxies; TARGET is host:port of
// an echo server over TCP. With "udp", TARGET and SECOND are UDP echo servers,
// checked as internal/udpecho's Check does; with "udp-refused", as its Refused
// does, SECOND being one the node's rules refuse. It prints "ok", or the error
// and exits 1.
//
// A program of its own because mihomo's outbounds and xray-core cannot share a
// test binary: both pull in a protobuf file registered as "error.proto".
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/PoriyaVali/V2bX/internal/udpecho"
	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
)

// integers gives whole JSON numbers, which decode as float64, as the integers
// a YAML profile has, nested options included.
func integers(v any) any {
	switch v := v.(type) {
	case float64:
		if v == float64(int64(v)) {
			return int64(v)
		}
	case map[string]any:
		for k, e := range v {
			v[k] = integers(e)
		}
	case []any:
		for i, e := range v {
			v[i] = integers(e)
		}
	}
	return v
}

func run(udp bool) error {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var profile map[string]any
	if err := json.Unmarshal(raw, &profile); err != nil {
		return err
	}
	p, err := adapter.ParseProxy(integers(profile).(map[string]any))
	if err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	defer p.Close()
	timeout := 8 * time.Second
	if udp {
		// A UDP session lasts as long as its context, and the checks resend.
		timeout = 25 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if udp {
		return datagram(ctx, p, os.Args[2], os.Args[4], os.Args[3] == "udp-refused")
	}
	m := &C.Metadata{NetWork: C.TCP}
	if err := m.SetRemoteAddress(os.Args[2]); err != nil {
		return err
	}
	conn, err := p.DialContext(ctx, m)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return fmt.Errorf("echoed %q", buf)
	}
	return nil
}

// datagram checks UDP through the proxy, as mihomo relays a UDP session, to
// the echo servers first and second; refused, that the node drops what goes
// to second.
func datagram(ctx context.Context, p C.Proxy, first, second string, refused bool) error {
	if !p.SupportUDP() {
		return udpecho.ErrNoUDP
	}
	a, err := netip.ParseAddrPort(first)
	if err != nil {
		return err
	}
	b, err := netip.ParseAddrPort(second)
	if err != nil {
		return err
	}
	m := &C.Metadata{NetWork: C.UDP}
	if err := m.SetRemoteAddress(first); err != nil {
		return err
	}
	pc, err := p.ListenPacketContext(ctx, m)
	if err != nil {
		return err
	}
	if refused {
		return udpecho.Refused(pc, a, b)
	}
	notes, err := udpecho.Check(pc, a, b)
	for _, note := range notes {
		fmt.Println(note)
	}
	return err
}

func main() {
	tcp := len(os.Args) == 3
	if !tcp && (len(os.Args) != 5 || (os.Args[3] != "udp" && os.Args[3] != "udp-refused")) {
		fmt.Println("usage: mihomoclient PROFILE.json TARGET [udp|udp-refused SECOND]")
		os.Exit(2)
	}
	// A connection that ignores its deadline must not hold up the test.
	time.AfterFunc(30*time.Second, func() {
		fmt.Println("nothing came back in 30 seconds")
		os.Exit(1)
	})
	if err := run(!tcp); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("ok")
}
