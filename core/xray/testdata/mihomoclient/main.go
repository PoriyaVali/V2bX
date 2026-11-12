// mihomoclient dials one Clash Meta proxy, as a mihomo-based client reads it
// from a subscription, and echoes through it:
//
//	mihomoclient PROFILE.json TARGET [udp|udp-refused SECOND]
//	mihomoclient PROFILE.json TARGET bulk SIZE
//	mihomoclient PROFILE.json TARGET hold
//	mihomoclient PROFILE.json TARGET upload|download SIZE
//	mihomoclient PROFILE.json TARGET udp-bulk COUNT SIZE
//
// PROFILE.json holds one entry of a profile's proxies; TARGET is host:port of
// an echo server over TCP. With "udp", TARGET and SECOND are UDP echo servers,
// checked as internal/udpecho's Check does; with "udp-refused", as its Refused
// does, SECOND being one the node's rules refuse. It prints "ok", or the error
// and exits 1.
//
// "bulk" echoes SIZE random bytes over TCP. "hold" echoes over TCP, prints
// "ready", waits for a line on stdin, then echoes again over the same
// connection and prints "open" or "closed: ERROR". "upload" and "download"
// move SIZE bytes one way against an internal/tcpmeter server, and print
// "ok ms=N", how long it took. "udp-bulk" echoes COUNT datagrams of SIZE
// bytes, as internal/udpecho's Bulk does, and prints "ok sent=N received=M".
//
// With MIHOMOCLIENT_INNER_TLS set, a TCP connection speaks TLS to TARGET
// through the proxy, as a browser does, trusting any certificate.
//
// A program of its own because mihomo's outbounds and xray-core cannot share a
// test binary: both pull in a protobuf file registered as "error.proto".
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/PoriyaVali/V2bX/internal/tcpmeter"
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

func run(mode string) error {
	udp := mode == "udp" || mode == "udp-refused" || mode == "udp-bulk"
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
	if udp || mode == "hold" || mode == "upload" || mode == "download" {
		// A UDP session lasts as long as its context, and the checks resend;
		// a held connection outlives a removal on the node, and a metered
		// transfer a speed limit.
		timeout = 25 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if mode == "udp-bulk" {
		return datagramBulk(ctx, p, os.Args[2], os.Args[4], os.Args[5])
	}
	if udp {
		return datagram(ctx, p, os.Args[2], os.Args[4], mode == "udp-refused")
	}
	m := &C.Metadata{NetWork: C.TCP}
	if err := m.SetRemoteAddress(os.Args[2]); err != nil {
		return err
	}
	var conn net.Conn
	if conn, err = p.DialContext(ctx, m); err != nil {
		return err
	}
	defer conn.Close()
	if os.Getenv("MIHOMOCLIENT_INNER_TLS") != "" {
		inner := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		if err := inner.Handshake(); err != nil {
			return fmt.Errorf("inner TLS: %w", err)
		}
		conn = inner
	}
	switch mode {
	case "upload", "download":
		size, err := strconv.Atoi(os.Args[4])
		if err != nil {
			return err
		}
		move := tcpmeter.Upload
		if mode == "download" {
			move = tcpmeter.Download
		}
		took, err := move(conn, size)
		if err != nil {
			return err
		}
		fmt.Printf("ok ms=%d\n", took.Milliseconds())
		os.Exit(0)
	case "bulk":
		size, err := strconv.Atoi(os.Args[4])
		if err != nil {
			return err
		}
		return bulk(conn, size)
	case "hold":
		if err := echo(conn); err != nil {
			return err
		}
		fmt.Println("ready")
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			return err
		}
		if err := echo(conn); err != nil {
			fmt.Println("closed:", err)
		} else {
			fmt.Println("open")
		}
		os.Exit(0)
	}
	return echo(conn)
}

func echo(conn net.Conn) error {
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

// bulk echoes size random bytes, writing while it reads.
func bulk(conn net.Conn, size int) error {
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	data := make([]byte, size)
	_, _ = rand.Read(data)
	written := make(chan error, 1)
	go func() {
		_, err := conn.Write(data)
		written <- err
	}()
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if err := <-written; err != nil {
		return err
	}
	if !bytes.Equal(got, data) {
		return fmt.Errorf("echoed different bytes")
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

// datagramBulk echoes count datagrams of size bytes to target.
func datagramBulk(ctx context.Context, p C.Proxy, target, count, size string) error {
	if !p.SupportUDP() {
		return udpecho.ErrNoUDP
	}
	to, err := netip.ParseAddrPort(target)
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(count)
	if err != nil {
		return err
	}
	s, err := strconv.Atoi(size)
	if err != nil {
		return err
	}
	m := &C.Metadata{NetWork: C.UDP}
	if err := m.SetRemoteAddress(target); err != nil {
		return err
	}
	pc, err := p.ListenPacketContext(ctx, m)
	if err != nil {
		return err
	}
	sent, received, err := udpecho.Bulk(pc, to, n, s)
	if err != nil {
		return err
	}
	fmt.Printf("ok sent=%d received=%d\n", sent, received)
	os.Exit(0)
	return nil
}

func main() {
	mode := ""
	if len(os.Args) > 3 {
		mode = os.Args[3]
	}
	args := map[string]int{"": 3, "udp": 5, "udp-refused": 5, "bulk": 5, "hold": 4, "upload": 5, "download": 5, "udp-bulk": 6}
	if want, ok := args[mode]; !ok || len(os.Args) != want {
		fmt.Println("usage: mihomoclient PROFILE.json TARGET [udp|udp-refused SECOND | bulk SIZE | hold | upload SIZE | download SIZE | udp-bulk COUNT SIZE]")
		os.Exit(2)
	}
	// A connection that ignores its deadline must not hold up the test.
	time.AfterFunc(30*time.Second, func() {
		fmt.Println("nothing came back in 30 seconds")
		os.Exit(1)
	})
	if err := run(mode); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("ok")
}
