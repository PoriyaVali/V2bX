// mihomoclient dials one Clash Meta proxy, as a mihomo-based client reads it
// from a subscription, and echoes through it:
//
//	mihomoclient PROFILE.json TARGET
//
// PROFILE.json holds one entry of a profile's proxies; TARGET is host:port of
// an echo server. It prints "ok", or the error and exits 1.
//
// A program of its own because mihomo's outbounds and xray-core cannot share a
// test binary: both pull in a protobuf file registered as "error.proto".
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

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

func run() error {
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
	m := &C.Metadata{NetWork: C.TCP}
	if err := m.SetRemoteAddress(os.Args[2]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
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

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: mihomoclient PROFILE.json TARGET")
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("ok")
}
