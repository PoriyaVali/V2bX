package sing

import (
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

// The panel emits base64_encode(MarshalECHKeys(...)) while sing-box's
// parseECHKeys insists on a PEM block of type "ECH KEYS". That mismatch fails at
// inbound construction with a message about ECH keys rather than about encoding,
// so it is worth pinning both directions here.
func TestEchKeyToPEM(t *testing.T) {
	raw := []byte{0x00, 0x20, 0xde, 0xad, 0xbe, 0xef}
	std := base64.StdEncoding.EncodeToString(raw)

	out, err := echKeyToPEM(std)
	if err != nil {
		t.Fatalf("std base64: %v", err)
	}
	block, _ := pem.Decode([]byte(out))
	if block == nil {
		t.Fatal("output is not PEM")
	}
	if block.Type != "ECH KEYS" {
		t.Fatalf("block type = %q, sing-box requires \"ECH KEYS\"", block.Type)
	}
	if string(block.Bytes) != string(raw) {
		t.Fatal("key bytes did not survive the round trip")
	}

	// An operator who pastes a real PEM block must not have it re-encoded.
	if again, err := echKeyToPEM(out); err != nil || again != strings.TrimSpace(out) {
		t.Fatalf("PEM passthrough failed: %v", err)
	}

	// url-safe alphabet is accepted rather than failing a whole node over it.
	if _, err := echKeyToPEM(base64.URLEncoding.EncodeToString(raw)); err != nil {
		t.Fatalf("url-safe base64: %v", err)
	}

	for _, bad := range []string{"", "   ", "not base64 !!!"} {
		if _, err := echKeyToPEM(bad); err == nil {
			t.Fatalf("expected an error for %q", bad)
		}
	}
}
