package panel

import (
	"encoding/json"
	"testing"
)

// An anytls node used to have node.Security hardcoded to Tls, so REALITY could
// never be selected for it however completely the sing core implemented it.
// These cases pin the decode + mode selection, including the un-upgraded-panel
// shape that must keep behaving exactly as before.
func TestAnyTlsSecurityFromPanel(t *testing.T) {
	decide := func(body string) (int, AnyTlsNode) {
		t.Helper()
		var n AnyTlsNode
		if err := json.Unmarshal([]byte(body), &n); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if n.Tls == Reality {
			return Reality, n
		}
		return Tls, n
	}

	// A panel that predates the tls column sends neither key.
	if got, _ := decide(`{"server_port":2087,"server_name":"a.example.com"}`); got != Tls {
		t.Fatalf("legacy panel payload => %d, want Tls(%d)", got, Tls)
	}

	// Explicit plain TLS.
	if got, _ := decide(`{"server_port":2087,"tls":1}`); got != Tls {
		t.Fatalf("tls=1 => %d, want Tls(%d)", got, Tls)
	}

	// REALITY, with the settings the sing core needs to build the inbound.
	got, n := decide(`{"server_port":2087,"tls":2,"tls_settings":{
		"server_name":"www.microsoft.com","server_port":"443",
		"short_id":"abcd1234","private_key":"PRIV","dest":"www.microsoft.com"}}`)
	if got != Reality {
		t.Fatalf("tls=2 => %d, want Reality(%d)", got, Reality)
	}
	if n.TlsSettings.ServerName != "www.microsoft.com" || n.TlsSettings.ShortId != "abcd1234" {
		t.Fatalf("tls_settings did not decode: %+v", n.TlsSettings)
	}

	// ECH rides on the plain-TLS mode and must decode from the same struct.
	_, e := decide(`{"server_port":2087,"tls":1,"tls_settings":{"ech":"custom","ech_key":"QUJD"}}`)
	if e.TlsSettings.Ech != "custom" || e.TlsSettings.EchKey != "QUJD" {
		t.Fatalf("ech fields did not decode: %+v", e.TlsSettings)
	}
}
