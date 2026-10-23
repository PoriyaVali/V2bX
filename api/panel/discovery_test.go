package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PoriyaVali/V2bX/conf"
)

func TestDiscoverNodeConfigsKeepsAmbiguousAnyTLSAndVLESS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/config" || r.URL.Query().Get("node_id") != "57" || r.URL.Query().Get("token") != "test-key" {
			t.Error("probe did not use the authenticated config endpoint")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("node_type") {
		case "anytls":
			fmt.Fprint(w, `{"server_port":443,"tls":2,"padding_scheme":[],"tls_settings":{"server_name":"target.example.test"}}`)
		case "vless":
			fmt.Fprint(w, `{"server_port":8443,"tls":1,"network":"tcp"}`)
		default:
			w.WriteHeader(500)
			fmt.Fprint(w, `{"message":"server is not exist"}`)
		}
	}))
	defer srv.Close()
	found, err := DiscoverNodeConfigs(context.Background(), conf.ApiConfig{APIHost: srv.URL, Key: "test-key", NodeID: 57}, []string{"anytls", "trojan", "vless"})
	if err != nil || len(found) != 2 {
		t.Fatalf("ambiguous discovery = %v / %v", found, err)
	}
	if found[0].Type != "anytls" || found[0].Security != Reality || found[1].Type != "vless" {
		t.Fatal("protocol or TLS mode was guessed instead of decoded")
	}
}

func TestDiscoverNodeConfigsNeverSelectsFromIncompleteResults(t *testing.T) {
	for _, scenario := range []string{"timeout", "login_page", "server_error", "unauthorized"} {
		t.Run(scenario, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("node_type") == "anytls" {
					fmt.Fprint(w, `{"server_port":443,"tls":1}`)
					return
				}
				switch scenario {
				case "timeout":
					<-r.Context().Done()
				case "login_page":
					fmt.Fprint(w, "<html>login</html>")
				case "server_error":
					w.WriteHeader(500)
					fmt.Fprint(w, `{"message":"database unavailable"}`)
				case "unauthorized":
					w.WriteHeader(403)
					fmt.Fprint(w, "secret-test-key")
				}
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			found, err := DiscoverNodeConfigs(ctx, conf.ApiConfig{APIHost: srv.URL, Key: "secret-test-key", NodeID: 1}, []string{"anytls", "vless"})
			if err == nil || found != nil || strings.Contains(err.Error(), "secret-test-key") {
				t.Fatalf("unsafe partial result or exposed key: %v / %v", found, err)
			}
		})
	}
}
