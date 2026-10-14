package panel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
)

// Exercise the real HTTP/decode path with the same bulk response on each poll.
func BenchmarkGetUserListJSON(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			var body strings.Builder
			body.WriteString(`{"users":[`)
			for i := 0; i < count; i++ {
				if i != 0 {
					body.WriteByte(',')
				}
				fmt.Fprintf(&body, `{"id":%d,"uuid":"00000000-0000-0000-0000-%012d","speed_limit":0,"device_limit":3}`, i+1, i+1)
			}
			body.WriteString(`]}`)
			response := []byte(body.String())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(response)
			}))
			defer srv.Close()
			client, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeID: 1, Key: "test", NodeType: "anytls", Timeout: 5})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(response)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				users, err := client.GetUserList()
				if err != nil || len(users) != count {
					b.Fatalf("users=%d err=%v", len(users), err)
				}
			}
		})
	}
}
