package xray

import (
	"encoding/json"
	"testing"
)

func TestXHTTPSettingsPutsPHPEmptyArraysRight(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`[]`, `{}`},
		{` [ ] `, `{}`},
		{`{"path":"/","extra":[]}`, `{"extra":{},"path":"/"}`},
		{`{"path":"/","headers":[],"xmux":[],"downloadSettings":[]}`, `{"path":"/"}`},
		{`{"extra":{"headers":[],"xmux":{"maxConcurrency":"4-8"}}}`, `{"extra":{"xmux":{"maxConcurrency":"4-8"}}}`},
		{`{"extra":{"downloadSettings":{"address":"a","port":443,"tlsSettings":[],"xhttpSettings":{"path":"/d","headers":[],"extra":[]}}}}`,
			`{"extra":{"downloadSettings":{"address":"a","port":443,"xhttpSettings":{"extra":{},"path":"/d"}}}}`},
		// Lists stay lists, and numbers keep their digits.
		{`{"extra":{"headers":[],"downloadSettings":{"tlsSettings":{"alpn":[]},"port":12345678901234567890}}}`,
			`{"extra":{"downloadSettings":{"port":12345678901234567890,"tlsSettings":{"alpn":[]}}}}`},
	} {
		if got := string(xhttpSettings(json.RawMessage(tc.in))); got != tc.want {
			t.Errorf("xhttpSettings(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
	// Nothing to put right, or nothing that decodes: returned as given.
	for _, in := range []string{`{"path":"/","extra":{"headers":{"a":"b"}}}`, `{"path":`, `"x"`} {
		if got := string(xhttpSettings(json.RawMessage(in))); got != in {
			t.Errorf("xhttpSettings(%s) = %s, want it unchanged", in, got)
		}
	}
}
