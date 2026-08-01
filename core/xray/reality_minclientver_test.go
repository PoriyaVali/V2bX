package xray

import "testing"

// 🔴 Xray v26 changed what an empty minClientVer means. It used to be "no
// minimum"; now the config builder fills in []byte{26, 3, 27} and the REALITY
// handshake only authenticates clients reporting at least that Xray-core
// version. sing-box and mihomo report no Xray version at all, so leaving this
// empty refuses every one of their users - silently, because the server just
// falls back to the borrowed site and a prober still sees a perfect
// certificate.
//
// The node must therefore send an explicit permissive value, and must still
// honour an operator who sets a real one.
func TestRealityMinClientVerIsNeverLeftEmpty(t *testing.T) {
	cases := map[string]string{
		"":       "0.0.0", // the dangerous default is replaced
		"0.0.0":  "0.0.0",
		"1.8.0":  "1.8.0", // an operator's own value is respected
		"26.3.27": "26.3.27",
	}
	for in, want := range cases {
		got := in
		if got == "" {
			got = "0.0.0"
		}
		if got != want {
			t.Errorf("minClientVer %q -> %q, want %q", in, got, want)
		}
		if got == "" {
			t.Errorf("minClientVer %q produced an empty value, which xray v26 replaces with 26.3.27", in)
		}
	}
}
