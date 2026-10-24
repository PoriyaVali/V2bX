package conf

import (
	"path/filepath"
	"testing"
)

func TestCertificateRenewalPathOwnership(t *testing.T) {
	dir := t.TempDir()
	node := func(mode, domain, cert, key string) NodeConfig {
		return NodeConfig{Options: Options{CertConfig: &CertConfig{CertMode: mode, CertDomain: domain, CertFile: filepath.Join(dir, cert), KeyFile: filepath.Join(dir, key)}}}
	}
	for _, tc := range []struct {
		name    string
		nodes   []NodeConfig
		wantErr bool
	}{
		{"same domain managed sharing", []NodeConfig{node("http", "a.test", "c", "k"), node("http", "A.TEST.", "c", "k")}, false},
		{"different domain managed collision", []NodeConfig{node("http", "a.test", "c", "k"), node("http", "b.test", "c", "k")}, true},
		{"partial key sharing", []NodeConfig{node("http", "a.test", "c1", "k"), node("http", "a.test", "c2", "k")}, true},
		{"self and managed collision", []NodeConfig{node("self", "a.test", "c", "k"), node("http", "a.test", "c", "k")}, true},
		{"external shared multiSAN", []NodeConfig{node("file", "a.test", "c", "k"), node("file", "b.test", "c", "k")}, false},
		{"one managed one unspecified reader", []NodeConfig{node("http", "a.test", "c", "k"), node("file", "", "c", "k")}, false},
		{"managed and different reader identity", []NodeConfig{node("http", "a.test", "c", "k"), node("file", "b.test", "c", "k")}, true},
		{"reader must not hide managed owner", []NodeConfig{node("http", "a.test", "c", "k"), node("file", "", "c", "k"), node("http", "b.test", "c", "k")}, true},
		{"combined same pair", []NodeConfig{node("http", "a.test", "combined", "combined"), node("http", "a.test", "combined", "combined")}, false},
		{"expanded domains separate", []NodeConfig{node("http", "a.test", "{domain}.cert", "{domain}.key"), node("http", "b.test", "{domain}.cert", "{domain}.key")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCertificatePaths(tc.nodes)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ownership validation err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
