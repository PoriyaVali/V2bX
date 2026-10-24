package conf

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// ValidateCertificatePaths prevents independently managed nodes from rotating
// a shared path to a certificate/key that breaks another node. Explicit file
// mode may share the exact pair; it does not acquire ownership of renewal.
func ValidateCertificatePaths(nodes []NodeConfig) error {
	type owner struct {
		index                   int
		mode, domain, cert, key string
		managed                 bool
	}
	canonical := func(path string) (string, error) {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
			absolute = resolved
		} else if parent, err := filepath.EvalSymlinks(filepath.Dir(absolute)); err == nil {
			absolute = filepath.Join(parent, filepath.Base(absolute))
		}
		if runtime.GOOS == "windows" {
			absolute = strings.ToLower(absolute)
		}
		return filepath.Clean(absolute), nil
	}
	owners := map[string]owner{}
	for i, node := range nodes {
		if node.ApiConfig.NodeType == "trusttunnel" || node.Options.CertConfig == nil {
			continue
		}
		cfg := *node.Options.CertConfig
		if cfg.CertMode == "none" || cfg.CertMode == "" {
			continue
		}
		cfg.ExpandPaths()
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			continue
		} // normal mode validation reports missing paths
		cert, err := canonical(cfg.CertFile)
		if err != nil {
			return fmt.Errorf("node %d invalid certificate path", i+1)
		}
		key, err := canonical(cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("node %d invalid key path", i+1)
		}
		managed := cfg.CertMode == "http" || cfg.CertMode == "dns" || cfg.CertMode == "self"
		current := owner{i, cfg.CertMode, strings.TrimSuffix(strings.ToLower(cfg.CertDomain), "."), cert, key, managed}
		for _, path := range []string{cert, key} {
			previous, ok := owners[path]
			if ok && (managed || previous.managed) {
				differentIdentity := previous.domain != "" && current.domain != "" && previous.domain != current.domain
				if previous.cert != cert || previous.key != key || differentIdentity || (managed && previous.managed && previous.mode != current.mode) {
					return fmt.Errorf("nodes %d and %d have conflicting certificate renewal ownership; use separate certificate/key paths or one shared renewal owner", previous.index+1, i+1)
				}
			}
			// Keep the managed owner, even when a later file-only reader shares it.
			if !ok || managed || !previous.managed {
				owners[path] = current
			}
		}
	}
	return nil
}
