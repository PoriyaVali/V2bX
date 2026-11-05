package panel

import (
	"bytes"
	"encoding/json"
)

// A PHP panel decodes the settings it stores into arrays and encodes an empty
// object back as an empty array. So a WebSocket node whose Host header was
// cleared reached the node with "headers":[], Irboard's and Xboard's XHTTP
// template with "extra":[], and settings left empty as [] or null. Every
// core refuses [] where it wants an object, and the node never came up.
//
// These are the keys of a transport's settings that hold an object: tcp's
// header and its request and response, the WebSocket and HTTPUpgrade
// headers, KCP's header, and XHTTP's xmux and download leg.
var objectSettingKeys = map[string]bool{
	"headers":          true,
	"header":           true,
	"request":          true,
	"response":         true,
	"xmux":             true,
	"downloadSettings": true,
	"xhttpSettings":    true,
	"tlsSettings":      true,
	"realitySettings":  true,
	"sockopt":          true,
}

// NormalizeNetworkSettings returns a panel's transport settings with each
// empty array that stands for an empty object put right: absent for the keys
// above, and {} for XHTTP's "extra", whose presence means that the settings
// are extra's. Settings that are entirely [] or null are none, and come back
// nil. Anything that does not decode is returned as it is, for the core to
// report.
func NormalizeNetworkSettings(raw json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(bytes.Join(bytes.Fields(trimmed), nil), []byte("[]")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var settings map[string]any
	if err := dec.Decode(&settings); err != nil || !mendEmptyArrays(settings) {
		return raw
	}
	mended, err := json.Marshal(settings)
	if err != nil {
		return raw
	}
	return mended
}

func mendEmptyArrays(level map[string]any) (changed bool) {
	for key, value := range level {
		switch v := value.(type) {
		case []any:
			if len(v) != 0 {
				continue
			}
			if key == "extra" {
				level[key] = map[string]any{}
				changed = true
			} else if objectSettingKeys[key] {
				delete(level, key)
				changed = true
			}
		case map[string]any:
			if mendEmptyArrays(v) {
				changed = true
			}
		}
	}
	return changed
}
