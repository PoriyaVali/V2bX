package xray

import (
	"bytes"
	"encoding/json"
)

// A PHP panel decodes the settings it stores into arrays, and encodes an empty
// object back as an empty array. So the XHTTP template that Irboard and
// Xboard offer, {"path":"/","mode":"auto","extra":{}}, reached the node with
// "extra":[], and so did an emptied "headers". Xray refuses [] wherever it
// wants an object, and the node never came up.
//
// These are the keys of XHTTP settings that hold an object.
var xhttpObjectKeys = map[string]bool{
	"headers":          true,
	"xmux":             true,
	"downloadSettings": true,
	"xhttpSettings":    true,
	"tlsSettings":      true,
	"realitySettings":  true,
	"sockopt":          true,
}

// xhttpSettings returns a panel's XHTTP settings with each empty array that
// stands for an empty object put right. An empty "extra" becomes {}: present,
// it still means that the settings are extra's, which is how the panel's
// clients read it too. Any other is left out, which is what an empty object
// means there. Settings that do not decode are returned as they are, for
// Xray to report.
func xhttpSettings(raw json.RawMessage) json.RawMessage {
	if isEmptyJSONArray(raw) {
		return json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
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
			} else if xhttpObjectKeys[key] {
				delete(level, key)
				changed = true
			}
		case map[string]any:
			// extra and downloadSettings.xhttpSettings are XHTTP settings
			// themselves; downloadSettings holds the sections above.
			if key == "extra" || key == "downloadSettings" || key == "xhttpSettings" {
				if mendEmptyArrays(v) {
					changed = true
				}
			}
		}
	}
	return changed
}

// isEmptyJSONArray reports whether raw is [], as PHP writes an empty object.
func isEmptyJSONArray(raw json.RawMessage) bool {
	return bytes.Equal(bytes.Join(bytes.Fields(raw), nil), []byte("[]"))
}
