package format

// UserTag is the key a user is known by on one node: "<node tag>|<uuid>".
//
// Built by concatenation rather than fmt.Sprintf: it runs on every connection
// and for every user in every traffic report, and Sprintf took several times
// as long for the same string.
func UserTag(tag string, uuid string) string {
	return tag + "|" + uuid
}
