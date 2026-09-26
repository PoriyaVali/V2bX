//go:build !linux

package memguard

// The nodes run Linux. Elsewhere the ceiling is unknown, so no limit is set
// and the watcher never acts.
func ceilingBytes() uint64   { return 0 }
func availableBytes() uint64 { return 0 }
func rssBytes() uint64       { return 0 }
func openFiles() int         { return 0 }
