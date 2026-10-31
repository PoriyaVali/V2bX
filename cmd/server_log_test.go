package cmd

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

// Every Log.Level sets a level: Mihomo's package changes the process default
// to debug, and a blank or misspelt level used to leave it there.
func TestLogLevelAlwaysSetsALevel(t *testing.T) {
	for level, want := range map[string]log.Level{
		"": log.InfoLevel, "info": log.InfoLevel, "debug": log.DebugLevel, "warn": log.WarnLevel,
		"Warning": log.WarnLevel, "error": log.ErrorLevel, "none": log.PanicLevel,
	} {
		if got, err := logLevel(level); err != nil || got != want {
			t.Errorf("%q: got %v, %v; want %v", level, got, err, want)
		}
	}
	if got, err := logLevel("verbose"); err == nil || got != log.InfoLevel {
		t.Errorf("unknown level: got %v, %v; want info and an error", got, err)
	}
}
