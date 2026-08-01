package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"

	_ "github.com/PoriyaVali/V2bX/core/imports"
	"github.com/spf13/cobra"
)

var command = &cobra.Command{
	Use: "V2bX",
}

// Run executes the CLI and exits non-zero when the command failed.
//
// It used to log the error and return, so the process exited 0 no matter what
// went wrong - including for a command that does not exist. Any script that
// branched on V2bX's exit status was therefore told "fine" unconditionally, and
// one did exactly that: it guarded a config edit with a command name that was
// never implemented, printed "config parses", and validated nothing.
func Run() {
	if err := command.Execute(); err != nil {
		log.WithField("err", err).Error("Execute command failed")
		os.Exit(1)
	}
}
