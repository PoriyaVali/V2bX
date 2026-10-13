package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateInstallerCommand(t *testing.T) {
	for _, name := range []string{"bare", "prefixed", "latest", "literal", "download_failure", "empty_installer", "installer_failure"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			trace := filepath.Join(root, "args")
			injected := filepath.Join(root, "injected")
			target := "1.7.2"
			switch name {
			case "prefixed":
				target = "v1.7.2"
			case "latest":
				target = ""
			case "literal":
				target = "1.7.2; touch " + injected
			}
			installer := "printf '%s\\n' \"$@\" > \"$UPDATE_TEST_TRACE\"\n"
			if name == "installer_failure" {
				installer += "exit 17\n"
			}
			curl := "#!/bin/sh\ncat <<'INSTALLER'\n" + installer + "INSTALLER\n"
			if name == "download_failure" {
				curl = "#!/bin/sh\nexit 22\n"
			} else if name == "empty_installer" {
				curl = "#!/bin/sh\nexit 0\n"
			}
			if err := os.WriteFile(filepath.Join(root, "curl"), []byte(curl), 0755); err != nil {
				t.Fatal(err)
			}
			process := updateInstallerCommand(target)
			process.Env = append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "UPDATE_TEST_TRACE="+trace)
			var output bytes.Buffer
			process.Stdin = nil
			process.Stdout, process.Stderr = &output, &output
			runErr := process.Run()
			wantFailure := name == "download_failure" || name == "empty_installer" || name == "installer_failure"
			if (runErr != nil) != wantFailure {
				t.Fatalf("error=%v, output=%s", runErr, output.String())
			}
			if name == "download_failure" || name == "empty_installer" {
				if _, err := os.Stat(trace); !os.IsNotExist(err) {
					t.Fatal("installer ran despite failed or empty download")
				}
				return
			}
			actual, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			if string(actual) != fmt.Sprintf("update\n%s\n", target) {
				t.Fatalf("argument changed: %q", actual)
			}
			if _, err := os.Stat(injected); !os.IsNotExist(err) {
				t.Fatal("target was interpreted as shell code")
			}
			if name == "installer_failure" && !strings.Contains(runErr.Error(), "exit status 17") {
				t.Fatalf("installer exit status lost: %v", runErr)
			}
		})
	}
}

func TestUpdateRejectsExtraVersionArguments(t *testing.T) {
	if err := updateCommand.Args(&updateCommand, []string{"1.7.2", "1.7.3"}); err == nil {
		t.Fatal("multiple target versions accepted")
	}
}
