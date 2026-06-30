//go:build linux

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/PoriyaVali/V2bX/common/exec"
	"github.com/spf13/cobra"
)

var statusCommand = cobra.Command{
	Use:   "status",
	Short: "Show V2bX service status and resource usage",
	Run:   statusHandle,
}

func init() {
	command.AddCommand(&statusCommand)
}

func statusHandle(_ *cobra.Command, _ []string) {
	fmt.Printf("\n%s%s %s%s%s\n\n", green, codename, yellow, version, plain)

	running, _ := checkRunning()
	if running {
		fmt.Printf("  Status  : %sRunning ✓%s\n", green, plain)
	} else {
		fmt.Printf("  Status  : %sStopped ✗%s\n", red, plain)
		fmt.Printf("\n  Start with: %sv2bx start%s\n\n", yellow, plain)
		return
	}

	// Uptime via PID start time
	pidOut, err := exec.RunCommandByShell("systemctl show V2bX --property=MainPID --value")
	if err == nil {
		pid := strings.TrimSpace(pidOut)
		if pid != "" && pid != "0" {
			etimeOut, err2 := exec.RunCommandByShell("ps -p " + pid + " -o etimes= 2>/dev/null")
			if err2 == nil {
				secs, _ := strconv.Atoi(strings.TrimSpace(etimeOut))
				if secs > 0 {
					h := secs / 3600
					m := (secs % 3600) / 60
					s := secs % 60
					if h > 0 {
						fmt.Printf("  Uptime  : %dh %dm %ds\n", h, m, s)
					} else {
						fmt.Printf("  Uptime  : %dm %ds\n", m, s)
					}
				}
			}
			// Memory from /proc
			memKB := readVmRSS(pid)
			if memKB > 0 {
				fmt.Printf("  Memory  : %d MB\n", memKB/1024)
			}
		}
	}

	// Autostart
	autoOut, _ := exec.RunCommandByShell("systemctl is-enabled V2bX 2>/dev/null")
	autoOut = strings.TrimSpace(autoOut)
	if autoOut == "enabled" {
		fmt.Printf("  Autostart: %senabled%s\n", green, plain)
	} else {
		fmt.Printf("  Autostart: %sdisabled%s\n", yellow, plain)
	}

	fmt.Printf("  Config  : /etc/V2bX/config.json\n")
	fmt.Printf("\n  %sv2bx log%s        → live logs\n", yellow, plain)
	fmt.Printf("  %sv2bx config%s     → show config\n", yellow, plain)
	fmt.Printf("  %sv2bx config edit%s → edit config\n\n", yellow, plain)
}

func readVmRSS(pid string) int64 {
	f, err := os.Open("/proc/" + pid + "/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseInt(fields[1], 10, 64)
				return v
			}
		}
	}
	return 0
}
