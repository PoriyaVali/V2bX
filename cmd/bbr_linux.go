//go:build linux

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/PoriyaVali/V2bX/common/exec"
	"github.com/spf13/cobra"
)

var bbrCommand = cobra.Command{
	Use:   "bbr",
	Short: "Enable BBR + FQ and low-latency TCP settings for this server",
	Run:   bbrHandle,
}

func init() {
	command.AddCommand(&bbrCommand)
}

// sysctlSetting is one kernel setting this command applies, and why.
type sysctlSetting struct {
	key, value, why string
}

// networkTuning is what `V2bX bbr` sets for the whole server. Nothing here is
// applied unless an operator runs the command: they change every TCP socket
// on the machine, not only V2bX's (V2bX's own inbounds already use BBR on
// their sockets without it).
//
// Each one is a standard setting for a server whose traffic crosses long,
// lossy paths - here, mobile networks in Iran - and none trades throughput
// for latency beyond a few extra wakeups.
var networkTuning = []sysctlSetting{
	{"net.core.default_qdisc", "fq",
		"fair queueing: one busy download cannot hold back everyone's packets, and it paces BBR"},
	{"net.ipv4.tcp_congestion_control", "bbr",
		"paces by measured bandwidth and RTT instead of backing off at every lost packet"},
	{"net.ipv4.tcp_notsent_lowat", "16384",
		"keep at most 16 KiB queued unsent per socket: an interactive reply is not stuck behind megabytes of a download sharing the same connection (mux, anytls, h2)"},
	{"net.ipv4.tcp_slow_start_after_idle", "0",
		"a connection that paused keeps its speed instead of restarting slow - the next page or message over a kept-alive connection arrives at full rate"},
	{"net.ipv4.tcp_mtu_probing", "1",
		"when large packets silently vanish on the path (common behind tunnels), find a size that passes instead of letting the connection hang"},
}

const (
	networkSysctlFile = "/etc/sysctl.d/99-v2bx-network.conf"
	// Written by earlier versions with only the first two settings; replaced
	// by networkSysctlFile.
	legacyBBRSysctlFile = "/etc/sysctl.d/99-bbr.conf"
)

// renderSysctlConf is the content of networkSysctlFile.
func renderSysctlConf(settings []sysctlSetting) string {
	var b strings.Builder
	b.WriteString("# Written by `V2bX bbr`. Remove this file and reboot to undo.\n")
	for _, s := range settings {
		fmt.Fprintf(&b, "\n# %s\n%s=%s\n", s.why, s.key, s.value)
	}
	return b.String()
}

func bbrHandle(_ *cobra.Command, _ []string) {
	fmt.Println(Warn("Applying BBR + FQ and low-latency TCP settings | اعمال BBR + FQ و تنظیمات کم‌تأخیر TCP..."))

	// BBR may be a module. The kernel loads it on demand in most setups; this
	// only helps where it does not.
	_, _ = exec.RunCommandByShell("modprobe tcp_bbr 2>/dev/null")

	// One file, rewritten whole: running the command again changes nothing.
	if err := os.WriteFile(networkSysctlFile, []byte(renderSysctlConf(networkTuning)), 0644); err != nil {
		fmt.Println(Err("Could not write ", networkSysctlFile, ": ", err))
		return
	}
	_ = os.Remove(legacyBBRSysctlFile)
	if _, err := exec.RunCommandByShell("sysctl -p " + networkSysctlFile); err != nil {
		// Keep going: the report below shows which settings took.
		fmt.Println(Warn("sysctl reported an error; checking each setting | خطا در sysctl؛ بررسی تک‌تک تنظیمات"))
	}

	failed := 0
	for _, s := range networkTuning {
		out, _ := exec.RunCommandByShell("sysctl -n " + s.key + " 2>/dev/null")
		got := strings.TrimSpace(out)
		if got == s.value {
			fmt.Printf("  %s%-36s = %s%s\n", green, s.key, got, plain)
		} else {
			failed++
			if got == "" {
				got = "not available on this kernel"
			}
			fmt.Printf("  %s%-36s = %s (wanted %s)%s\n", red, s.key, got, s.value, plain)
		}
	}
	if failed > 0 {
		fmt.Println(Warn(fmt.Sprintf("Saved to %s, but %d setting(s) did not apply now; an old kernel or a container can refuse them | ذخیره شد، اما %d تنظیم اکنون اعمال نشد",
			networkSysctlFile, failed, failed)))
		return
	}
	fmt.Println(Ok("Applied and saved to " + networkSysctlFile + " | اعمال و ذخیره شد"))
}
