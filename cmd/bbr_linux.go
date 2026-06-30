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
	Short: "Enable BBR + FQ congestion control",
	Run:   bbrHandle,
}

func init() {
	command.AddCommand(&bbrCommand)
}

func bbrHandle(_ *cobra.Command, _ []string) {
	// Check if already enabled
	out, _ := exec.RunCommandByShell("sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null")
	if strings.TrimSpace(out) == "bbr" {
		qdiscOut, _ := exec.RunCommandByShell("sysctl -n net.core.default_qdisc 2>/dev/null")
		fmt.Println(Ok("BBR is already enabled | BBR قبلاً فعال است"))
		fmt.Printf("  congestion_control = %sbbr%s\n", green, plain)
		fmt.Printf("  default_qdisc      = %s%s%s\n", green, strings.TrimSpace(qdiscOut), plain)
		return
	}

	fmt.Println(Warn("Enabling BBR + FQ | فعال‌سازی BBR + FQ..."))

	// Load module if not loaded
	modOut, _ := exec.RunCommandByShell("lsmod 2>/dev/null | grep tcp_bbr")
	if modOut == "" {
		_, err := exec.RunCommandByShell("modprobe tcp_bbr 2>/dev/null")
		if err != nil {
			fmt.Println(Warn("tcp_bbr module not found, may be built-in | ماژول tcp_bbr ممکن است داخلی باشد"))
		}
	}

	// Apply sysctl
	_, err1 := exec.RunCommandByShell("sysctl -w net.core.default_qdisc=fq")
	_, err2 := exec.RunCommandByShell("sysctl -w net.ipv4.tcp_congestion_control=bbr")
	if err1 != nil || err2 != nil {
		fmt.Println(Err("Failed to apply sysctl settings | اعمال تنظیمات ناموفق بود"))
		return
	}

	// Persist across reboots
	conf := "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"
	if err := os.WriteFile("/etc/sysctl.d/99-bbr.conf", []byte(conf), 0644); err != nil {
		fmt.Println(Warn("Could not persist settings to sysctl.d | ذخیره دائمی ناموفق بود"))
	} else {
		fmt.Println(Ok("Settings persisted to /etc/sysctl.d/99-bbr.conf"))
	}

	// Verify
	ccOut, _ := exec.RunCommandByShell("sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null")
	qdOut, _ := exec.RunCommandByShell("sysctl -n net.core.default_qdisc 2>/dev/null")
	fmt.Println(Ok("\nBBR + FQ enabled successfully | BBR + FQ با موفقیت فعال شد"))
	fmt.Printf("  congestion_control = %s%s%s\n", green, strings.TrimSpace(ccOut), plain)
	fmt.Printf("  default_qdisc      = %s%s%s\n", green, strings.TrimSpace(qdOut), plain)
}
