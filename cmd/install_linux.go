package cmd

import (
	"fmt"
	"os"
	osexec "os/exec"
	"strings"

	"github.com/PoriyaVali/V2bX/common/exec"
	"github.com/spf13/cobra"
)

var targetVersion string

var (
	updateCommand = cobra.Command{
		Use:   "update [version]",
		Short: "Update or downgrade V2bX to latest (or specified) version",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fmt.Printf("Current version | نسخه فعلی: %s%s%s\n", yellow, version, plain)
			target := targetVersion
			if len(args) > 0 {
				target = args[0]
			}
			if target != "" {
				fmt.Printf("Target version  | نسخه هدف: %s%s%s\n", yellow, target, plain)
			} else {
				fmt.Println(Warn("Fetching latest version | دریافت آخرین نسخه..."))
			}
			// Stream the installer output live to the terminal so the user
			// can see download/build progress instead of a silent update.
			return updateInstallerCommand(target).Run()
		},
	}
	uninstallCommand = cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall V2bX",
		Run:   uninstallHandle,
	}
	menuCommand = cobra.Command{
		Use:   "menu",
		Short: "Open the interactive management menu | باز کردن منوی مدیریت",
		Run: func(_ *cobra.Command, _ []string) {
			script := "bash <(curl -Ls https://raw.githubusercontent.com/PoriyaVali/V2bX/dev_new/install.sh)"
			exec.RunCommandStd("bash", "-c", script)
		},
	}
)

func updateInstallerCommand(target string) *osexec.Cmd {
	// Fetch successfully before running Bash. Process substitution can turn a
	// failed curl into an empty script that exits zero. Pass the requested tag
	// as a positional argument, so shell metacharacters cannot become commands.
	const script = `installer=$(curl -fLsS --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/PoriyaVali/V2bX/dev_new/install.sh) || exit "$?"
[[ -n "$installer" ]] || { echo "Empty installer | اسکریپت نصب خالی است" >&2; exit 1; }
bash -s -- update "$1" <<< "$installer"`
	process := osexec.Command("bash", "-c", script, "v2bx-update", target)
	process.Stdin = os.Stdin
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
	return process
}

func init() {
	updateCommand.PersistentFlags().StringVar(&targetVersion, "version", "", "update target version")
	command.AddCommand(&updateCommand)
	command.AddCommand(&uninstallCommand)
	command.AddCommand(&menuCommand)
}

func uninstallHandle(_ *cobra.Command, _ []string) {
	var yes string
	fmt.Println(Warn("Are you sure you want to uninstall V2bX? | آیا مطمئنید که می‌خواهید V2bX را حذف کنید؟ (Y/n)"))
	fmt.Scan(&yes)
	if strings.ToLower(yes) != "y" {
		fmt.Println("Uninstall cancelled | حذف لغو شد")
		return
	}
	_, err := exec.RunCommandByShell("systemctl stop V2bX&&systemctl disable V2bX")
	if err != nil {
		fmt.Println(Err("exec cmd error: ", err))
		fmt.Println(Err("Uninstall failed | حذف ناموفق بود"))
		return
	}
	_ = os.RemoveAll("/etc/systemd/system/V2bX.service")
	_ = os.RemoveAll("/etc/V2bX/")
	_ = os.RemoveAll("/usr/local/V2bX/")
	_ = os.RemoveAll("/bin/V2bX")
	_, err = exec.RunCommandByShell("systemctl daemon-reload&&systemctl reset-failed")
	if err != nil {
		fmt.Println(Err("exec cmd error: ", err))
		fmt.Println(Err("Uninstall failed | حذف ناموفق بود"))
		return
	}
	fmt.Println(Ok("V2bX uninstalled successfully | V2bX با موفقیت حذف شد"))
}
