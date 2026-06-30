package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/PoriyaVali/V2bX/common/exec"
	"github.com/spf13/cobra"
)

var targetVersion string

var (
	updateCommand = cobra.Command{
		Use:   "update",
		Short: "Update V2bX version",
		Run: func(_ *cobra.Command, _ []string) {
			script := "bash <(curl -Ls https://raw.githubusercontent.com/PoriyaVali/V2bX/dev_new/install.sh) update"
			if targetVersion != "" {
				script += " " + targetVersion
			}
			_, err := exec.RunCommandByShell(script)
			if err != nil {
				fmt.Println(Err("Update failed | به‌روزرسانی ناموفق بود: ", err))
			}
		},
		Args: cobra.NoArgs,
	}
	uninstallCommand = cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall V2bX",
		Run:   uninstallHandle,
	}
)

func init() {
	updateCommand.PersistentFlags().StringVar(&targetVersion, "version", "", "update target version")
	command.AddCommand(&updateCommand)
	command.AddCommand(&uninstallCommand)
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
