package cmd

import (
	"fmt"
	"os"

	"github.com/PoriyaVali/V2bX/common/exec"
	"github.com/spf13/cobra"
)

const configPath = "/etc/V2bX/config.json"

var configCommand = cobra.Command{
	Use:   "config",
	Short: "Show or edit V2bX config",
	Run: func(_ *cobra.Command, _ []string) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Println(Err("Cannot read config | خواندن config ناموفق بود: ", err))
			fmt.Printf("  Expected at: %s%s%s\n", yellow, configPath, plain)
			return
		}
		fmt.Println(string(data))
	},
}

var configEditCommand = cobra.Command{
	Use:   "edit",
	Short: "Edit config with nano",
	Run: func(_ *cobra.Command, _ []string) {
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Println(Err("Config not found | فایل config یافت نشد: ", configPath))
			return
		}
		exec.RunCommandStd("nano", configPath)
	},
}

func init() {
	configCommand.AddCommand(&configEditCommand)
	command.AddCommand(&configCommand)
}
