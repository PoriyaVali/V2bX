package cmd

import (
	"fmt"
	"os"

	"github.com/PoriyaVali/V2bX/conf"

	"github.com/spf13/cobra"
)

// check parses the config exactly as the server does and reports what it found.
//
// It exists because there was no way to ask this program whether a config it is
// about to run is valid, and scripts that edit config.json need one. Reading
// back the file you just wrote proves only that the write happened - a key put
// somewhere the parser never looks reads back perfectly and does nothing, which
// is how three releases once got built chasing an inert setting.
//
// Printing the parsed node list matters as much as the exit code: a config can
// be valid JSON, load without error, and still not contain the node you thought
// you added.
var checkCommand = cobra.Command{
	Use:   "check",
	Short: "Parse the config and report it | بررسی صحت فایل تنظیمات",
	Run: func(_ *cobra.Command, _ []string) {
		c := conf.New()
		if err := c.LoadFromPath(configPath); err != nil {
			fmt.Println(Err("Config is not valid | فایل تنظیمات معتبر نیست: ", err))
			os.Exit(1)
		}

		fmt.Printf("%sConfig parses | فایل تنظیمات سالم است%s\n", green, plain)
		fmt.Printf("  %s%-10s%s %d\n", yellow, "cores", plain, len(c.CoresConfig))
		for i := range c.CoresConfig {
			fmt.Printf("    - %s\n", c.CoresConfig[i].Type)
		}
		fmt.Printf("  %s%-10s%s %d\n", yellow, "nodes", plain, len(c.NodeConfig))
		for i := range c.NodeConfig {
			n := &c.NodeConfig[i]
			// ProxyProtocol is reported because it is the setting operators most
			// often believe they have set and have not - it can be written in two
			// places and only one of them survives.
			pp := "-"
			if n.Options.SingOptions != nil && n.Options.SingOptions.ProxyProtocol {
				pp = "ProxyProtocol"
			}
			fmt.Printf("    - id=%-4d type=%-12s core=%-6s %s\n",
				n.ApiConfig.NodeID, n.ApiConfig.NodeType, n.Options.Core, pp)
		}
		if len(c.NodeConfig) == 0 {
			fmt.Println(Warn("  No nodes configured | هیچ نودی تعریف نشده"))
		}
	},
}

func init() {
	command.AddCommand(&checkCommand)
}
