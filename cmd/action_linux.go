package cmd

import (
	"fmt"
	"time"

	"github.com/PoriyaVali/V2bX/common/exec"
	"github.com/spf13/cobra"
)

var (
	startCommand = cobra.Command{
		Use:   "start",
		Short: "Start V2bX service",
		Run:   startHandle,
	}
	stopCommand = cobra.Command{
		Use:   "stop",
		Short: "Stop V2bX service",
		Run:   stopHandle,
	}
	restartCommand = cobra.Command{
		Use:   "restart",
		Short: "Restart V2bX service",
		Run:   restartHandle,
	}
	logCommand = cobra.Command{
		Use:   "log",
		Short: "Output V2bX log",
		Run: func(_ *cobra.Command, _ []string) {
			exec.RunCommandStd("journalctl", "-u", "V2bX.service", "-e", "--no-pager", "-f")
		},
	}
)

func init() {
	command.AddCommand(&startCommand)
	command.AddCommand(&stopCommand)
	command.AddCommand(&restartCommand)
	command.AddCommand(&logCommand)
}

func startHandle(_ *cobra.Command, _ []string) {
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err("V2bX start failed | راه‌اندازی V2bX ناموفق بود"))
		return
	}
	if r {
		fmt.Println(Ok("V2bX is already running. Use 'V2bX restart' to restart. | V2bX در حال اجرا است، برای راه‌اندازی مجدد از restart استفاده کنید"))
	}
	_, err = exec.RunCommandByShell("systemctl start V2bX.service")
	if err != nil {
		fmt.Println(Err("exec start cmd error: ", err))
		fmt.Println(Err("V2bX start failed | راه‌اندازی V2bX ناموفق بود"))
		return
	}
	time.Sleep(time.Second * 3)
	r, err = checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err("V2bX start failed | راه‌اندازی V2bX ناموفق بود"))
	}
	if !r {
		fmt.Println(Err("V2bX may have failed to start. Check logs with: V2bX log | V2bX ممکن است راه‌اندازی نشده باشد، لاگ را بررسی کنید: V2bX log"))
		return
	}
	fmt.Println(Ok("V2bX started successfully. Use 'V2bX log' to view logs. | V2bX با موفقیت راه‌اندازی شد"))
}

func stopHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl stop V2bX.service")
	if err != nil {
		fmt.Println(Err("exec stop cmd error: ", err))
		fmt.Println(Err("V2bX stop failed | توقف V2bX ناموفق بود"))
		return
	}
	time.Sleep(2 * time.Second)
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error:", err))
		fmt.Println(Err("V2bX stop failed | توقف V2bX ناموفق بود"))
		return
	}
	if r {
		fmt.Println(Err("V2bX stop failed, may have exceeded timeout. Check logs later. | توقف V2bX ناموفق بود، لاگ را بررسی کنید"))
		return
	}
	fmt.Println(Ok("V2bX stopped successfully | V2bX با موفقیت متوقف شد"))
}

func restartHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl restart V2bX.service")
	if err != nil {
		fmt.Println(Err("exec restart cmd error: ", err))
		fmt.Println(Err("V2bX restart failed | راه‌اندازی مجدد V2bX ناموفق بود"))
		return
	}
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err("V2bX restart failed | راه‌اندازی مجدد V2bX ناموفق بود"))
		return
	}
	if !r {
		fmt.Println(Err("V2bX may have failed to start. Check logs with: V2bX log | V2bX ممکن است راه‌اندازی نشده باشد، لاگ را بررسی کنید: V2bX log"))
		return
	}
	fmt.Println(Ok("V2bX restarted successfully | V2bX با موفقیت مجدداً راه‌اندازی شد"))
}
