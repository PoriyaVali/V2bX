package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/PoriyaVali/V2bX/common/memguard"
	"github.com/PoriyaVali/V2bX/common/metrics"
	"github.com/PoriyaVali/V2bX/conf"
	vCore "github.com/PoriyaVali/V2bX/core"
	"github.com/PoriyaVali/V2bX/limiter"
	"github.com/PoriyaVali/V2bX/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	config string
	watch  bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run V2bX server",
	// RunE, not Run: a start that fails must end the process with a non-zero
	// status. With Run the error was only logged and the process exited 0, and
	// the systemd unit restarts on FAILURE only - so a node that booted while the
	// panel was unreachable simply stayed down until someone noticed.
	RunE: serverHandle,
	Args: cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/V2bX/config.json", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) error {
	showVersion()
	c := conf.New()
	if err := c.LoadFromPath(config); err != nil {
		return fmt.Errorf("load config file: %w", err)
	}
	switch c.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if c.LogConfig.Output != "" {
		f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			// Keep stdout. Handing logrus the nil *os.File from a failed open
			// silently discarded every log line from then on.
			log.WithField("err", err).Error("Open log file failed, using stdout instead")
		} else {
			log.SetOutput(f)
		}
	}
	// Before anything allocates much: the soft limit steers the collector from
	// the first connection on.
	memguard.Start(c.MemoryConfig.LimitPercent)
	limiter.Init()
	log.Info("Start V2bX...")
	vc, err := vCore.NewCore(c.CoresConfig)
	if err != nil {
		return fmt.Errorf("new core: %w", err)
	}
	if err = vc.Start(); err != nil {
		return fmt.Errorf("start core: %w", err)
	}
	// A closure, not `defer vc.Close()`: that form binds the core that exists
	// right now, so after a reload the process would close the old one on exit
	// and leave the running one open.
	defer func() { _ = vc.Close() }()
	log.Info("Core ", vc.Type(), " started")
	nodes := node.New()
	if err = nodes.Start(c.NodeConfig, vc); err != nil {
		return fmt.Errorf("run nodes: %w", err)
	}
	log.Info("Nodes started")
	metrics.Start(c.MetricsConfig.Listen)
	xdns := os.Getenv("XRAY_DNS_PATH")
	sdns := os.Getenv("SING_DNS_PATH")
	if watch {
		err = c.Watch(config, xdns, sdns, func() {
			// Everything below runs after the old nodes and core are gone, so a
			// failure here would leave the process alive and serving nobody -
			// and systemd, seeing it alive, would never step in. Exit instead:
			// the unit restarts on failure and starts from the file again.
			nodes.Close()
			if err := vc.Close(); err != nil {
				log.WithField("err", err).Error("Close core before reload failed")
			}
			newCore, err := vCore.NewCore(c.CoresConfig)
			if err != nil {
				log.WithField("err", err).Error("New core failed during reload; exiting so the service restarts")
				os.Exit(1)
			}
			if err = newCore.Start(); err != nil {
				log.WithField("err", err).Error("Start core failed during reload; exiting so the service restarts")
				os.Exit(1)
			}
			vc = newCore
			log.Info("Core ", vc.Type(), " restarted")
			if err = nodes.Start(c.NodeConfig, vc); err != nil {
				log.WithField("err", err).Error("Run nodes failed during reload; exiting so the service restarts")
				os.Exit(1)
			}
			log.Info("Nodes restarted")
			runtime.GC()
		})
		if err != nil {
			return fmt.Errorf("start watch: %w", err)
		}
	}
	// clear memory
	runtime.GC()
	// wait exit signal
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)
	<-osSignals
	nodes.Close()
	return nil
}
