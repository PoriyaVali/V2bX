package trusttunnel

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	log "github.com/sirupsen/logrus"
)

const (
	endpointBin = "trusttunnel_endpoint"
	wizardBin   = "setup_wizard"

	// Restart backoff. A node that cannot start - a taken port, a certificate
	// it cannot read - would otherwise be relaunched in a tight loop and bury
	// the reason in log noise.
	restartMinDelay = 2 * time.Second
	restartMaxDelay = 60 * time.Second
)

// node is one endpoint process and the state needed to talk to it.
type node struct {
	tag         string
	dir         string
	metricsPort int

	mu      sync.Mutex
	cmd     *exec.Cmd
	users   map[string]string // uuid -> password
	closing bool
	done    chan struct{}
	// exec.Cmd's own docs: it is incorrect to call Wait before the reads from
	// StdoutPipe/StderrPipe have finished, because Wait closes them. Without
	// this the tail of a dying endpoint's output - the part explaining why -
	// is the part most likely to be lost.
	logs sync.WaitGroup
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func (t *TrustTunnel) binPath(name string) string {
	return filepath.Join(t.binDir, name)
}

func (t *TrustTunnel) AddNode(tag string, info *panel.NodeInfo, _ *conf.Options) error {
	if info.TrustTunnel == nil {
		return fmt.Errorf("trusttunnel: node %s has no trusttunnel params", tag)
	}
	p := info.TrustTunnel

	dir := filepath.Join(t.workDir, sanitizeTag(tag))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("trusttunnel: create dir for %s: %w", tag, err)
	}

	// Every endpoint gets its own metrics port: they all run on this host, and
	// two nodes sharing one would silently report each other's traffic.
	metricsPort, err := freePort()
	if err != nil {
		return fmt.Errorf("trusttunnel: pick metrics port for %s: %w", tag, err)
	}

	if err := t.generateConfig(dir, p, metricsPort); err != nil {
		return fmt.Errorf("trusttunnel: configure %s: %w", tag, err)
	}

	n := &node{
		tag:         tag,
		dir:         dir,
		metricsPort: metricsPort,
		users:       make(map[string]string),
		done:        make(chan struct{}),
	}
	if err := n.start(t.binPath(endpointBin)); err != nil {
		return fmt.Errorf("trusttunnel: start %s: %w", tag, err)
	}
	go n.supervise(t.binPath(endpointBin))

	t.mu.Lock()
	t.nodes[tag] = n
	t.mu.Unlock()
	return nil
}

func (t *TrustTunnel) DelNode(tag string) error {
	t.mu.Lock()
	n, ok := t.nodes[tag]
	delete(t.nodes, tag)
	t.mu.Unlock()

	if ok {
		n.shutdown()
		log.WithField("tag", tag).Info("trusttunnel: node removed")
	}
	return nil
}

// generateConfig runs the wizard that ships with the endpoint instead of
// writing TOML here, so the files always match the binary's own expectations.
//
// The wizard needs at least one credential to write a credentials file at all;
// it is replaced wholesale by the first user sync, so the placeholder never
// authenticates anyone.
func (t *TrustTunnel) generateConfig(dir string, p *panel.TrustTunnelNode, metricsPort int) error {
	args := []string{
		"-m", "non-interactive",
		"-n", p.Hostname,
		"-a", fmt.Sprintf("0.0.0.0:%d", p.ServerPort),
		"-c", "placeholder:placeholder",
		"--lib-settings", "./vpn.toml",
		"--hosts-settings", "./hosts.toml",
	}
	switch p.CertType {
	case "letsencrypt":
		args = append(args, "--cert-type", "letsencrypt", "--acme-email", p.AcmeEmail)
	case "provided":
		args = append(args, "--cert-type", "provided",
			"--cert-chain-path", p.CertChainPath, "--cert-key-path", p.CertKeyPath)
	default:
		args = append(args, "--cert-type", "self-signed")
	}

	cmd := exec.Command(t.binPath(wizardBin), args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wizard failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return enableMetrics(filepath.Join(dir, "vpn.toml"), metricsPort)
}

// enableMetrics uncomments the [metrics] block the wizard writes commented out.
//
// Without it the endpoint never opens its metrics port, and this core has no
// way to read traffic - every subscriber would appear to use nothing at all,
// with the endpoint otherwise working perfectly.
func enableMetrics(path string, port int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read vpn.toml: %w", err)
	}

	lines := strings.Split(string(raw), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "# [metrics]":
			lines[i] = "[metrics]"
			found = true
		case strings.HasPrefix(trimmed, "# address = ") && found:
			lines[i] = fmt.Sprintf("address = \"127.0.0.1:%d\"", port)
		case strings.HasPrefix(trimmed, "# request_timeout_secs") && found:
			lines[i] = strings.TrimPrefix(trimmed, "# ")
		}
	}
	if !found {
		// Rather than guess where it went, append a block that is valid on its
		// own. A wizard that stops emitting the commented template should not
		// take traffic accounting down with it.
		lines = append(lines, "", "[metrics]",
			fmt.Sprintf("address = \"127.0.0.1:%d\"", port),
			"request_timeout_secs = 3", "")
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
}

// endpointLogLevel translates V2bX's own log level into the endpoint's.
//
// The endpoint is a separate process with its own verbosity, so leaving it at a
// fixed level would either flood an operator who asked for errors only, or hide
// detail from one who asked for debug. Following V2bX means one setting governs
// both.
func endpointLogLevel() string {
	switch log.GetLevel() {
	case log.TraceLevel, log.DebugLevel:
		return "debug"
	case log.InfoLevel:
		return "info"
	case log.WarnLevel:
		return "warn"
	default:
		return "error"
	}
}

// pipeToLog forwards one of the endpoint's streams into V2bX's log, a line at a
// time, tagged with the node it came from.
//
// The endpoint used to write to its own file beside its config, which meant two
// places to look and a file nothing rotated. Sending it here puts everything in
// the log the operator already reads, and makes it obey that log's rotation and
// destination.
func pipeToLog(r io.Reader, tag string, isErr bool) {
	sc := bufio.NewScanner(r)
	// A stack trace or a long request line would exceed the default 64 KiB and
	// silently end the scan, taking the rest of the node's output with it.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	entry := log.WithField("tag", tag)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		if isErr {
			entry.Warnf("trusttunnel: %s", line)
		} else {
			entry.Infof("trusttunnel: %s", line)
		}
	}
}

func (n *node) start(bin string) error {
	cmd := exec.Command(bin, "./vpn.toml", "./hosts.toml", "-l", endpointLogLevel())
	cmd.Dir = n.dir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Both pipes are drained until the process closes them, so a restart does
	// not leak these goroutines.
	n.logs.Add(2)
	go func() { defer n.logs.Done(); pipeToLog(stdout, n.tag, false) }()
	go func() { defer n.logs.Done(); pipeToLog(stderr, n.tag, true) }()

	n.mu.Lock()
	n.cmd = cmd
	n.mu.Unlock()

	log.WithField("tag", n.tag).Infof("trusttunnel: endpoint started (pid %d)", cmd.Process.Pid)
	return nil
}

// supervise restarts the endpoint if it exits on its own.
//
// No other core needs this: they are libraries, and a panic takes V2bX with
// them where an operator will see it. A child process that dies is invisible -
// the node would stay in the panel, accept no connections, and report no
// traffic, which looks identical to nobody using it.
func (n *node) supervise(bin string) {
	defer close(n.done)
	delay := restartMinDelay

	for {
		n.mu.Lock()
		cmd := n.cmd
		n.mu.Unlock()
		if cmd == nil {
			return
		}

		// Drain both streams first; Wait closes the pipes under the readers.
		n.logs.Wait()
		err := cmd.Wait()

		n.mu.Lock()
		closing := n.closing
		n.mu.Unlock()
		if closing {
			return
		}

		log.WithField("tag", n.tag).Warnf("trusttunnel: endpoint exited (%v), restarting in %s", err, delay)
		time.Sleep(delay)
		if delay *= 2; delay > restartMaxDelay {
			delay = restartMaxDelay
		}

		if err := n.start(bin); err != nil {
			log.WithField("tag", n.tag).Errorf("trusttunnel: restart failed: %v", err)
			continue
		}
		// A process that has stayed up long enough to be restarted cleanly gets
		// the short delay back, so one bad night does not leave a healthy node
		// waiting a minute after every blip.
		if err := n.writeCredentials(); err != nil {
			log.WithField("tag", n.tag).Errorf("trusttunnel: restore users after restart: %v", err)
		}
		delay = restartMinDelay
	}
}

func (n *node) shutdown() {
	n.mu.Lock()
	n.closing = true
	cmd := n.cmd
	n.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		// SIGTERM, which the endpoint handles by closing its listeners and
		// exiting - verified against a live endpoint, ports released cleanly.
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-n.done:
	case <-time.After(10 * time.Second):
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
}

func sanitizeTag(tag string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, tag)
}
