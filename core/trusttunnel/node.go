package trusttunnel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
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
)

// Restart backoff. A node that cannot start - a taken port, a certificate it
// cannot read - would otherwise be relaunched in a tight loop and bury the
// reason in log noise. Variables so tests can shorten them.
var (
	restartMinDelay = 2 * time.Second
	restartMaxDelay = 60 * time.Second
	// A run at least this long counts as healthy and earns the short delay
	// back; anything shorter is a crash loop and keeps backing off.
	stableUptime = time.Minute
)

const (
	// How long to wait for a freshly started endpoint to answer before giving
	// up on signalling it. Generous: being slow here costs nothing.
	readyTimeout      = 30 * time.Second
	readyPollInterval = 250 * time.Millisecond
)

// node is one endpoint process and the state needed to talk to it.
type node struct {
	tag         string
	dir         string
	metricsPort int
	// A poll reuses its bounded loopback transport instead of abandoning a
	// new keep-alive connection and its goroutines on every metrics request.
	metricsOnce   sync.Once
	metricsClient *http.Client
	// Serialize the snapshot and replacement together. Concurrent syncs must
	// not truncate the same temporary file or overwrite a newer user list.
	credentialsMu sync.Mutex

	mu      sync.Mutex
	cmd     *exec.Cmd
	users   map[string]string // uuid -> password
	closing bool
	done    chan struct{}
	stop    chan struct{} // closed by shutdown; wakes a restart that is waiting
	started time.Time     // when the current process was launched
	// Set once the endpoint answers on its metrics port. Until then it may not
	// have installed its SIGHUP handler yet, and the default disposition for
	// that signal is to terminate - so a reload sent too early kills the
	// process we just started.
	ready bool
	// A user sync can arrive after startup read the credentials but before
	// SIGHUP is safe. Keep it pending until this exact process is ready.
	pendingReload bool
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

func (t *TrustTunnel) AddNode(tag string, info *panel.NodeInfo, opts *conf.Options) error {
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

	if err := t.generateConfig(dir, p, metricsPort, opts); err != nil {
		return fmt.Errorf("trusttunnel: configure %s: %w", tag, err)
	}
	certificates, err := t.newCertificateLifecycle(dir, p)
	if err != nil {
		return fmt.Errorf("trusttunnel: certificate lifecycle %s: %w", tag, err)
	}

	n := &node{
		tag:         tag,
		dir:         dir,
		metricsPort: metricsPort,
		users:       make(map[string]string),
		done:        make(chan struct{}),
		stop:        make(chan struct{}),
	}
	if err := n.start(t.binPath(endpointBin)); err != nil {
		return fmt.Errorf("trusttunnel: start %s: %w", tag, err)
	}
	go n.supervise(t.binPath(endpointBin))
	go certificates.run(n.stop, n.applyCertificateUpdate)

	t.mu.Lock()
	t.nodes[tag] = n
	t.mu.Unlock()
	return nil
}

func (t *TrustTunnel) DelNode(tag string) error {
	t.mu.Lock()
	n, ok := t.nodes[tag]
	delete(t.nodes, tag)
	delete(t.usersMap, tag)
	t.mu.Unlock()

	if ok {
		n.shutdown()
		log.WithField("tag", tag).Info("trusttunnel: node removed")
	}
	return nil
}

// setTopLevel sets a top-level key of vpn.toml - one written before the first
// [table] - to value, adding it there if the wizard did not write it.
//
// ipv6_available is the one set this way. The wizard always writes true, while
// the panel tells subscribers whether the host has IPv6 at all: on a host
// without it the endpoint accepted IPv6 destinations it could not reach, and
// those connections hung until they timed out.
func setTopLevel(path, key, value string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read vpn.toml: %w", err)
	}
	lines := strings.Split(string(raw), "\n")
	firstTable := len(lines)
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			firstTable = i
			break
		}
	}
	entry := key + " = " + value
	set := false
	for i := 0; i < firstTable; i++ {
		k, _, ok := strings.Cut(lines[i], "=")
		if ok && strings.TrimSpace(k) == key {
			lines[i] = entry
			set = true
		}
	}
	if !set {
		lines = append(lines[:firstTable], append([]string{entry, ""}, lines[firstTable:]...)...)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
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
	// Keep credential replacement and launch ordered with user syncs. This
	// also discards stale users from a previous process before restart.
	n.credentialsMu.Lock()
	defer n.credentialsMu.Unlock()
	if err := n.writeCredentialsLocked(); err != nil {
		return err
	}
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
	// Checked and launched under the lock, so a shutdown can never slip in
	// between: a process started after it would be signalled by nobody and
	// keep the node's port until someone killed it by hand.
	n.mu.Lock()
	if n.closing {
		n.mu.Unlock()
		stdout.Close()
		stderr.Close()
		return errClosing
	}
	if err := cmd.Start(); err != nil {
		n.mu.Unlock()
		return err
	}
	n.cmd = cmd
	n.ready = false
	n.pendingReload = false // the startup file already holds the latest snapshot
	n.started = time.Now()
	n.mu.Unlock()
	// Both pipes are drained until the process closes them, so a restart does
	// not leak these goroutines.
	n.logs.Add(2)
	go func() { defer n.logs.Done(); pipeToLog(stdout, n.tag, false) }()
	go func() { defer n.logs.Done(); pipeToLog(stderr, n.tag, true) }()
	go n.waitReady(cmd)

	log.WithField("tag", n.tag).Infof("trusttunnel: endpoint started (pid %d)", cmd.Process.Pid)
	return nil
}

// waitReady marks the endpoint reloadable once its metrics port answers.
//
// Readiness belongs to one process. A previous process's slow HTTP response
// must never make its replacement reloadable before it installs SIGHUP.
func (n *node) waitReady(cmd *exec.Cmd) {
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		n.mu.Lock()
		closing := n.closing || n.cmd != cmd
		n.mu.Unlock()
		if closing {
			return
		}
		if _, err := n.drain(false); err == nil {
			if err := n.finishReadiness(cmd, func() error { return cmd.Process.Signal(syscall.SIGHUP) }); err != nil {
				log.WithField("tag", n.tag).Errorf("trusttunnel: replay startup user sync: %v", err)
			}
			return
		}
		time.Sleep(readyPollInterval)
	}
	log.WithField("tag", n.tag).Warn("trusttunnel: endpoint did not answer on its metrics port; user changes will apply on its next start")
}

// finishReadiness serializes the deferred signal with file replacement. A
// callback keeps the state transition testable on hosts without POSIX signals.
func (n *node) finishReadiness(cmd *exec.Cmd, signal func() error) error {
	n.credentialsMu.Lock()
	defer n.credentialsMu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing || n.cmd != cmd {
		return nil
	}
	n.ready = true
	if n.pendingReload {
		if err := signal(); err != nil {
			return err // leave the pending state intact on signal failure
		}
		n.pendingReload = false
	}
	return nil
}

// applyCertificateUpdate commits only a prepared local snapshot. Network and
// ACME work happen outside these locks, so shutdown and user sync remain fast.
// An obsolete lifecycle can never publish into a replacement node's files.
func (n *node) applyCertificateUpdate(commit func() error) error {
	n.credentialsMu.Lock()
	defer n.credentialsMu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing {
		return errClosing
	}
	if err := commit(); err != nil {
		return err
	}
	n.pendingReload = true
	if n.cmd == nil || n.cmd.Process == nil || !n.ready {
		return nil
	}
	if err := n.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return err
	}
	n.pendingReload = false
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
		ranFor := time.Since(n.started)
		if n.cmd == cmd {
			n.cmd = nil
			n.ready = false
		}
		n.mu.Unlock()
		if closing {
			return
		}

		// A process that stayed up gets the short delay back, so one bad night
		// does not leave a healthy node waiting a minute after every blip. This
		// used to reset right after every restart, before knowing whether the
		// new process lived - so a crash loop never backed off at all.
		if ranFor >= stableUptime {
			delay = restartMinDelay
		}
		log.WithField("tag", n.tag).Warnf("trusttunnel: endpoint exited after %s (%v), restarting in %s",
			ranFor.Round(time.Second), err, delay)
		// Interruptible: the node may be removed while this waits. A plain
		// sleep used to be followed by a start regardless, leaving an orphan
		// endpoint on the node's port.
		for {
			select {
			case <-time.After(delay):
			case <-n.stop:
				return
			}
			if delay *= 2; delay > restartMaxDelay {
				delay = restartMaxDelay
			}
			err := n.start(bin)
			if err == nil {
				break
			}
			if errors.Is(err, errClosing) {
				return
			}
			log.WithField("tag", n.tag).Errorf("trusttunnel: restart failed, next try in %s: %v", delay, err)
		}
	}
}

// errClosing is what start returns once the node is being shut down.
var errClosing = errors.New("trusttunnel: node is shutting down")

func (n *node) shutdown() {
	n.mu.Lock()
	if !n.closing {
		n.closing = true
		close(n.stop)
	}
	cmd := n.cmd
	n.mu.Unlock()
	n.metricsHTTPClient().CloseIdleConnections()

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
