package mihomo

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
	mlog "github.com/metacubex/mihomo/log"
	log "github.com/sirupsen/logrus"
)

// refusedError is a client the node turned away before dialing: an identity
// it does not serve, or a user over a limit.
type refusedError struct {
	uid    int // 0 for an identity the node does not know
	reason string
}

func (e refusedError) Error() string { return e.reason }

// blockedError is a destination a panel rule or the node's policy refuses.
type blockedError struct{ reason string }

func (e blockedError) Error() string { return e.reason }

// connLogged reports whether the Mihomo core's Log.Level lets a connection
// line of level through. Lines about connections follow the core's level, as
// the other cores' access logs do; lines about the node itself (a listener
// that opens or closes) follow V2bX's own level.
func connLogged(level mlog.LogLevel) bool {
	threshold := mlog.LogLevel(forwardLevel.Load())
	return threshold != mlog.SILENT && level >= threshold
}

// connLogs caps the lines a refused or blocked client can produce: a device
// over its limit retries every few seconds, and each UDP packet of a refused
// flow would otherwise be a line of its own.
var connLogs = newBurstLimiter(time.Minute, 3)

// The node's log lines carry the panel's user id, never the user's name:
// on most protocols that name is a credential.
func (n *node) logEntry(uid int, source, network string) *log.Entry {
	fields := log.Fields{"tag": n.tag, "core": "mihomo", "network": network, "from": source}
	if uid > 0 {
		fields["uid"] = uid
	}
	return log.WithFields(fields)
}

// logAdmission reports why a client was not let in. A closed or reloading
// node is not news: its listener is going away.
func (n *node) logAdmission(e error, source, network string) {
	var refused refusedError
	if !errors.As(e, &refused) || !connLogged(mlog.INFO) {
		return
	}
	key := n.tag + "|refused|" + strconv.Itoa(refused.uid) + "|" + refused.reason
	if suppressed, ok := connLogs.allow(key, time.Now()); ok {
		entry := n.logEntry(refused.uid, source, network)
		if suppressed > 0 {
			entry = entry.WithField("suppressed", suppressed)
		}
		entry.Info("Refused: ", refused.reason)
	}
}

// logDestination reports a request that never reached its destination: at
// info when a rule blocked it, at debug when the network failed it.
func (n *node) logDestination(e error, uid int, source, network string, m *C.Metadata) {
	target := m.RemoteAddress()
	var blocked blockedError
	if !errors.As(e, &blocked) {
		if connLogged(mlog.DEBUG) {
			n.logEntry(uid, source, network).WithField("to", target).Debug("Connect failed: ", e)
		}
		return
	}
	if !connLogged(mlog.INFO) {
		return
	}
	key := n.tag + "|blocked|" + strconv.Itoa(uid) + "|" + target
	if suppressed, ok := connLogs.allow(key, time.Now()); ok {
		entry := n.logEntry(uid, source, network).WithField("to", target)
		if suppressed > 0 {
			entry = entry.WithField("suppressed", suppressed)
		}
		entry.Info("Blocked: ", blocked.reason)
	}
}

func (n *node) logAccepted(uid int, source, network string, m *C.Metadata) {
	if connLogged(mlog.DEBUG) && log.IsLevelEnabled(log.DebugLevel) {
		n.logEntry(uid, source, network).WithField("to", m.RemoteAddress()).Debug("Accepted")
	}
}

func deviceLimitReason(limit int64) string {
	return fmt.Sprintf("device limit (%d) reached", limit)
}
