package node

import (
	"encoding/json"
	"fmt"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	log "github.com/sirupsen/logrus"
)

// filteringAdvice is one thing about a node's setup that is known to fail
// against Iranian filtering. It is only logged: whether to change the node is
// the operator's call, and some nodes exist for users elsewhere.
type filteringAdvice struct {
	// fatal: users on affected networks are expected not to get through at
	// all; otherwise a note worth knowing.
	fatal bool
	msg   string
}

// whitelistedTCPPorts are the ports Iran's protocol whitelister guards: it
// lets a TCP connection to them live only if its first data packets look like
// DNS, HTTP or TLS, and silently drops everything else (Bock et al., FOCI
// 2020; the same behaviour was measured during the 2025 shutdown, arXiv
// 2507.14183).
var whitelistedTCPPorts = map[int]bool{53: true, 80: true, 443: true}

// filteringAdviceFor checks a node against the filtering techniques reported
// for Iranian networks (docs/censorship-countermeasures.md).
func filteringAdviceFor(node *panel.NodeInfo, opts *conf.Options) []filteringAdvice {
	if node == nil || node.Common == nil {
		return nil
	}
	var out []filteringAdvice
	port := node.Common.ServerPort

	if whitelistedTCPPorts[port] && !looksLikeWhitelistedProtocol(node) {
		out = append(out, filteringAdvice{fatal: true, msg: fmt.Sprintf(
			"%s on TCP port %d: Iranian networks let a connection to ports 53, 80 and 443 live only if its "+
				"first packets look like DNS, HTTP or TLS, and this node's do not. Users there will be cut off; "+
				"use another port, or TLS/REALITY", node.Type, port)})
	}

	if port == 80 && node.Security == panel.None && plaintextWebSocket(node) {
		out = append(out, filteringAdvice{fatal: true, msg: "WebSocket over plain HTTP on port 80: Iranian " +
			"networks have been seen filtering it (net4people/bbs#489). Use TLS, or the xhttp transport"})
	}

	if node.Security == panel.Tls && opts != nil && opts.CertConfig != nil && opts.CertConfig.CertMode == "self" {
		out = append(out, filteringAdvice{fatal: false, msg: "self-signed certificate: an active prober that " +
			"completes the TLS handshake sees a certificate no public site uses, which marks the address. " +
			"Use CertMode http, dns or file"})
	}

	switch node.Type {
	case "hysteria", "hysteria2", "tuic":
		out = append(out, filteringAdvice{fatal: false, msg: node.Type + " runs over UDP/QUIC, which most " +
			"Iranian networks have blocked or throttled since mid-2025 (net4people/bbs#489, #626). Keep a TCP " +
			"node (REALITY or anytls) for the users there"})
	}
	return out
}

// looksLikeWhitelistedProtocol reports whether a node's first packets are TLS,
// HTTP or DNS - what the whitelister lets through.
func looksLikeWhitelistedProtocol(node *panel.NodeInfo) bool {
	switch node.Type {
	case "shadowsocks":
		return false // random bytes from the first one
	case "vmess", "vless":
		if node.Security != panel.None || node.VAllss == nil {
			return true // TLS or REALITY: a ClientHello
		}
		if node.VAllss.Network != "tcp" {
			return true // ws, grpc, httpupgrade, xhttp: HTTP requests
		}
		return tcpHTTPHeader(node.VAllss.NetworkSettings)
	case "mdns":
		return true // a DNS tunnel; and UDP, which the whitelister does not judge
	}
	// trojan, anytls, trusttunnel: TLS. hysteria/hysteria2/tuic: UDP.
	return true
}

// tcpHTTPHeader reports whether raw TCP settings dress the stream as HTTP.
func tcpHTTPHeader(raw json.RawMessage) bool {
	var s struct {
		Header struct {
			Type string `json:"type"`
		} `json:"header"`
	}
	return len(raw) > 0 && json.Unmarshal(raw, &s) == nil && s.Header.Type == "http"
}

func plaintextWebSocket(node *panel.NodeInfo) bool {
	switch {
	case node.VAllss != nil:
		return node.VAllss.Network == "ws" || node.VAllss.Network == "httpupgrade"
	case node.Trojan != nil:
		return node.Trojan.Network == "ws"
	}
	return false
}

// logFilteringAdvice writes a node's advice to the log once per start or
// reload, and starts the background check of a REALITY node's target.
func logFilteringAdvice(tag string, node *panel.NodeInfo, opts *conf.Options) {
	for _, a := range filteringAdviceFor(node, opts) {
		entry := log.WithField("tag", tag)
		if a.fatal {
			entry.Warn(a.msg)
		} else {
			entry.Info(a.msg)
		}
	}
	checkRealityTarget(tag, node)
}
