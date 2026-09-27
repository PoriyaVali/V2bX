package panel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	log "github.com/sirupsen/logrus"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	// Node-side thresholds pushed by the panel (0 = disabled/unset).
	// Units: kilobytes (multiplied by 1000 when compared to byte counters).
	NodeReportMinTraffic   int64
	DeviceOnlineMinTraffic int64
	RawDNS                 RawDNS
	Rules                  Rules
	// Only the xray core can apply these; see RouteRule.
	RouteRules []RouteRule

	// origin
	VAllss      *VAllssNode
	Shadowsocks *ShadowsocksNode
	Trojan      *TrojanNode
	Tuic        *TuicNode
	AnyTls      *AnyTlsNode
	Mdns        *MdnsNode
	TrustTunnel *TrustTunnelNode
	Hysteria    *HysteriaNode
	Hysteria2   *Hysteria2Node
	Common      *CommonNode
}

type CommonNode struct {
	Host       string      `json:"host"`
	ServerPort int         `json:"server_port"`
	ServerName string      `json:"server_name"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
}

type Route struct {
	Id          int         `json:"id"`
	Match       interface{} `json:"match"`
	Action      string      `json:"action"`
	ActionValue string      `json:"action_value"`
}
type BaseConfig struct {
	PushInterval           any `json:"push_interval"`
	PullInterval           any `json:"pull_interval"`
	NodeReportMinTraffic   any `json:"node_report_min_traffic"`
	DeviceOnlineMinTraffic any `json:"device_online_min_traffic"`
}

// VAllssNode is vmess and vless node info
type VAllssNode struct {
	CommonNode
	Tls                 int             `json:"tls"`
	TlsSettings         TlsSettings     `json:"tls_settings"`
	TlsSettingsBack     *TlsSettings    `json:"tlsSettings"`
	Network             string          `json:"network"`
	NetworkSettings     json.RawMessage `json:"network_settings"`
	NetworkSettingsBack json.RawMessage `json:"networkSettings"`
	Encryption          string          `json:"encryption"`
	EncryptionSettings  EncSettings     `json:"encryption_settings"`
	ServerName          string          `json:"server_name"`

	// vless only
	Flow          string        `json:"flow"`
	RealityConfig RealityConfig `json:"-"`
}

type TlsSettings struct {
	ServerName  string `json:"server_name"`
	Dest        string `json:"dest"`
	ServerPort  string `json:"server_port"`
	ShortId     string `json:"short_id"`
	PrivateKey  string `json:"private_key"`
	Mldsa65Seed string `json:"mldsa65Seed"`
	// Read by UnmarshalJSON, which takes it as a number or a string.
	Xver uint64 `json:"xver"`

	// Encrypted Client Hello. Ech is the panel's mode switch ("custom", or
	// empty for off) and EchKey is the server key. The panel stores it as bare
	// base64 while sing-box demands a PEM block of type "ECH KEYS", so it is
	// wrapped on the way into the inbound options - see core/sing/node.go.
	Ech    string `json:"ech"`
	EchKey string `json:"ech_key"`
}

// UnmarshalJSON takes xver and server_port as either a JSON number or a
// string.
//
// The panel's REALITY form saves its Proxy Protocol choice (0, 1, 2) as a
// number, while xver was declared ",string" and server_port as a string. So
// once an operator picked a Proxy Protocol value, the whole node config failed
// to decode ("cannot unmarshal number") and the vless or anytls node never
// came up, or stopped taking config changes.
func (t *TlsSettings) UnmarshalJSON(b []byte) error {
	type plain TlsSettings
	var raw struct {
		plain
		// Shallower than plain's fields of the same names, so these win.
		Xver       flexString `json:"xver"`
		ServerPort flexString `json:"server_port"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*t = TlsSettings(raw.plain)
	t.ServerPort = string(raw.ServerPort)
	t.Xver = 0
	if s := strings.TrimSpace(string(raw.Xver)); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return fmt.Errorf("tls_settings.xver: %q is not a whole number", s)
		}
		t.Xver = v
	}
	return nil
}

// flexString decodes a JSON string, number or null into its text.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) == 0 || string(b) == "null":
		*f = ""
		return nil
	case b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("want a number or a string, got %s", b)
	}
	*f = flexString(n.String())
	return nil
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Rtt           string `json:"rtt"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

// ServerDecryption is the VLESS "decryption" string for mlkem768x25519plus.
//
// The panel leaves mode and ticket empty unless the operator fills them in
// (it sets the ticket only for 1-RTT), and an empty part made xray reject the
// whole string, so the node never came up. They default to what subscribers
// are given for the same fields: "native" mode, and a ticket that matches the
// RTT - 0-RTT needs tickets to resume with, 1-RTT ("0s") issues none.
func (e EncSettings) ServerDecryption() string {
	mode := e.Mode
	if mode == "" {
		mode = "native"
	}
	ticket := e.Ticket
	if ticket == "" {
		ticket = "0s"
		if e.Rtt == "0rtt" {
			ticket = "600s"
		}
	}
	parts := []string{"mlkem768x25519plus", mode, ticket}
	if e.ServerPadding != "" {
		parts = append(parts, e.ServerPadding)
	}
	return strings.Join(append(parts, e.PrivateKey), ".")
}

type RealityConfig struct {
	Xver         uint64 `json:"Xver"`
	MinClientVer string `json:"MinClientVer"`
	MaxClientVer string `json:"MaxClientVer"`
	MaxTimeDiff  string `json:"MaxTimeDiff"`
}

type ShadowsocksNode struct {
	CommonNode
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
}

type TrojanNode struct {
	CommonNode
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
}

type TuicNode struct {
	CommonNode
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
}

type AnyTlsNode struct {
	CommonNode
	PaddingScheme []string `json:"padding_scheme,omitempty"`

	// Same two fields, and the same JSON names, the vless node already uses -
	// the panel serves them identically for both. Before this an anytls node
	// received nothing but server_port/server_name/padding_scheme, so it could
	// only ever serve plain TLS. A panel that has not been updated omits them
	// and Tls decodes as 0, which is treated as plain TLS below.
	Tls         int         `json:"tls"`
	TlsSettings TlsSettings `json:"tls_settings"`
}

// MdnsNode is a MasterDnsVPN (DNS-tunnel) node. server_port is the UDP
// listener; the rest are tunnel specifics the panel sends for this type.
type MdnsNode struct {
	CommonNode
	Domain           []string `json:"domain"`
	EncryptionMethod int      `json:"encryption_method"`
	EncryptionKey    string   `json:"encryption_key"`
	NodeSecret       string   `json:"node_secret"`
}

// TrustTunnelNode is an endpoint run as a separate process rather than inside
// V2bX, so what the panel sends here is what the setup wizard needs on its
// command line - not a config this core assembles itself.
type TrustTunnelNode struct {
	CommonNode
	// Certificate hostname the endpoint serves TLS for.
	Hostname string `json:"hostname"`
	// How the endpoint obtains its certificate: "self-signed", "letsencrypt"
	// or "provided". Each needs different things from the host - letsencrypt
	// wants port 80 reachable and an account email, provided wants the two
	// paths below - so the panel has to say which rather than a default being
	// guessed here.
	CertType string `json:"cert_type"`
	// Required when CertType is "letsencrypt".
	AcmeEmail string `json:"acme_email"`
	// Required when CertType is "provided".
	CertChainPath string `json:"cert_chain_path"`
	CertKeyPath   string `json:"cert_key_path"`
	// Whether this host can route IPv6. Subscribers are told the same thing
	// in their link, so the endpoint has to agree with it. nil (a panel
	// that does not send it) keeps the endpoint's default.
	HasIPv6 *bool `json:"has_ipv6"`
}

type HysteriaNode struct {
	CommonNode
	UpMbps   int    `json:"up_mbps"`
	DownMbps int    `json:"down_mbps"`
	Obfs     string `json:"obfs"`
}

type Hysteria2Node struct {
	CommonNode
	Ignore_Client_Bandwidth bool   `json:"ignore_client_bandwidth"`
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	ObfsType                string `json:"obfs"`
	ObfsPassword            string `json:"obfs-password"`
}

type RawDNS struct {
	DNSMap  map[string]map[string]interface{}
	DNSJson []byte
}

// Rules are the panel's blocking rules for a node, enforced for every core
// that routes connections through the limiter (xray and sing).
type Rules struct {
	// Domains from "block" written bare or as "regexp:", read as regular
	// expressions (the "regexp:" prefix removed).
	Regexp []string
	// Domains from "block" in xray's rule syntax: "domain:", "full:",
	// "keyword:", "geosite:", "ext:".
	Domain []string
	// Sniffed protocols: "protocol" rules, and "block" entries written as
	// "protocol:<name>".
	Protocol []string
	// Destination addresses from "block_ip": an IP, a CIDR or "geoip:<code>".
	IP []string
	// Destination ports from "block_port": a port or a range "1000-2000".
	Port []string
}

// RouteRule sends matching traffic of a node to an outbound of its own: the
// panel's "route" (by domain), "route_ip" (by address) and "default_out"
// (everything else). Outbound is an xray outbound object.
type RouteRule struct {
	Id       int
	Action   string
	Match    []string
	Outbound json.RawMessage
}

// domainRulePrefixes are the xray rule forms a "block" entry may use besides
// a bare or "regexp:" pattern.
var domainRulePrefixes = []string{"domain:", "full:", "keyword:", "geosite:", "ext:", "ext-domain:", "ext-site:", "dotless:"}

func isPrefixedDomainRule(v string) bool {
	for _, p := range domainRulePrefixes {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// ResetNodeCache clears the cached node ETag/body hash so the next GetNodeInfo
// re-fetches the full node config instead of returning "unchanged". Used to
// force a retry after a node reload failed partway through — otherwise the node
// would look unchanged on the next poll and stay broken until the panel config
// actually changes.
func (c *Client) ResetNodeCache() {
	c.nodeEtag = ""
	c.responseBodyHash = ""
}

func (c *Client) GetNodeInfo() (node *NodeInfo, err error) {
	const path = "/api/v1/server/UniProxy/config"
	r, err := c.client.
		R().
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)

	if r != nil && r.StatusCode() == 304 {
		return nil, nil
	}
	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	// Remember this reply only once it has been understood. The hash and ETag
	// used to be stored before the status check and the parse, so an error
	// page, or a config that failed to decode, was recorded as the current
	// one: the next poll got a 304 or the same hash, and the node never
	// applied that config until the panel changed it again.
	newEtag := r.Header().Get("ETag")
	defer func() {
		if err == nil && node != nil {
			c.responseBodyHash = newBodyHash
			c.nodeEtag = newEtag
		}
	}()

	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("received nil response")
	}
	nodeType := hysteriaVersionType(c.NodeType, r.Body())
	node = &NodeInfo{
		Id:   c.NodeId,
		Type: nodeType,
		RawDNS: RawDNS{
			DNSMap:  make(map[string]map[string]interface{}),
			DNSJson: []byte(""),
		},
	}
	// parse protocol params
	var cm *CommonNode
	switch nodeType {
	case "vmess", "vless":
		rsp := &VAllssNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode v2ray params error: %s", err)
		}
		if len(rsp.NetworkSettingsBack) > 0 {
			rsp.NetworkSettings = rsp.NetworkSettingsBack
			rsp.NetworkSettingsBack = nil
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.VAllss = rsp
		node.Security = node.VAllss.Tls
	case "shadowsocks":
		rsp := &ShadowsocksNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode shadowsocks params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Shadowsocks = rsp
		node.Security = None
	case "trojan":
		rsp := &TrojanNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode trojan params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Trojan = rsp
		node.Security = Tls
	case "tuic":
		rsp := &TuicNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode tuic params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Tuic = rsp
		node.Security = Tls
	case "anytls":
		rsp := &AnyTlsNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode anytls params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.AnyTls = rsp
		// Read the mode the panel actually sent instead of assuming plain TLS.
		// The old unconditional `node.Security = Tls` is why REALITY could never
		// reach an anytls node however completely it was implemented below.
		// anytls is never plaintext, so anything that is not an explicit
		// Reality (2) - including the 0 an un-upgraded panel sends - is Tls.
		if rsp.Tls == Reality {
			node.Security = Reality
		} else {
			node.Security = Tls
		}
	case "mdns":
		rsp := &MdnsNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode mdns params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Mdns = rsp
		node.Security = None
	case "trusttunnel":
		rsp := &TrustTunnelNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode trusttunnel params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.TrustTunnel = rsp
		// The endpoint terminates TLS itself, whatever certificate it ends up
		// with, so this is never plaintext.
		node.Security = Tls
	case "hysteria":
		rsp := &HysteriaNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode hysteria params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Hysteria = rsp
		node.Security = Tls
	case "hysteria2":
		rsp := &Hysteria2Node{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode hysteria2 params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Hysteria2 = rsp
		node.Security = Tls
	}

	if cm == nil {
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}
	// A panel that sends no base_config gets the defaults below. Reading
	// through the nil pointer crashed the process - on a node's first start,
	// where nothing recovers, that was every node the process served.
	if cm.BaseConfig == nil {
		cm.BaseConfig = &BaseConfig{}
	}

	// parse rules and dns
	for i := range cm.Routes {
		route := cm.Routes[i]
		matchs := routeMatches(route.Match)
		// default_out matches everything, so it has no match list; every
		// other action with nothing to match is a no-op. An empty or null
		// match used to crash the process here (an unchecked type assertion,
		// then matchs[0]).
		if len(matchs) == 0 && route.Action != "default_out" {
			continue
		}
		switch route.Action {
		case "block":
			for _, v := range matchs {
				switch {
				case strings.HasPrefix(v, "protocol:"):
					node.Rules.Protocol = append(node.Rules.Protocol, strings.TrimPrefix(v, "protocol:"))
				case isPrefixedDomainRule(v):
					node.Rules.Domain = append(node.Rules.Domain, v)
				default:
					node.Rules.Regexp = append(node.Rules.Regexp, strings.TrimPrefix(v, "regexp:"))
				}
			}
		// The next three were offered by the panel and ignored here, so an
		// operator's rule blocking an address range, a port or BitTorrent did
		// nothing, with no error anywhere.
		case "block_ip":
			node.Rules.IP = append(node.Rules.IP, matchs...)
		case "block_port":
			node.Rules.Port = append(node.Rules.Port, matchs...)
		case "protocol":
			node.Rules.Protocol = append(node.Rules.Protocol, matchs...)
		case "route", "route_ip", "default_out":
			if strings.TrimSpace(route.ActionValue) == "" {
				log.WithField("route", route.Id).Warnf("panel %s rule has no outbound; skipped", route.Action)
				continue
			}
			node.RouteRules = append(node.RouteRules, RouteRule{
				Id:       route.Id,
				Action:   route.Action,
				Match:    matchs,
				Outbound: json.RawMessage(route.ActionValue),
			})
		case "dns":
			var domains []string
			domains = append(domains, matchs...)
			if matchs[0] != "main" {
				node.RawDNS.DNSMap[strconv.Itoa(i)] = map[string]interface{}{
					"address": route.ActionValue,
					"domains": domains,
				}
			} else {
				dns := []byte(strings.Join(matchs[1:], ""))
				node.RawDNS.DNSJson = dns
			}
		default:
			log.WithField("route", route.Id).Warnf("panel route action %q is not supported; skipped", route.Action)
		}
	}
	// A default outbound catches everything, so it goes last whatever its
	// place in the panel's list; the specific rules must be tried first.
	sort.SliceStable(node.RouteRules, func(a, b int) bool {
		return node.RouteRules[a].Action != "default_out" && node.RouteRules[b].Action == "default_out"
	})

	// set interval
	node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
	node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)
	// Optional thresholds — nil/absent on older panels → 0 (feature disabled).
	node.NodeReportMinTraffic = anyToInt64(cm.BaseConfig.NodeReportMinTraffic)
	node.DeviceOnlineMinTraffic = anyToInt64(cm.BaseConfig.DeviceOnlineMinTraffic)

	node.Common = cm
	// clear
	cm.Routes = nil
	cm.BaseConfig = nil

	return node, nil
}

// hysteriaVersionType is the node type to decode a hysteria reply as.
//
// The panel keeps hysteria 1 and 2 as one node type and tells them apart by
// the node's "version", while the node went by its own NodeType alone. A node
// configured as "hysteria" whose panel entry is version 2 (or the reverse)
// decoded the reply as the other protocol and served it, with no error: every
// subscriber, configured from the panel's version, failed to connect. The
// panel's version now decides; a reply without one keeps the configured type.
func hysteriaVersionType(configured string, body []byte) string {
	if configured != "hysteria" && configured != "hysteria2" {
		return configured
	}
	var v struct {
		Version any `json:"version"`
	}
	if json.Unmarshal(body, &v) != nil {
		return configured
	}
	want := configured
	switch anyToInt64(v.Version) {
	case 1:
		want = "hysteria"
	case 2:
		want = "hysteria2"
	}
	if want != configured {
		log.Warnf("panel node is %s (version %v) but NodeType is %s: serving %s",
			want, v.Version, configured, want)
	}
	return want
}

// anyToInt64 converts a msgpack/json-decoded number (int/uint/float/string)
// to int64. Returns 0 for nil so panels that don't send the field are safe.
func anyToInt64(i interface{}) int64 {
	if i == nil {
		return 0
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflect.ValueOf(i).Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(reflect.ValueOf(i).Uint())
	case reflect.Float64, reflect.Float32:
		return int64(reflect.ValueOf(i).Float())
	case reflect.String:
		v, _ := strconv.Atoi(i.(string))
		return int64(v)
	default:
		return 0
	}
}

// defaultInterval stands in for a push/pull interval the panel did not send
// or sent as nothing usable.
const defaultInterval = 60 * time.Second

// intervalToTime converts the panel's push/pull interval (seconds, as a number
// or a string) to a duration. A missing, zero, negative or unparsable value
// yields defaultInterval: nil used to panic here, and zero produced a task
// that re-ran with no pause at all - every node hammering the panel.
func intervalToTime(i interface{}) time.Duration {
	if seconds := anyToInt64(i); seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return defaultInterval
}

// routeMatches normalises a route's "match" field, which the panel may send as
// a comma-separated string, a list of strings, or a list of mixed JSON values.
// Anything that is not a non-empty string is dropped.
func routeMatches(m interface{}) []string {
	var raw []string
	switch v := m.(type) {
	case string:
		raw = strings.Split(v, ",")
	case []string:
		raw = v
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				raw = append(raw, s)
			}
		}
	}
	out := raw[:0:0]
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
