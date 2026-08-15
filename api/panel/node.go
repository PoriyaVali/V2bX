package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"encoding/json"
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
	Xver        uint64 `json:"xver,string"`

	// Encrypted Client Hello. Ech is the panel's mode switch ("custom", or
	// empty for off) and EchKey is the server key. The panel stores it as bare
	// base64 while sing-box demands a PEM block of type "ECH KEYS", so it is
	// wrapped on the way into the inbound options - see core/sing/node.go.
	Ech    string `json:"ech"`
	EchKey string `json:"ech_key"`
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
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

type Rules struct {
	Regexp   []string
	Protocol []string
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

	if r.StatusCode() == 304 {
		return nil, nil
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")
	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}

	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("received nil response")
	}
	node = &NodeInfo{
		Id:   c.NodeId,
		Type: c.NodeType,
		RawDNS: RawDNS{
			DNSMap:  make(map[string]map[string]interface{}),
			DNSJson: []byte(""),
		},
	}
	// parse protocol params
	var cm *CommonNode
	switch c.NodeType {
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

	// parse rules and dns
	for i := range cm.Routes {
		var matchs []string
		if _, ok := cm.Routes[i].Match.(string); ok {
			matchs = strings.Split(cm.Routes[i].Match.(string), ",")
		} else if _, ok = cm.Routes[i].Match.([]string); ok {
			matchs = cm.Routes[i].Match.([]string)
		} else {
			temp := cm.Routes[i].Match.([]interface{})
			matchs = make([]string, len(temp))
			for i := range temp {
				matchs[i] = temp[i].(string)
			}
		}
		switch cm.Routes[i].Action {
		case "block":
			for _, v := range matchs {
				if strings.HasPrefix(v, "protocol:") {
					// protocol
					node.Rules.Protocol = append(node.Rules.Protocol, strings.TrimPrefix(v, "protocol:"))
				} else {
					// domain
					node.Rules.Regexp = append(node.Rules.Regexp, strings.TrimPrefix(v, "regexp:"))
				}
			}
		case "dns":
			var domains []string
			domains = append(domains, matchs...)
			if matchs[0] != "main" {
				node.RawDNS.DNSMap[strconv.Itoa(i)] = map[string]interface{}{
					"address": cm.Routes[i].ActionValue,
					"domains": domains,
				}
			} else {
				dns := []byte(strings.Join(matchs[1:], ""))
				node.RawDNS.DNSJson = dns
			}
		}
	}

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

func intervalToTime(i interface{}) time.Duration {
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int:
		return time.Duration(i.(int)) * time.Second
	case reflect.String:
		i, _ := strconv.Atoi(i.(string))
		return time.Duration(i) * time.Second
	case reflect.Float64:
		return time.Duration(i.(float64)) * time.Second
	default:
		return time.Duration(reflect.ValueOf(i).Int()) * time.Second
	}
}
