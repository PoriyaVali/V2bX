package sing

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/conf"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	log "github.com/sirupsen/logrus"
)

type HttpNetworkConfig struct {
	Header struct {
		Type     string           `json:"type"`
		Request  *json.RawMessage `json:"request"`
		Response *json.RawMessage `json:"response"`
	} `json:"header"`
}

type HttpRequest struct {
	Version string   `json:"version"`
	Method  string   `json:"method"`
	Path    []string `json:"path"`
	Headers struct {
		Host []string `json:"Host"`
	} `json:"headers"`
}

type WsNetworkConfig struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type GrpcNetworkConfig struct {
	ServiceName string `json:"serviceName"`
}

type HttpupgradeNetworkConfig struct {
	Path string `json:"path"`
	Host string `json:"host"`
}

func getInboundOptions(tag string, info *panel.NodeInfo, c *conf.Options) (option.Inbound, error) {
	addr, err := netip.ParseAddr(c.ListenIP)
	if err != nil {
		return option.Inbound{}, fmt.Errorf("the listen ip not vail")
	}
	listen := option.ListenOptions{
		Listen:      (*badoption.Addr)(&addr),
		ListenPort:  uint16(info.Common.ServerPort),
		TCPFastOpen: c.SingOptions.TCPFastOpen,
		// Wire the SingOptions sniff/domain settings into the inbound. Without
		// this, sniffing is off so the destination stays an IP — domain and
		// protocol audit rules (hook.go) never match and logs show raw IPs.
		InboundOptions: option.InboundOptions{
			SniffEnabled:             c.SingOptions.SniffEnabled,
			SniffOverrideDestination: c.SingOptions.SniffOverrideDestination,
			DomainStrategy:           c.SingOptions.DomainStrategy,
		},
		// Recover the real client IP behind the Hedioum tunnel via PROXY protocol.
		// AcceptNoHeader keeps direct (non-tunnel) connections working.
		ProxyProtocol:               c.SingOptions.ProxyProtocol,
		ProxyProtocolAcceptNoHeader: c.SingOptions.ProxyProtocol,
	}
	var multiplex *option.InboundMultiplexOptions
	if c.SingOptions.Multiplex != nil {
		multiplexOption := option.InboundMultiplexOptions{
			Enabled: c.SingOptions.Multiplex.Enabled,
			Padding: c.SingOptions.Multiplex.Padding,
			Brutal: &option.BrutalOptions{
				Enabled:  c.SingOptions.Multiplex.Brutal.Enabled,
				UpMbps:   c.SingOptions.Multiplex.Brutal.UpMbps,
				DownMbps: c.SingOptions.Multiplex.Brutal.DownMbps,
			},
		}
		multiplex = &multiplexOption
	}
	// The TLS settings and the reality tuning live on different node structs
	// per protocol. Resolving them ONCE here is what lets the two branches below
	// stay protocol-agnostic: the Reality branch used to read info.VAllss
	// directly, which is populated only for vmess/vless, so reaching it with an
	// anytls node dereferenced a nil pointer.
	var tlsSettings panel.TlsSettings
	var realityConfig panel.RealityConfig
	switch {
	case info.VAllss != nil:
		tlsSettings = info.VAllss.TlsSettings
		realityConfig = info.VAllss.RealityConfig
	case info.AnyTls != nil:
		tlsSettings = info.AnyTls.TlsSettings
	}

	var tls option.InboundTLSOptions
	switch info.Security {
	case panel.Tls:
		if c.CertConfig == nil {
			return option.Inbound{}, fmt.Errorf("the CertConfig is not vail")
		}
		switch c.CertConfig.CertMode {
		case "none", "":
			break // disable
		default:
			tls.Enabled = true
			tls.CertificatePath = c.CertConfig.CertFile
			tls.KeyPath = c.CertConfig.KeyFile
		}
		// ECH encrypts the SNI of the certificate we just loaded, so it only
		// makes sense on this branch - under REALITY the name on the wire is
		// the borrowed site's already. Attached only when the panel both turned
		// it on and sent a key, so a node whose panel predates this stays
		// exactly as it was.
		if tls.Enabled && tlsSettings.Ech != "" && tlsSettings.EchKey != "" {
			pem, err := echKeyToPEM(tlsSettings.EchKey)
			if err != nil {
				return option.Inbound{}, fmt.Errorf("anytls ech key: %s", err)
			}
			tls.ECH = &option.InboundECHOptions{
				Enabled: true,
				Key:     []string{pem},
			}
		}
	case panel.Reality:
		tls.Enabled = true
		tls.ServerName = tlsSettings.ServerName
		port, _ := strconv.Atoi(tlsSettings.ServerPort)
		var dest string
		if tlsSettings.Dest != "" {
			dest = tlsSettings.Dest
		} else {
			dest = tls.ServerName
		}

		mtd, _ := time.ParseDuration(realityConfig.MaxTimeDiff)
		tls.Reality = &option.InboundRealityOptions{
			Enabled:    true,
			ShortID:    []string{tlsSettings.ShortId},
			PrivateKey: tlsSettings.PrivateKey,
			Xver:       uint8(tlsSettings.Xver),
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     dest,
					ServerPort: uint16(port),
				},
			},
			MaxTimeDifference: badoption.Duration(mtd),
		}
	}
	in := option.Inbound{
		Tag: tag,
	}
	switch info.Type {
	case "vmess", "vless":
		n := info.VAllss
		t := option.V2RayTransportOptions{
			Type: n.Network,
		}
		switch n.Network {
		case "tcp":
			if len(n.NetworkSettings) != 0 {
				network := HttpNetworkConfig{}
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
				//Todo fix http options
				if network.Header.Type == "http" {
					t.Type = network.Header.Type
					var request HttpRequest
					if network.Header.Request != nil {
						err = json.Unmarshal(*network.Header.Request, &request)
						if err != nil {
							return option.Inbound{}, fmt.Errorf("decode HttpRequest error: %s", err)
						}
						t.HTTPOptions.Host = request.Headers.Host
						t.HTTPOptions.Path = request.Path[0]
						t.HTTPOptions.Method = request.Method
					}
				} else {
					t.Type = ""
				}
			} else {
				t.Type = ""
			}
		case "ws":
			var (
				path    string
				ed      int
				headers map[string]badoption.Listable[string]
			)
			if len(n.NetworkSettings) != 0 {
				network := WsNetworkConfig{}
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
				var u *url.URL
				u, err = url.Parse(network.Path)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("parse path error: %s", err)
				}
				path = u.Path
				ed, _ = strconv.Atoi(u.Query().Get("ed"))
				headers = make(map[string]badoption.Listable[string], len(network.Headers))
				for k, v := range network.Headers {
					headers[k] = badoption.Listable[string]{
						v,
					}
				}
			}
			t.WebsocketOptions = option.V2RayWebsocketOptions{
				Path:                path,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
				MaxEarlyData:        uint32(ed),
				Headers:             headers,
			}
		case "grpc":
			network := GrpcNetworkConfig{}
			if len(n.NetworkSettings) != 0 {
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
			}
			t.GRPCOptions = option.V2RayGRPCOptions{
				ServiceName: network.ServiceName,
			}
		case "httpupgrade":
			network := HttpupgradeNetworkConfig{}
			if len(n.NetworkSettings) != 0 {
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
			}
			t.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{
				Path: network.Path,
				Host: network.Host,
			}
		}
		if info.Type == "vless" {
			in.Type = "vless"
			in.Options = &option.VLESSInboundOptions{
				ListenOptions: listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &tls,
				},
				Transport: &t,
				Multiplex: multiplex,
			}
		} else {
			in.Type = "vmess"
			in.Options = &option.VMessInboundOptions{
				ListenOptions: listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &tls,
				},
				Transport: &t,
				Multiplex: multiplex,
			}
		}
	case "shadowsocks":
		in.Type = "shadowsocks"
		n := info.Shadowsocks
		var keyLength int
		switch n.Cipher {
		case "2022-blake3-aes-128-gcm":
			keyLength = 16
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
			keyLength = 32
		default:
			keyLength = 16
		}
		ssoption := &option.ShadowsocksInboundOptions{
			ListenOptions: listen,
			Method:        n.Cipher,
			Multiplex:     multiplex,
		}
		p := make([]byte, keyLength)
		_, _ = rand.Read(p)
		randomPasswd := string(p)
		if strings.Contains(n.Cipher, "2022") {
			ssoption.Password = n.ServerKey
			randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		}
		ssoption.Users = []option.ShadowsocksUser{{
			Password: randomPasswd,
		}}
		in.Options = ssoption
	case "trojan":
		n := info.Trojan
		t := option.V2RayTransportOptions{
			Type: n.Network,
		}
		switch n.Network {
		case "tcp":
			t.Type = ""
		case "ws":
			var (
				path    string
				ed      int
				headers map[string]badoption.Listable[string]
			)
			if len(n.NetworkSettings) != 0 {
				network := WsNetworkConfig{}
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
				var u *url.URL
				u, err = url.Parse(network.Path)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("parse path error: %s", err)
				}
				path = u.Path
				ed, _ = strconv.Atoi(u.Query().Get("ed"))
				headers = make(map[string]badoption.Listable[string], len(network.Headers))
				for k, v := range network.Headers {
					headers[k] = badoption.Listable[string]{
						v,
					}
				}
			}
			t.WebsocketOptions = option.V2RayWebsocketOptions{
				Path:                path,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
				MaxEarlyData:        uint32(ed),
				Headers:             headers,
			}
		case "grpc":
			network := GrpcNetworkConfig{}
			if len(n.NetworkSettings) != 0 {
				err := json.Unmarshal(n.NetworkSettings, &network)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
			}
			t.GRPCOptions = option.V2RayGRPCOptions{
				ServiceName: network.ServiceName,
			}
		default:
			t.Type = ""
		}
		in.Type = "trojan"
		trojanoption := &option.TrojanInboundOptions{
			ListenOptions: listen,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
			Transport: &t,
			Multiplex: multiplex,
		}
		if c.SingOptions.FallBackConfigs != nil {
			// fallback handling
			fallback := c.SingOptions.FallBackConfigs.FallBack
			fallbackPort, err := strconv.Atoi(fallback.ServerPort)
			if err == nil {
				trojanoption.Fallback = &option.ServerOptions{
					Server:     fallback.Server,
					ServerPort: uint16(fallbackPort),
				}
			}
			fallbackForALPNMap := c.SingOptions.FallBackConfigs.FallBackForALPN
			fallbackForALPN := make(map[string]*option.ServerOptions, len(fallbackForALPNMap))
			if err := processFallback(c, fallbackForALPN); err == nil {
				trojanoption.FallbackForALPN = fallbackForALPN
			}
		}
		in.Options = trojanoption
	case "tuic":
		in.Type = "tuic"
		tls.ALPN = append(tls.ALPN, "h3")
		in.Options = &option.TUICInboundOptions{
			ListenOptions:     listen,
			CongestionControl: info.Tuic.CongestionControl,
			ZeroRTTHandshake:  info.Tuic.ZeroRTTHandshake,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "anytls":
		in.Type = "anytls"
		in.Options = &option.AnyTLSInboundOptions{
			ListenOptions: listen,
			PaddingScheme: info.AnyTls.PaddingScheme,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "hysteria":
		in.Type = "hysteria"
		in.Options = &option.HysteriaInboundOptions{
			ListenOptions: listen,
			UpMbps:        info.Hysteria.UpMbps,
			DownMbps:      info.Hysteria.DownMbps,
			Obfs:          info.Hysteria.Obfs,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "hysteria2":
		in.Type = "hysteria2"
		var obfs *option.Hysteria2Obfs
		if info.Hysteria2.ObfsType != "" && info.Hysteria2.ObfsPassword != "" {
			obfs = &option.Hysteria2Obfs{
				Type:     info.Hysteria2.ObfsType,
				Password: info.Hysteria2.ObfsPassword,
			}
		} else if info.Hysteria2.ObfsType != "" {
			obfs = &option.Hysteria2Obfs{
				Type:     "salamander",
				Password: info.Hysteria2.ObfsType,
			}
		}
		in.Options = &option.Hysteria2InboundOptions{
			ListenOptions:         listen,
			UpMbps:                info.Hysteria2.UpMbps,
			DownMbps:              info.Hysteria2.DownMbps,
			IgnoreClientBandwidth: info.Hysteria2.Ignore_Client_Bandwidth,
			Obfs:                  obfs,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	}
	return in, nil
}

// echKeyToPEM turns the panel's ECH server key into the form sing-box accepts.
//
// The two ends disagree on purpose-built formats and neither is wrong: the panel
// stores MarshalECHKeys output as bare base64 (it is JSON, and that travels),
// while sing-box's parseECHKeys runs pem.Decode and rejects anything whose block
// type is not "ECH KEYS". Handing the stored value over unwrapped therefore
// fails at inbound construction with a message about ECH keys rather than about
// encoding, which is a long way to walk for a missing header - so the wrapping
// lives here, next to the only caller.
//
// A value that is already PEM is passed through, so an operator who pastes a
// proper block by hand is not punished for it.
func echKeyToPEM(key string) (string, error) {
	key = strings.TrimSpace(key)
	if strings.Contains(key, "-----BEGIN") {
		return key, nil
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		// The panel may url-safe encode elsewhere; accept that too rather than
		// fail a node over an alphabet.
		raw, err = base64.URLEncoding.DecodeString(key)
		if err != nil {
			return "", fmt.Errorf("decode base64: %s", err)
		}
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("empty key")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: raw})), nil
}

func (b *Sing) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	b.nodeReportMinTrafficBytes[tag] = config.ReportMinTraffic * 1024
	c, err := getInboundOptions(tag, info, config)
	if err != nil {
		return err
	}
	// Point the anytls inbound's fallback at this node's own decoy site, so a
	// prober that speaks TLS and then fails authentication is answered by a
	// web page instead of a closed socket. Started here rather than inside
	// getInboundOptions because the listener's lifetime belongs to the node,
	// not to the options struct.
	//
	// A failure to start it is deliberately NOT fatal: losing the disguise is
	// worse than nothing, but refusing to bring the node up would cost every
	// user their connection over a cosmetic listener.
	if c.Type == "anytls" && config.SingOptions.DecoyEnabled() {
		if opts, ok := c.Options.(*option.AnyTLSInboundOptions); ok {
			if d, derr := startDecoy(decoySeed(tag)); derr != nil {
				log.WithField("err", derr).Warn("decoy site unavailable; unauthenticated connections will be closed")
			} else {
				host, port := d.hostPort()
				opts.Fallback = &option.ServerOptions{Server: host, ServerPort: port}
				b.decoysMu.Lock()
				if old := b.decoys[tag]; old != nil {
					_ = old.Close() // node re-added: replace, never leak
				}
				b.decoys[tag] = d
				b.decoysMu.Unlock()
			}
		}
	}
	in := b.box.Inbound()
	err = in.Create(
		b.ctx,
		b.box.Router(),
		b.logFactory.NewLogger(F.ToString("inbound/", c.Type, "[", tag, "]")),
		tag,
		c.Type,
		c.Options,
	)

	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (b *Sing) DelNode(tag string) error {
	b.decoysMu.Lock()
	if d := b.decoys[tag]; d != nil {
		_ = d.Close()
		delete(b.decoys, tag)
	}
	b.decoysMu.Unlock()
	in := b.box.Inbound()
	err := in.Remove(tag)
	if err != nil {
		return fmt.Errorf("delete inbound error: %s", err)
	}
	return nil
}
