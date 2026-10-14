package xray

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

func buildSSUsers(tag string, userInfo []panel.UserInfo, cypher string, serverKey string) (users []*protocol.User, err error) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i], err = buildSSUser(tag, &userInfo[i], cypher, serverKey)
		if err != nil {
			return nil, err
		}
	}
	return users, nil
}

func buildSSUser(tag string, userInfo *panel.UserInfo, cypher string, serverKey string) (user *protocol.User, err error) {
	if serverKey == "" {
		ssAccount := &shadowsocks.Account{
			Password:   userInfo.Uuid,
			CipherType: getCipherFromString(cypher),
		}
		return &protocol.User{
			Level:   0,
			Email:   format.UserTag(tag, userInfo.Uuid),
			Account: serial.ToTypedMessage(ssAccount),
		}, nil
	} else {
		var keyLength int
		switch cypher {
		case "2022-blake3-aes-128-gcm":
			keyLength = 16
		case "2022-blake3-aes-256-gcm":
			keyLength = 32
		default:
			return nil, fmt.Errorf("unsupported multi-user shadowsocks 2022 cipher: %s", cypher)
		}
		if len(userInfo.Uuid) < keyLength {
			return nil, fmt.Errorf("shadowsocks 2022 credential for UID %d needs at least %d bytes", userInfo.Id, keyLength)
		}
		ssAccount := &shadowsocks_2022.Account{
			Key: base64.StdEncoding.EncodeToString([]byte(userInfo.Uuid[:keyLength])),
		}
		return &protocol.User{
			Level:   0,
			Email:   format.UserTag(tag, userInfo.Uuid),
			Account: serial.ToTypedMessage(ssAccount),
		}, nil
	}
}

func getCipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		// New in xray v26.
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	default:
		// "none"/"plain" used to map to CipherType_NONE, which xray v26 removed
		// along with unencrypted shadowsocks. UNKNOWN is the honest answer: such
		// a node cannot run on this core, and failing to build the inbound is
		// better than starting one that carries traffic in the clear.
		return shadowsocks.CipherType_UNKNOWN
	}
}
