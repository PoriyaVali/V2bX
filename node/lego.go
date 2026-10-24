package node

import (
	"crypto/ecdsa"
	"github.com/PoriyaVali/V2bX/common/certmanager"
	"github.com/PoriyaVali/V2bX/conf"
)

// Preserve node's public certificate API while endpoints share its lifecycle.
type Lego = certmanager.Lego
type User = certmanager.User

func NewLego(config *conf.CertConfig) (*Lego, error)      { return certmanager.NewLego(config) }
func NewLegoUser(path, email string) (*User, error)       { return certmanager.NewLegoUser(path, email) }
func EncodePrivate(key *ecdsa.PrivateKey) (string, error) { return certmanager.EncodePrivate(key) }
