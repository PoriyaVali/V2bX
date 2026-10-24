package node

import (
	"github.com/PoriyaVali/V2bX/common/certmanager"
	"github.com/PoriyaVali/V2bX/conf"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) renewCertTask() error {
	tag, _, _ := c.state()
	if err := certmanager.Renew(c.CertConfig); err != nil {
		log.WithField("tag", tag).Error("renew cert error: ", err)
	}
	// A transient authority/provider failure must not stop the periodic task.
	return nil
}

func (c *Controller) requestCert() error { return certmanager.Ensure(c.CertConfig) }

func validCertificatePair(config *conf.CertConfig) error {
	return certmanager.ValidCertificatePair(config)
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	return certmanager.GenerateSelf(domain, certPath, keyPath)
}
