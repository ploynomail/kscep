package data

import (
	"crypto/x509"
	"kscep/internal/biz"
	"kscep/internal/conf"

	"github.com/go-kratos/kratos/v2/log"
)

type SCEPCARepo struct {
	data       *Data
	dataConfig *conf.Data
	log        *log.Helper
}

func NewSCEPCARepo(c *conf.Data, data *Data, logger log.Logger) biz.SCEPCARepo {
	return &SCEPCARepo{
		data:       data,
		dataConfig: c,
		log:        log.NewHelper(log.With(logger, "module", "data/scep/ca")),
	}
}

func (c *SCEPCARepo) GetCert(t biz.CaType) (*x509.Certificate, error) {
	var pass string = ""
	if t == biz.RsaCa {
		pass = c.dataConfig.RSAsigerconfig.Capass
	}
	pub, _, err := c.data.Depot.CA([]byte(pass), t.String())
	if err != nil {
		return nil, err
	}
	return pub[0], nil
}
func (c *SCEPCARepo) GetKey(t biz.CaType) (interface{}, error) {
	var pass string = ""
	if t == biz.RsaCa {
		pass = c.dataConfig.RSAsigerconfig.Capass
	}
	_, key, err := c.data.Depot.CA([]byte(pass), t.String())
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *SCEPCARepo) GetAddlCA() ([]*x509.Certificate, error) {
	return nil, nil
}
