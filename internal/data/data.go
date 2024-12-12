package data

import (
	"kscep/internal/biz"
	"kscep/internal/conf"
	"kscep/internal/depots/filedepot"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/wire"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(
	NewData,
	NewSCEPCARepo,
	NewSigner,
)

// Data .
type Data struct {
	Depot Depot
}

// NewData .
func NewData(c *conf.Data, logger log.Logger) (*Data, func(), error) {
	var depot Depot
	var err error
	switch c.DepotType {
	case "file":
		if c.Filedepot.Capath == "" || c.Filedepot.Addlcapath == "" {
			return nil, nil, biz.DepotConfigErr
		}
		depot, err = filedepot.NewFileDepot(c.Filedepot.Capath)
		if err != nil {
			panic(err)
		}
	}
	cleanup := func() {
		log.NewHelper(logger).Info("closing the data resources")
	}
	return &Data{
		Depot: depot,
	}, cleanup, nil
}
