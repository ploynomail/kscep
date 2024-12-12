package biz

import (
	"crypto/x509"

	"github.com/go-kratos/kratos/v2/log"
)

type SCEPCARepo interface {
	GetCert(t CaType) (*x509.Certificate, error)
	GetKey(t CaType) (interface{}, error)
	GetAddlCA() ([]*x509.Certificate, error)
}

type SCEPCAUsecase struct {
	caRepo SCEPCARepo
	log    *log.Helper
}

// NewSCEPCAUsecase returns a new SCEPCAUsecase instance.
func NewSCEPCAUsecase(caRepo SCEPCARepo, logger log.Logger) *SCEPCAUsecase {
	return &SCEPCAUsecase{
		caRepo: caRepo,
		log:    log.NewHelper(log.With(logger, "module", "usecase/scep/ca")),
	}
}

func (svc *SCEPCAUsecase) GetCACert(t string) (*x509.Certificate, error) {
	return svc.caRepo.GetCert(GetCaType(t))
}

func (svc *SCEPCAUsecase) GetCAKey(t string) (interface{}, error) {
	return svc.caRepo.GetKey(GetCaType(t))
}

func (svc *SCEPCAUsecase) GetAddlCA() ([]*x509.Certificate, error) {
	return svc.caRepo.GetAddlCA()
}
