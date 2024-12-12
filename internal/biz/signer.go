package biz

import (
	"context"
	"crypto/x509"
	"kscep/internal/conf"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/ploynomail/scep"
)

// CSRReqMessage can be of the type PKCSReq/RenewalReq/UpdateReq
// and includes a PKCS#10 CSR request.
// The content of this message is protected
// by the recipient public key(example CA)
type CSRReqMessage struct {
	RawDecrypted []byte
	// PKCS#10 Certificate request inside the envelope
	CSR *x509.CertificateRequest

	ChallengePassword string
}

type CSRSignerRepo interface {
	SignCSRContext(context.Context, *scep.CSRReqMessage) (*x509.Certificate, error)
	WithCAPass(pass string)
	WithAllowRenewalDays(r int)
	WithValidityDays(v int)
	WithSeverAttrs()
}

type CSRSignerUsecase struct {
	repo CSRSignerRepo
	conf *conf.Data
	log  *log.Helper
}

func NewCSRSignerUsecase(conf *conf.Data, logger log.Logger, repo CSRSignerRepo) *CSRSignerUsecase {
	return &CSRSignerUsecase{
		conf: conf,
		repo: repo,
		log:  log.NewHelper(log.With(logger, "module", "usecase/scep/signer")),
	}
}

func (uc *CSRSignerUsecase) SignCSR(ctx context.Context, csr *scep.CSRReqMessage) (*x509.Certificate, error) {
	return uc.repo.SignCSRContext(ctx, csr)
}
