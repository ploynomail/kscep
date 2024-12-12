package biz

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"kscep/internal/utils"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/ploynomail/pkcs7"
	"github.com/ploynomail/scep"
)

type SCEPUsecase struct {
	caUsecase *SCEPCAUsecase
	// The (chainable) CSR signing function. Intended to handle all
	// SCEP request functionality such as CSR & challenge checking, CA
	// issuance, RA proxying, etc.
	signer *CSRSignerUsecase

	/// info logging is implemented in the service middleware layer.
	log *log.Helper
}

// NewSCEPRepo returns a new SCEPRepo instance.
func NewSCEPUsecase(cu *SCEPCAUsecase, singer *CSRSignerUsecase, logger log.Logger) *SCEPUsecase {
	return &SCEPUsecase{
		caUsecase: cu,
		signer:    singer,
		log:       log.NewHelper(log.With(logger, "module", "usecase/scep")),
	}
}

func (svc *SCEPUsecase) GetCACaps(ctx context.Context) ([]byte, error) {
	return GBT0089Caps, nil
}

func (svc *SCEPUsecase) GetCACert(ctx context.Context, msg string) ([]byte, int, error) {
	caType := strings.ToUpper(strings.Trim(msg, "\n"))
	if !utils.IsInArray(SupportedCaTypes, caType) {
		return nil, 0, UnsupportedCaTypeErr
	}
	cer, err := svc.caUsecase.GetCACert(caType)
	if err != nil || cer == nil {
		svc.log.Errorf("failed to get CA cert: %v", err)
		return nil, 0, MissingCaCertErr
	}
	addlCA, err := svc.caUsecase.GetAddlCA()
	if err != nil {
		return nil, 0, err
	}
	if len(addlCA) < 1 {
		return cer.Raw, 1, nil
	}
	certs := []*x509.Certificate{cer}
	certs = append(certs, addlCA...)
	data, err := svc.DegenerateCertificates(certs)
	return data, len(addlCA) + 1, err
}

// TODO
func (svc *SCEPUsecase) PKIOperation(ctx context.Context, data []byte) ([]byte, error) {
	caCrt, err := svc.caUsecase.GetCACert("RSA")
	if err != nil {
		return nil, err
	}
	caKey, err := svc.caUsecase.GetCAKey("RSA")
	if err != nil {
		return nil, err
	}

	msg, err := scep.ParsePKIMessage(data, scep.WithLogger(utils.LoggerWapper(svc.log)))
	if err != nil {
		return nil, err
	}
	if err := msg.DecryptPKIEnvelope(caCrt, caKey); err != nil {
		return nil, err
	}

	crt, err := svc.signer.SignCSR(ctx, msg.CSRReqMessage)
	if err == nil && crt == nil {
		err = errors.New("no signed certificate")
	}
	if err != nil {
		svc.log.Errorf("failed to sign CSR: %v", err)
		certRep, err := msg.Fail(caCrt, caKey, scep.BadRequest)
		return certRep.Raw, err
	}

	certRep, err := msg.Success(caCrt, caKey, crt)
	return certRep.Raw, err
}

func (svc *SCEPUsecase) GetNextCACert(ctx context.Context) ([]byte, error) {
	return nil, errors.New("not yet implemented")
}

func (svc *SCEPUsecase) DegenerateCertificates(certs []*x509.Certificate) ([]byte, error) {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	degenerate, err := pkcs7.DegenerateCertificate(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return degenerate, nil
}
