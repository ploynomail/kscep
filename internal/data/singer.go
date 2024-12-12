package data

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"kscep/internal/biz"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/ploynomail/scep"
	"github.com/ploynomail/scep/cryptoutil"
)

// Signer signs x509 certificates and stores them in a Depot
type SignerRepo struct {
	data             *Data
	caPass           string
	allowRenewalDays int
	validityDays     int
	serverAttrs      bool
	signatureAlgo    x509.SignatureAlgorithm
	log              *log.Helper
}

// Option customizes Signer
type Option func(*SignerRepo)

// NewSigner creates a new Signer
func NewSigner(data *Data, logger log.Logger) biz.CSRSignerRepo {
	return &SignerRepo{
		data: data,
		log:  log.NewHelper(log.With(logger, "module", "data/signer")),
	}
}

// WithCAPass specifies the password to use with an encrypted CA key
func (s *SignerRepo) WithCAPass(pass string) {
	s.caPass = pass
}

// WithAllowRenewalDays sets the allowable renewal time for existing certs
func (s *SignerRepo) WithAllowRenewalDays(r int) {
	s.allowRenewalDays = r
}

// WithValidityDays sets the validity period new certs will use
func (s *SignerRepo) WithValidityDays(v int) {
	s.validityDays = v
}

func (s *SignerRepo) WithSeverAttrs() {
	s.serverAttrs = true
}

func (s *SignerRepo) SignCSRContext(ctx context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
	s.signatureAlgo = m.CSR.SignatureAlgorithm
	id, err := cryptoutil.GenerateSubjectKeyID(m.CSR.PublicKey)
	if err != nil {
		return nil, err
	}

	serial, err := s.data.Depot.Serial()
	if err != nil {
		return nil, err
	}

	var signatureAlgo x509.SignatureAlgorithm
	if s.signatureAlgo != 0 {
		signatureAlgo = s.signatureAlgo
	}

	// create cert template
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      m.CSR.Subject,
		NotBefore:    time.Now().Add(time.Second * -600).UTC(),
		NotAfter:     time.Now().AddDate(10, 0, s.validityDays).UTC(),
		SubjectKeyId: id,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		SignatureAlgorithm: signatureAlgo,
		DNSNames:           m.CSR.DNSNames,
		EmailAddresses:     m.CSR.EmailAddresses,
		IPAddresses:        m.CSR.IPAddresses,
		URIs:               m.CSR.URIs,
	}

	if s.serverAttrs {
		tmpl.KeyUsage |= x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	caCerts, caKey, err := s.data.Depot.CA([]byte(s.caPass), "RSA")
	if err != nil {
		return nil, err
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCerts[0], m.CSR.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, err
	}

	name := certName(crt)

	// Test if this certificate is already in the CADB, revoke if needed
	// revocation is done if the validity of the existing certificate is
	// less than allowRenewalDays
	_, err = s.data.Depot.HasCN(name, s.allowRenewalDays, crt, false)
	if err != nil {
		return nil, err
	}

	if err := s.data.Depot.Put(name, crt); err != nil {
		return nil, err
	}

	return crt, nil
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	return string(crt.Signature)
}
