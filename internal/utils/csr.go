package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"

	"github.com/ploynomail/scep/x509util"
)

const (
	csrPEMBlockType           = "CERTIFICATE REQUEST"
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
)

type CsrOptions struct {
	Cn, Org, Country, OU, Locality, Province, DnsName, Challenge string
	Key                                                          *rsa.PrivateKey
}

func LoadCSRfromFile(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != csrPEMBlockType || len(pemBlock.Headers) != 0 {
		return nil, errors.New("unmatched type or headers")
	}
	return x509.ParseCertificateRequest(pemBlock.Bytes)
}

// convert DER to PEM format
func PemCSR(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    csrPEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	return pem.EncodeToMemory(pemBlock)
}

func LoadOrMakeCSR(path string, opts *CsrOptions) (*x509.CertificateRequest, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if os.IsExist(err) {
			return LoadCSRfromFile(path)
		}
		return nil, err
	}
	defer file.Close()

	subject := pkix.Name{
		Country:            SubjOrNil(opts.Country),
		Province:           SubjOrNil(opts.Province),
		Organization:       SubjOrNil(opts.Org),
		OrganizationalUnit: SubjOrNil(opts.OU),
		Locality:           SubjOrNil(opts.Locality),
		CommonName:         opts.Cn,
	}
	template := x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject:            subject,
			SignatureAlgorithm: x509.SHA256WithRSA,
			DNSNames:           SubjOrNil(opts.DnsName),
		},
	}
	if opts.Challenge != "" {
		template.ChallengePassword = opts.Challenge
	}

	derBytes, err := x509util.CreateCertificateRequest(rand.Reader, &template, opts.Key)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{
		Type:  csrPEMBlockType,
		Bytes: derBytes,
	}
	if err := pem.Encode(file, pemBlock); err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(derBytes)
}

// load key if it exists or create a new one
func LoadOrMakeKey(path string, rsaBits int) (*rsa.PrivateKey, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if os.IsExist(err) {
			return loadKeyFromFile(path)
		}
		return nil, err
	}
	defer file.Close()

	// write key
	priv, err := newRSAKey(rsaBits)
	if err != nil {
		return nil, err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pemBlock := &pem.Block{
		Type:    rsaPrivateKeyPEMBlockType,
		Headers: nil,
		Bytes:   privBytes,
	}
	if err = pem.Encode(file, pemBlock); err != nil {
		return nil, err
	}
	return priv, nil
}

func LoadKey(path string) (*rsa.PrivateKey, error) {
	return loadKeyFromFile(path)
}

// load a PEM private key from disk
func loadKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

// create a new RSA private key
func newRSAKey(bits int) (*rsa.PrivateKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return private, nil
}
