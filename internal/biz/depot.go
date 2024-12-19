package biz

import (
	"crypto/x509"
	"math/big"
)

// Depot is a repository for managing certificates
type DepotRepo interface {
	CA(pass []byte, namePrefix string) ([]*x509.Certificate, interface{}, error)
	Put(name string, crt *x509.Certificate) error
	Serial() (*big.Int, error)
	HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error)
	Get(issuer, serial string) (*x509.Certificate, error)
}
