package data

import (
	"crypto/x509"
	"math/big"
)

// Depot is a repository for managing certificates
type Depot interface {
	CA(pass []byte, namePrefix string) ([]*x509.Certificate, interface{}, error)
	Put(name string, crt *x509.Certificate) error
	Serial() (*big.Int, error)
	HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error)
}
