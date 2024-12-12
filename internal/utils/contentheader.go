package utils

const (
	CertChainHeader = "application/x-x509-ca-ra-cert"
	LeafHeader      = "application/x-x509-ca-cert"
	PkiOpHeader     = "application/x-pki-message"
)

func ContentHeader(op string, certNum int) string {
	switch op {
	case "GetCACert":
		if certNum > 1 {
			return CertChainHeader
		}
		return LeafHeader
	case "PKIOperation":
		return PkiOpHeader
	default:
		return "text/plain"
	}
}
