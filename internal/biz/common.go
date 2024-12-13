package biz

import "errors"

const MaxPayloadSize = 2 << 20 // 2MB

var DefaultCaps = []byte("Renewal\nSHA-1\nSHA-256\nAES\nDES3\nSCEPStandard\nPOSTPKIOperation")
var GBT0089Caps = []byte("Renewal\nGetNextCACert\nPOSTPKIOperation\nSM3\nSM4")

var (
	SupportedCaTypes = []string{"RSA", "ECC", "SM2", ""}

	ErrUnsupportedCaType      = errors.New("unsupported CA type")
	ErrMissingCaCert          = errors.New("missing CA certificate")
	ErrUnsupportedOperation   = errors.New("unsupported operation")
	ErrMissingOperation       = errors.New("missing operation")
	ErrMissingMessage         = errors.New("missing message")
	ErrDepotConfig            = errors.New("depot config error")
	ErrUnsupportedMessageType = errors.New("unsupported message type")
)

type CaType int

const (
	RsaCa CaType = iota
	EccCa
	SM2Ca
)

// possible SCEP operations
const (
	GetCACaps     = "GetCACaps"
	GetCACert     = "GetCACert"
	PkiOperation  = "PKIOperation"
	GetNextCACert = "GetNextCACert"
)

const (
	CAIDENTIFIER = "CA-IDENT"
)

const (
	POSTPKIOperation = "POSTPKIOperation"
	SCEPStandard     = "SCEPStandard"
)

func (c CaType) String() string {
	switch c {
	case RsaCa:
		return "RSA"
	case EccCa:
		return "ECC"
	case SM2Ca:
		return "SM2"
	default:
		return "RSA"
	}
}

func GetCaType(t string) CaType {
	switch t {
	case "RSA":
		return RsaCa
	case "ECC":
		return EccCa
	case "SM2":
		return SM2Ca
	default:
		return RsaCa
	}
}
