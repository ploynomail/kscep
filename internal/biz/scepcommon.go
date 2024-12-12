package biz

// SCEPRequest is a SCEP server request.
type SCEPRequest struct {
	Operation string `form:"operation" json:"operation"`
	Message   []byte `form:"message" json:"message"`
}

func (r SCEPRequest) scepOperation() string {
	return r.Operation
}

// SCEPResponse is a SCEP server response.
// Business errors will be encoded as a CertRep message
// with pkiStatus FAILURE and a failInfo attribute.
type SCEPResponse struct {
	Operation string
	CACertNum int
	Data      []byte
	Err       error
}

func (r SCEPResponse) scepOperation() string {
	return r.Operation
}
