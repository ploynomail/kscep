package client

import (
	"bytes"
	"context"
	"kscep/internal/biz"
	"net/url"
	"strings"
	"sync"

	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	"go.uber.org/zap"
)

type Endpoints struct {
	GetEndpoint  endpoint.Endpoint
	PostEndpoint endpoint.Endpoint

	mtx          sync.RWMutex
	capabilities []byte
	log          *zap.Logger
}

// New creates a SCEP Client.
func NewClient(serverURL string, logger *zap.Logger) (*Endpoints, error) {
	endpoints, err := MakeClientEndpoints(serverURL)
	if err != nil {
		return nil, err
	}
	endpoints.log = logger
	return endpoints, nil
}

func (e *Endpoints) GetCACaps(ctx context.Context) ([]byte, error) {
	request := biz.SCEPRequest{Operation: biz.GetCACaps}
	response, err := e.GetEndpoint(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(biz.SCEPResponse)

	e.mtx.Lock()
	e.capabilities = resp.Data
	e.mtx.Unlock()
	return resp.Data, resp.Err
}

func (e *Endpoints) Supports(cap string) bool {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	if len(e.capabilities) == 0 {
		e.mtx.RUnlock()
		e.GetCACaps(context.Background())
		e.mtx.RLock()
	}
	return bytes.Contains(e.capabilities, []byte(cap))
}

func (e *Endpoints) GetCACert(ctx context.Context, message string) ([]byte, int, error) {
	request := biz.SCEPRequest{Operation: biz.GetCACert, Message: []byte(message)}
	response, err := e.GetEndpoint(ctx, request)
	if err != nil {
		return nil, 0, err
	}
	resp := response.(biz.SCEPResponse)
	return resp.Data, resp.CACertNum, resp.Err
}

func (e *Endpoints) PKIOperation(ctx context.Context, msg []byte) ([]byte, error) {
	var ee endpoint.Endpoint
	// TODO: This is a bit of a hack. We should have a better way to determine
	if e.Supports(biz.POSTPKIOperation) || e.Supports(biz.SCEPStandard) {
		ee = e.PostEndpoint
	} else {
		ee = e.GetEndpoint
	}

	request := biz.SCEPRequest{Operation: biz.PkiOperation, Message: msg}
	response, err := ee(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(biz.SCEPResponse)
	return resp.Data, resp.Err
}

func (e *Endpoints) GetNextCACert(ctx context.Context) ([]byte, error) {
	var request biz.SCEPRequest
	response, err := e.GetEndpoint(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(biz.SCEPResponse)
	return resp.Data, resp.Err
}

// MakeClientEndpoints returns an Endpoints struct where each endpoint invokes
// the corresponding method on the remote instance, via a transport/http.Client.
// Useful in a SCEP client.
func MakeClientEndpoints(instance string) (*Endpoints, error) {
	if !strings.HasPrefix(instance, "http") {
		instance = "http://" + instance
	}
	tgt, err := url.Parse(instance)
	if err != nil {
		return nil, err
	}

	options := []httptransport.ClientOption{}

	return &Endpoints{
		GetEndpoint: httptransport.NewClient(
			"GET",
			tgt,
			EncodeSCEPRequest,
			DecodeSCEPResponse,
			options...).Endpoint(),
		PostEndpoint: httptransport.NewClient(
			"POST",
			tgt,
			EncodeSCEPRequest,
			DecodeSCEPResponse,
			options...).Endpoint(),
	}, nil
}
