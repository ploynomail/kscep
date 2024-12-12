package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"kscep/internal/biz"
	"kscep/internal/utils"
	"net/http"

	"github.com/pkg/errors"
)

// EncodeSCEPRequest encodes a SCEP HTTP Request. Used by the client.
func EncodeSCEPRequest(ctx context.Context, r *http.Request, request interface{}) error {
	req := request.(biz.SCEPRequest)
	params := r.URL.Query()
	params.Set("operation", req.Operation)
	switch r.Method {
	case "GET":
		if len(req.Message) > 0 {
			var msg string
			if req.Operation == "PKIOperation" {
				msg = base64.URLEncoding.EncodeToString(req.Message)
			} else {
				msg = string(req.Message)
			}
			params.Set("message", msg)
		}
		r.URL.RawQuery = params.Encode()
		return nil
	case "POST":
		body := bytes.NewReader(req.Message)
		// recreate the request here because IIS does not support chunked encoding by default
		// and Go doesn't appear to set Content-Length if we use an io.ReadCloser
		u := r.URL
		u.RawQuery = params.Encode()
		rr, err := http.NewRequest("POST", u.String(), body)
		rr.Header.Set("Content-Type", "application/octet-stream")
		if err != nil {
			return errors.Wrapf(err, "creating new POST request for %s", req.Operation)
		}
		*r = *rr
		return nil
	default:
		return fmt.Errorf("scep: %s method not supported", r.Method)
	}
}

// DecodeSCEPResponse decodes a SCEP response
func DecodeSCEPResponse(ctx context.Context, r *http.Response) (interface{}, error) {
	if r.StatusCode != http.StatusOK && r.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(io.LimitReader(r.Body, 4096))
		return nil, fmt.Errorf("http request failed with status %s, msg: %s",
			r.Status,
			string(body),
		)
	}
	data, err := ioutil.ReadAll(io.LimitReader(r.Body, biz.MaxPayloadSize))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	resp := biz.SCEPResponse{
		Data: data,
	}
	header := r.Header.Get("Content-Type")
	if header == utils.CertChainHeader {
		// we only set it to two to indicate a cert chain.
		// the actual number of certs will be in the payload.
		resp.CACertNum = 2
	}
	return resp, nil
}
