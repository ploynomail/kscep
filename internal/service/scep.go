package service

import (
	"encoding/base64"
	"kscep/internal/biz"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/go-kratos/kratos/v2/log"
)

type SCEPService struct {
	uc  *biz.SCEPUsecase
	log *log.Helper
}

func NewSCEPService(uc *biz.SCEPUsecase, logger log.Logger) *SCEPService {
	return &SCEPService{
		uc:  uc,
		log: log.NewHelper(log.With(logger, "module", "service/scep")),
	}
}

func (sc *SCEPService) RegisterServiceRouter(r *gin.RouterGroup) {
	groupGroupRouter := r.Group("/scep")
	{
		groupGroupRouter.GET("", sc.scep)
		groupGroupRouter.POST("", sc.sceppost)
	}
}

// 如果 CA支持.则除GetCACert、GetNextCACert 或GetCACaps 之外，其他 SCEP 消息都可以不通过HTTP GET,
// 而通过 HTTP POST发送。在这种形式的消息中，不使用base64 编码。

func (s *SCEPService) scep(c *gin.Context) {
	var req biz.SCEPRequest
	var resp biz.SCEPResponse = biz.SCEPResponse{Operation: req.Operation}
	req.Operation = c.Query(SCEPOptQuery)
	if req.Operation == "" {
		resp.Err = biz.ErrMissingOperation
		ClientError(resp.Err, c)
		return
	}
	msg := c.Query(SCEPMsgQuery)
	if msg == "" && req.Operation != biz.GetCACert {
		resp.Err = biz.ErrMissingMessage
		ClientError(resp.Err, c)
		return
	}
	if req.Operation == biz.GetCACaps && msg != biz.CAIDENTIFIER {
		resp.Err = biz.ErrDepotConfig
		ClientError(resp.Err, c)
		return
	}
	if req.Operation == biz.PkiOperation {
		msg2, err := url.PathUnescape(msg)
		if err != nil {
			resp.Err = err
			ClientError(resp.Err, c)
			return
		}
		req.Message, err = base64.StdEncoding.DecodeString(msg2)
		if err != nil {
			resp.Err = err
			ClientError(resp.Err, c)
			return
		}
	} else {
		req.Message = []byte(msg)
	}
	switch req.Operation {
	case biz.GetCACaps:
		resp.Data, resp.Err = s.uc.GetCACaps(c)
	case biz.GetCACert:
		resp.Data, resp.CACertNum, resp.Err = s.uc.GetCACert(c, string(req.Message))
	case biz.PkiOperation:
		resp.Data, resp.Err = s.uc.PKIOperation(c, req.Message)
	case biz.GetNextCACert:
		resp.Data, resp.Err = s.uc.GetNextCACert(c)
	default:
		resp.Err = biz.ErrUnsupportedOperation
	}
	if resp.Err != nil {
		ClientError(resp.Err, c)
		return
	}
	Ok(resp, c)
}

func (s *SCEPService) sceppost(c *gin.Context) {
	var req biz.SCEPRequest
	var resp biz.SCEPResponse = biz.SCEPResponse{Operation: req.Operation}
	req.Operation = c.Query(SCEPOptQuery)
	if req.Operation == "" {
		resp.Err = biz.ErrMissingOperation
		ClientError(resp.Err, c)
		s.log.Error("Missing Operation Err")
		return
	}

	if req.Operation == biz.PkiOperation {
		req.Message = make([]byte, c.Request.ContentLength)
		_, err := c.Request.Body.Read(req.Message)
		if err != nil && err.Error() != "EOF" {
			resp.Err = err
			s.log.Error("Read request body error", err)
			ClientError(resp.Err, c)
			return
		}
	} else {
		s.log.Error("Unsupported Operation Err")
		ClientError(biz.ErrUnsupportedOperation, c)
		return
	}

	switch req.Operation {
	case biz.PkiOperation:
		resp.Data, resp.Err = s.uc.PKIOperation(c, req.Message)
	default:
		resp.Err = biz.ErrUnsupportedOperation
		s.log.Error("Unsupported Operation Err")
		ClientError(resp.Err, c)
		return
	}
	Ok(resp, c)
}
