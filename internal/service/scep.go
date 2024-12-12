package service

import (
	"encoding/base64"
	"fmt"
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
	req.Operation = c.Query("operation")
	if req.Operation == "" {
		resp.Err = biz.MissingOperationErr
		ClientError(resp.Err, c)
		return
	}
	msg := c.Query("message")
	if msg == "" && (req.Operation != "GetCACaps" && req.Operation != "GetCACert") {
		resp.Err = biz.MissingMessageErr
		ClientError(resp.Err, c)
		return
	}
	if req.Operation == "PKIOperation" {
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
	case "GetCACaps":
		resp.Data, resp.Err = s.uc.GetCACaps(c)
	case "GetCACert":
		resp.Data, resp.CACertNum, resp.Err = s.uc.GetCACert(c, string(req.Message))
	case "PKIOperation":
		resp.Data, resp.Err = s.uc.PKIOperation(c, req.Message)
	case "GetNextCACert":
		resp.Data, resp.Err = s.uc.GetNextCACert(c)
	default:
		resp.Err = biz.UnsupportedOperationErr
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
	req.Operation = c.Query("operation")
	if req.Operation == "" {
		resp.Err = biz.MissingOperationErr
		ClientError(resp.Err, c)
		s.log.Error("MissingOperationErr")
		return
	}

	if req.Operation == "PKIOperation" {
		req.Message = make([]byte, c.Request.ContentLength)
		_, err := c.Request.Body.Read(req.Message)
		if err != nil && err.Error() != "EOF" {
			resp.Err = err
			s.log.Error("Read request body error", err)
			ClientError(resp.Err, c)
			return
		}
	} else {
		s.log.Error("UnsupportedOperationErr")
		ClientError(biz.UnsupportedOperationErr, c)
		return
	}

	switch req.Operation {
	case "PKIOperation":
		resp.Data, resp.Err = s.uc.PKIOperation(c, req.Message)
	default:
		resp.Err = biz.UnsupportedOperationErr
		s.log.Error("UnsupportedOperationErr")
		ClientError(resp.Err, c)
		return
	}
	fmt.Println("resp:", len(resp.Data))
	Ok(resp, c)
}
