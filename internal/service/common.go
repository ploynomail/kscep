package service

import (
	"kscep/internal/biz"
	"kscep/internal/utils"

	"github.com/gin-gonic/gin"
)

func Result(statusCode int, resp biz.SCEPResponse, c *gin.Context) {
	c.Writer.Header().Set("Content-Type", utils.ContentHeader(resp.Operation, resp.CACertNum))
	c.Writer.WriteHeader(statusCode)
	c.Writer.Write(resp.Data)
}

func ResultErr(statusCode int, resp biz.SCEPResponse, c *gin.Context) {
	c.Writer.Header().Set("Content-Type", utils.ContentHeader(resp.Operation, resp.CACertNum))
	c.Writer.WriteHeader(statusCode)
	c.Writer.Write([]byte(resp.Err.Error()))
	c.Abort()
}

func ServerInternalError(err error, c *gin.Context) {
	ResultErr(500, biz.SCEPResponse{Err: err}, c)
}

func ClientError(err error, c *gin.Context) {
	ResultErr(400, biz.SCEPResponse{Err: err}, c)
}

func Ok(resp biz.SCEPResponse, c *gin.Context) {
	Result(200, resp, c)
}
