package service

import (
	"kscep/internal/biz"

	"github.com/gin-gonic/gin"
	"github.com/go-kratos/kratos/v2/log"
)

type HelloWorldService struct {
	uc  *biz.HelloWorldUsecase
	log *log.Helper
}

func NewHelloWorldService(uc *biz.HelloWorldUsecase, logger log.Logger) *HelloWorldService {
	return &HelloWorldService{
		uc:  uc,
		log: log.NewHelper(log.With(logger, "module", "service/helloworld")),
	}
}

func (as *HelloWorldService) RegisterServiceRouter(r *gin.RouterGroup) {
	groupGroupRouter := r.Group("/group")
	{
		groupGroupRouter.GET("/hw", as.SayHello)
	}
}

func (s *HelloWorldService) SayHello(c *gin.Context) {
	res := s.uc.SayHello()
	s.log.Info("SayHello", res)
	c.JSON(200, res)
}
