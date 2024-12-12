package server

import (
	"kscep/internal/conf"
	"kscep/internal/service"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport/http"
)

// NewGinhttpServer new an Gin HTTP server.
func NewGinhttpServer(c *conf.Server,
	logger log.Logger,
	hwService *service.HelloWorldService,
	secpSerivce *service.SCEPService,
) *http.Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(GinLogger(logger))
	// 路由版本
	apiv1 := router.Group("/api/v1")
	{
		hwService.RegisterServiceRouter(apiv1)
		secpSerivce.RegisterServiceRouter(apiv1)
	}
	httpSrv := http.NewServer(
		http.Address(c.Http.Addr),
		http.Timeout(c.Http.Timeout.AsDuration()),
	)
	httpSrv.HandlePrefix("/", router)
	return httpSrv
}

func GinLogger(logger log.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		c.Next()

		cost := time.Since(start)
		log := log.NewHelper(logger)
		// 记录请求日志
		log.Infof("path: %s, query: %s, ip: %s, cost: %v", path, query, c.ClientIP(), cost)
	}
}
