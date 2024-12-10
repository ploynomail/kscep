package biz

import "github.com/go-kratos/kratos/v2/log"

type HelloWorldUsecase struct {
	log *log.Helper
}

func NewHelloWorldUsecase(logger log.Logger) *HelloWorldUsecase {
	return &HelloWorldUsecase{
		log: log.NewHelper(log.With(logger, "module", "usecase/helloworld")),
	}
}

func (uc *HelloWorldUsecase) SayHello() string {
	return "Hello World"
}
