package utils

import (
	"github.com/go-kratos/kratos/v2/log"
	stdzap "go.uber.org/zap"
)

type ScepLogger struct {
	log *log.Helper
}

func (s ScepLogger) Log(o ...interface{}) error {
	s.log.Log(log.LevelDebug, o...)
	return nil
}

func LoggerSCEPWPapper(s *log.Helper) ScepLogger {
	return ScepLogger{
		log: s,
	}
}

type ScepLoggerZap struct {
	log *stdzap.Logger
}

func (s ScepLoggerZap) Log(o ...interface{}) error {
	s.log.Sugar().Debug(o...)
	return nil
}

func LoggerSCEPWapperWithZap(s *stdzap.Logger) ScepLoggerZap {
	return ScepLoggerZap{
		log: s,
	}
}
