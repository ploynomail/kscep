package utils

import "github.com/go-kratos/kratos/v2/log"

type ScepLogger struct {
	log *log.Helper
}

func (s ScepLogger) Log(o ...interface{}) error {
	s.log.Log(log.LevelDebug, o...)
	return nil
}

func LoggerWapper(s *log.Helper) ScepLogger {
	return ScepLogger{
		log: s,
	}
}
