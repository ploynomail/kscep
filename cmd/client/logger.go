package main

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

func InitializeLogger(fmt string) {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:    "time",
		LevelKey:   "level",
		NameKey:    "logger",
		CallerKey:  "caller",
		MessageKey: "msg",
		// StacktraceKey: "stacktrace",
		LineEnding: zapcore.DefaultLineEnding,
		//EncodeLevel:    zapcore.LowercaseLevelEncoder,  // 小写编码器
		EncodeLevel:    zapcore.CapitalColorLevelEncoder, //这里可以指定颜色
		EncodeTime:     zapcore.ISO8601TimeEncoder,       // ISO8601 UTC 时间格式
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.FullCallerEncoder, // error code location
	}
	if errTrace {
		encoderConfig.StacktraceKey = "stacktrace"
	}
	var encoder = "console"
	if fmt == "json" {
		encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
		encoder = "json"
	}
	// 设置日志级别
	atom := zap.NewAtomicLevelAt(zap.DebugLevel)
	config := zap.Config{
		Level:            atom,                                                  // 日志级别
		Development:      true,                                                  // 开发模式，堆栈跟踪
		Encoding:         encoder,                                               // 输出格式 console 或 json
		EncoderConfig:    encoderConfig,                                         // 编码器配置
		InitialFields:    map[string]interface{}{"service name": "scep client"}, // 初始化字段，如：添加一个服务器名称
		OutputPaths:      []string{"stdout"},                                    // 输出到指定文件 stdout（标准输出，正常颜色） stderr（错误输出，红色）
		ErrorOutputPaths: []string{"stderr"},
	}
	var err error
	logger, err = config.Build()
	if err != nil {
		panic("log init failed")
	}
}
