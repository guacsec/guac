//
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logging

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

type LogLevel string

const (
	Debug  LogLevel = "debug"
	Info   LogLevel = "info"
	Warn   LogLevel = "warn"
	Error  LogLevel = "error"
	DPanic LogLevel = "dpanic"
	Panic  LogLevel = "panic"
	Fatal  LogLevel = "fatal"
)

type loggerKey struct{}

// Initializes the logger with the input level, defaulting to Info if the input is invalid
func InitLogger(level LogLevel) {
	zapLevel, levelErr := zapcore.ParseLevel(string(level))
	if levelErr != nil {
		zapLevel = zapcore.InfoLevel
	}

	var zapLogger *zap.Logger
	if zapLevel == zapcore.DebugLevel {
		zapLogger = zap.Must(zap.NewDevelopment())
	} else {
		config := zap.NewProductionConfig()
		config.Level.SetLevel(zapLevel)
		zapLogger = zap.Must(config.Build())
	}

	// flushes buffer, if any
	defer func() {
		// intentionally ignoring error here, see https://github.com/uber-go/zap/issues/328
		_ = zapLogger.Sync()
	}()

	logger = zapLogger.Sugar()

	if levelErr != nil {
		logger.Infof("Invalid log level %s: ", level, levelErr)
	}
	logger.Infof("Logging at %s level", zapLogger.Level())
}

// convert a string to the LogLevel type
func ParseLevel(level string) (LogLevel, error) {
	switch strings.ToLower(level) {
	case "debug":
		return Debug, nil
	case "info":
		return Info, nil
	case "warn":
		return Warn, nil
	case "error":
		return Error, nil
	case "dpanic":
		return DPanic, nil
	case "panic":
		return Panic, nil
	case "fatal":
		return Fatal, nil
	default:
		return Info, fmt.Errorf("%s is not a valid level", level)
	}
}

func WithLogger(ctx context.Context) context.Context {
	if logger == nil {
		// defaults to Debug if InitLogger has not been called.
		// all cli commands should call InitLogger, so this should mostly be for unit tests
		InitLogger(Debug)
		logger.Debugf("InitLogger has not been called. Defaulting to debug log level")
	}
	return context.WithValue(ctx, loggerKey{}, logger)
}

func FromContext(ctx context.Context) *zap.SugaredLogger {
	if logger, ok := ctx.Value(loggerKey{}).(*zap.SugaredLogger); ok {
		return logger
	}

	return zap.NewNop().Sugar()
}
