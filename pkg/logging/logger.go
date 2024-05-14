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

	"github.com/guacsec/guac/pkg/version"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

type (
	LogLevel   string
	contextKey string
)

const (
	Debug          LogLevel   = "debug"
	Info           LogLevel   = "info"
	Warn           LogLevel   = "warn"
	Error          LogLevel   = "error"
	DPanic         LogLevel   = "dpanic"
	Panic          LogLevel   = "panic"
	Fatal          LogLevel   = "fatal"
	ChildLoggerKey contextKey = "childLogger"
	DocumentHash              = "documentHash"
	guacVersion               = "guac-version"
)

type loggerKey struct{}

// Initializes the logger with the input level, defaulting to Info if the input is invalid
func InitLogger(level LogLevel, opts ...zap.Option) {
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

	logger = zapLogger.Sugar().With(guacVersion, version.Version).WithOptions(opts...)

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

// Attaches the logger to the input context, optionally adding a number of fields
// to the logging context. The fields should be key-value pairs.
func WithLogger(ctx context.Context, fields ...interface{}) context.Context {
	if logger == nil {
		// defaults to Debug if InitLogger has not been called.
		// all cli commands should call InitLogger, so this should mostly be for unit tests
		InitLogger(Debug)
		logger.Debugf("InitLogger has not been called. Defaulting to debug log level")
	}
	if len(fields) > 0 {
		return context.WithValue(ctx, loggerKey{}, logger.With(fields...))
	}
	return context.WithValue(ctx, loggerKey{}, logger)

}

func FromContext(ctx context.Context) *zap.SugaredLogger {
	// First, try to retrieve the childLogger from the context as to avoid breaking the default logger
	if childLogger, ok := ctx.Value(ChildLoggerKey).(*zap.SugaredLogger); ok {
		return childLogger
	}
	// Fallback to the existing behavior if the childLogger is not found
	if logger, ok := ctx.Value(loggerKey{}).(*zap.SugaredLogger); ok {
		return logger
	}

	return zap.NewNop().Sugar()
}

func SetLogger(l *zap.Logger) {
	logger = l.Sugar()
}
