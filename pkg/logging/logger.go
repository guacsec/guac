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

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

type loggerKey struct{}

func InitLogger(level int) {
	zapLevel, envVarErr := parseLevel(level)
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

	if envVarErr != nil {
		logger.Info(envVarErr)
	}
	logger.Infof("Logging at %s level", zapLogger.Level())
}

func WithLogger(ctx context.Context) context.Context {
	if logger == nil {
		// defaults to Debug if InitLogger has not been called
		InitLogger(-1)
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

// maps the integer level to a zapcore.Level
// if the input is invalid, the info level is returned
func parseLevel(level int) (zapcore.Level, error) {
	if level < -1 || level > 5 {
		return zapcore.Level(0), fmt.Errorf("The log level %v is not in [-1, 5].", level)
	}
	return zapcore.Level(level), nil
}
