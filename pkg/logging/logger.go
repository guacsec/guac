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
	"os"

	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

type loggerKey struct{}

func init() {
	var zapLogger *zap.Logger
	env := os.Getenv("ENVIRONMENT")

	if env == "production" {
		zapLogger, _ = zap.NewProduction(zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	} else {
		zapLogger, _ = zap.NewDevelopment(zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	}

	// flushes buffer, if any
	defer func() {
		// intentionally ignoring error here, see https://github.com/uber-go/zap/issues/328
		_ = zapLogger.Sync()
	}()

	logger = zapLogger.Sugar()
}

func WithLogger(ctx context.Context) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

func FromContext(ctx context.Context) *zap.SugaredLogger {
	if logger, ok := ctx.Value(loggerKey{}).(*zap.SugaredLogger); ok {
		return logger
	}

	return zap.NewNop().Sugar()
}
