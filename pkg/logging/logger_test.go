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

package logging_test

import (
	"context"
	"testing"

	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap/zapcore"
)

func Test_InitLogger(t *testing.T) {
	tests := []struct {
		name     string
		inLevel  int
		outLevel zapcore.Level
	}{
		{
			name:     "invalid level leads to info level",
			inLevel:  -2,
			outLevel: zapcore.InfoLevel,
		},
		{
			name:     "debug level",
			inLevel:  -1,
			outLevel: zapcore.DebugLevel,
		},
		{
			name:     "warn level",
			inLevel:  1,
			outLevel: zapcore.WarnLevel,
		},
		{
			name:     "error level",
			inLevel:  2,
			outLevel: zapcore.ErrorLevel,
		},
		{
			name:     "DPanic level",
			inLevel:  3,
			outLevel: zapcore.DPanicLevel,
		},
		{
			name:     "PanicLevel level",
			inLevel:  4,
			outLevel: zapcore.PanicLevel,
		},
		{
			name:     "Fatal level",
			inLevel:  5,
			outLevel: zapcore.FatalLevel,
		},
	}

	for _, test := range tests {
		logging.InitLogger(test.inLevel)

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		if logger.Level() != test.outLevel {
			t.Errorf("Expected %v, got %v", test.outLevel, logger.Level())
		}
	}
}
