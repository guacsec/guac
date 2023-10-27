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

func Test_ParseLevel(t *testing.T) {
	tests := []struct {
		name        string
		inLevel     string
		expected    logging.LogLevel
		expectedErr bool
	}{
		{
			name:        "invalid level",
			inLevel:     "1",
			expectedErr: true,
		},
		{
			name:        "empty level leads to invalid",
			inLevel:     "",
			expectedErr: true,
		},
		{
			name:     "debug level",
			inLevel:  "Debug",
			expected: logging.Debug,
		},
		{
			name:     "warn level",
			inLevel:  "WARN",
			expected: logging.Warn,
		},
		{
			name:     "error level",
			inLevel:  "error",
			expected: logging.Error,
		},
		{
			name:     "DPanic level",
			inLevel:  "dpanic",
			expected: logging.DPanic,
		},
		{
			name:     "PanicLevel level",
			inLevel:  "Panic",
			expected: logging.Panic,
		},
		{
			name:     "Fatal level",
			inLevel:  "fatal",
			expected: logging.Fatal,
		},
	}

	for _, test := range tests {

		res, err := logging.ParseLevel(test.inLevel)
		if test.expectedErr {
			if err == nil {
				t.Error("Expected error but did not get one")
			}
		} else if res != test.expected {
			t.Errorf("Expected %v, got %v", test.expected, res)

		}
	}
}

func Test_InitLogger(t *testing.T) {

	logging.InitLogger(logging.Warn)

	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	if logger.Level() != zapcore.WarnLevel {
		t.Errorf("Expected %v, got %v", zapcore.WarnLevel, logger.Level())
	}
}
