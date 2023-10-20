//
// Copyright 2023 The GUAC Authors.
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

package cli_test

import (
	"context"
	"os"
	"testing"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap/zapcore"
)

var envVar string = "GUAC_LOG_LEVEL"

// tests that InitConfig sets up logging correctly with configuration from an env var
func Test_InitConfig_EnvVarSet(t *testing.T) {
	prevVal := os.Getenv(envVar)
	defer func() { os.Setenv(envVar, prevVal) }()
	os.Setenv(envVar, "-1")

	cli.InitConfig()
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	if logger.Level() != zapcore.DebugLevel {
		t.Errorf("Expected %s, got %s", zapcore.DebugLevel, logger.Level())
	}
}

// tests that InitConfig sets up logging correctly when no env var is set
func Test_InitConfig_EnvVarNotSet(t *testing.T) {
	prevVal := os.Getenv(envVar)
	defer func() { os.Setenv(envVar, prevVal) }()
	os.Unsetenv(envVar)

	cli.InitConfig()
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	if logger.Level() != zapcore.InfoLevel {
		t.Errorf("Expected %s, got %s", zapcore.InfoLevel, logger.Level())
	}
}
