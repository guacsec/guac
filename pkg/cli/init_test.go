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
