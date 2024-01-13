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

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func InitConfig() {
	home, err := homedir.Dir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get user home directory: %v\n", err)
		os.Exit(1)
	}

	viper.AddConfigPath(home)
	viper.AddConfigPath(".")
	viper.SetConfigName("guac")
	viper.SetConfigType("yaml")

	viper.AutomaticEnv()
	viper.SetEnvPrefix("guac")
	// The following line is needed to replace - with _ in env variables
	// e.g. GUAC_DB_ADDR will be read as GUAC_gdbaddr
	// The POSIX standard does not allow - in env variables
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	err = viper.ReadInConfig()

	viper.SetDefault("log-level", string(logging.Info))

	// initialize logging after reading in the config
	level, logErr := logging.ParseLevel(viper.GetString(ConfigLogLevelVar))
	if logErr != nil {
		level = logging.Info
	}
	logging.InitLogger(level)

	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)
	if logErr != nil {
		logger.Infof("Error setting up logging: %v", logErr)
	}
	if err == nil {
		logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
}

// SetupPrometheus sets up the prometheus server
func SetupPrometheus(ctx context.Context, logger *zap.SugaredLogger, name string) error {
	if name == "" {
		return errors.New("name cannot be empty")
	}
	m := metrics.FromContext(ctx, name)
	enablePrometheus := viper.GetBool("enable-prometheus")
	prometheusPort := viper.GetInt("prometheus-addr")
	if !enablePrometheus {
		return nil
	}

	go func() {
		http.Handle("/metrics", m.MetricsHandler())
		logger.Infof("Prometheus server is listening on: %d", prometheusPort)
		server := &http.Server{Addr: fmt.Sprintf(":%d", prometheusPort)}

		// Start server in a goroutine so that it doesn't block
		go func() {
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatalf("Error starting HTTP server: %v", err)
			}
		}()

		// Listen for the cancellation signal
		<-ctx.Done()

		// Shutdown the server when cancellation signal is received
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Errorf("Error shutting down server: %v", err)
		}
	}()
	return nil
}
