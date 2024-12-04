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

package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vektah/gqlparser/v2/gqlerror"

	// Import regular postgres driver
	_ "github.com/lib/pq"
)

const (
	// Batch size for ingesting in bulk. Increasing this could results in "PostgreSQL only supports 65535 parameters" error
	MaxBatchSize = 5000
)

var Errorf = gqlerror.Errorf

type EntBackend struct {
	client *ent.Client
}

// flags holds the command-line flags for Ent configuration
var flags = struct {
	dbAddress  string
	dbDriver   string
	dbDebug    bool
	dbMigrate  bool
	dbConnTime string
}{}

// registerFlags registers Ent-specific command line flags
func registerFlags(cmd *cobra.Command) error {
	flagSet := cmd.Flags()
	flagSet.StringVar(&flags.dbAddress, "db-address", "postgres://guac:guac@0.0.0.0:5432/guac?sslmode=disable", "Full URL of database to connect to")
	flagSet.StringVar(&flags.dbDriver, "db-driver", "postgres", "database driver to use, one of [postgres | sqlite3 | mysql] or anything supported by sql.DB")
	flagSet.BoolVar(&flags.dbDebug, "db-debug", false, "enable debug logging for database queries")
	flagSet.BoolVar(&flags.dbMigrate, "db-migrate", true, "automatically run database migrations on start")
	flagSet.StringVar(&flags.dbConnTime, "db-conn-time", "", "sets the maximum amount of time a connection may be reused in m, h, s, etc.")

	if err := viper.BindPFlags(flagSet); err != nil {
		return fmt.Errorf("failed to bind flags: %w", err)
	}

	return nil
}

// parseFlags returns the Ent configuration from parsed flags
func parseFlags(ctx context.Context) (backends.BackendArgs, error) {
	var connTimeout *time.Duration
	if flags.dbConnTime != "" {
		if timeout, err := time.ParseDuration(flags.dbConnTime); err == nil {
			connTimeout = &timeout
		} else {
			return nil, fmt.Errorf("failed to parse duration with error: %w", err)
		}
	}
	return &BackendOptions{
		DriverName:            flags.dbDriver,
		Address:               flags.dbAddress,
		Debug:                 flags.dbDebug,
		AutoMigrate:           flags.dbMigrate,
		ConnectionMaxLifeTime: connTimeout,
	}, nil
}

func getBackend(ctx context.Context, args backends.BackendArgs) (backends.Backend, error) {
	config, ok := args.(*BackendOptions)
	if !ok {
		return nil, fmt.Errorf("failed to get ent config from backend args")
	}
	client, err := SetupBackend(ctx, config)
	if err != nil {
		return nil, err
	}
	return GetBackend(client)
}

func GetBackend(client *ent.Client) (backends.Backend, error) {
	if client == nil {
		return nil, fmt.Errorf("invalid args: client is required, got nil")
	}

	be := &EntBackend{}
	err := client.Ping(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to ping db: %w", err)
	}

	be.client = client

	return be, nil
}
