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

	"entgo.io/ent/dialect"
	dialectsql "entgo.io/ent/dialect/sql"
	"github.com/XSAM/otelsql"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hook"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/migrate"
	"github.com/guacsec/guac/pkg/logging"
)

type BackendOptions struct {
	DriverName  string
	Address     string
	Debug       bool
	AutoMigrate bool
	// sets the maximum amount of time a connection may be reused.
	// If nil, this is set to default of 0
	ConnectionMaxLifeTime *time.Duration
}

// GetReadOnlyClient sets up the ent backend and returns a read-only client.
func GetReadOnlyClient(ctx context.Context, options *BackendOptions) (*ent.Client, error) {
	client, err := SetupBackend(ctx, options)
	if err != nil {
		return nil, err
	}
	// https://entgo.io/docs/hooks/#mutation
	client.Use(hook.Reject(
		ent.OpCreate | ent.OpUpdate | ent.OpUpdateOne | ent.OpDelete | ent.OpDeleteOne,
	))
	return client, nil
}

// SetupBackend sets up the ent backend, preparing the database and returning a client
func SetupBackend(ctx context.Context, options *BackendOptions) (*ent.Client, error) {
	logger := logging.FromContext(ctx)

	driver := dialect.Postgres
	if options.DriverName != "" {
		driver = options.DriverName
	}

	if driver != dialect.Postgres {
		// TODO: Passively import preferred driver packages for MySQL and Sqlite
		return nil, fmt.Errorf("only postgres is supported at this time")
	}

	db, err := otelsql.Open(driver, options.Address)
	if err != nil {
		return nil, fmt.Errorf("error opening db: %w", err)
	}
	if _, err := otelsql.RegisterDBStatsMetrics(db); err != nil {
		return nil, fmt.Errorf("error registering db metrics: %w", err)
	}

	if options.ConnectionMaxLifeTime != nil {
		// set timeout limit for connections
		db.SetConnMaxLifetime(*options.ConnectionMaxLifeTime)
	}

	client := ent.NewClient(ent.Driver(dialectsql.OpenDB(driver, db)))

	if options.AutoMigrate {
		// Run db migrations
		err = client.Schema.Create(
			ctx,
			migrate.WithGlobalUniqueID(true),
			migrate.WithDropIndex(true),
			migrate.WithDropColumn(true),
		)
		if err != nil {
			return nil, fmt.Errorf("error creating ent schema: %w", err)
		}

		logger.Infof("ent migrations complete")
	} else {
		logger.Infof("skipping ent migrations")
	}

	return client, nil
}
