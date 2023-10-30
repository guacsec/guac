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

package testutils

import (
	"context"
	"database/sql"
	"log"
	"os"

	"github.com/DATA-DOG/go-txdb"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/enttest"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/suite"

	dsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"

	// Import regular postgres driver
	_ "github.com/lib/pq"
)

func init() {
	db := os.Getenv("ENT_TEST_DATABASE_URL")
	if db == "" {
		db = "postgresql://localhost/guac_test?sslmode=disable"
	}

	txdb.Register("txdb", "postgres", db)
	err := os.Setenv("MAX_CONCURRENT_BULK_INGESTION", "1")
	if err != nil {
		log.Fatal(err)
	}
}

type Suite struct {
	suite.Suite
	Ctx         context.Context
	Client      *ent.Client
	db          *sql.DB
	beforeHooks []func(suiteName, testName string)
	afterHooks  []func()
}

func TestSuite() *Suite {
	return &Suite{}
}

func (s *Suite) Run(testName string, tf func()) {
	_, err := s.db.Exec("SAVEPOINT savepoint1")
	if err != nil {
		log.Fatal(err)
	}
	defer func(db *sql.DB, query string, args ...any) {
		_, err := db.Exec(query, args...)
		if err != nil {
			log.Fatal(err)
		}
	}(s.db, "ROLLBACK TO SAVEPOINT savepoint1")
	s.Suite.Run(testName, tf)
}

func (s *Suite) BeforeEach(fn func(suiteName, testName string)) {
	s.beforeHooks = append(s.beforeHooks, fn)
}

func (s *Suite) AfterEach(fn func()) {
	s.afterHooks = append(s.afterHooks, fn)
}

func (s *Suite) BeforeTest(suiteName, testName string) {
	ctx := context.Background()
	ident := ksuid.New().String()
	db, err := sql.Open("txdb", ident)
	if err != nil {
		log.Fatal(err)
	}
	s.db = db
	entSqlDriver := dsql.OpenDB("postgres", db)
	// enttest automatically runs migrations to create the schema in the test database.
	client := enttest.NewClient(s.T(),
		enttest.WithOptions(ent.Driver(entSqlDriver)),
		enttest.WithMigrateOptions(
			schema.WithGlobalUniqueID(true),
		),
	)
	s.Client = client

	// Populate context with ent client so that transactions work
	ctx = ent.NewContext(ctx, s.Client)
	s.Ctx = ctx

	for _, fn := range s.beforeHooks {
		fn(suiteName, testName)
	}
}

func (s *Suite) AfterTest(suiteName, testName string) {
	s.Client.Close()
}

var _ suite.BeforeTest = (*Suite)(nil)
var _ suite.AfterTest = (*Suite)(nil)
