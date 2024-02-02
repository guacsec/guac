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

package backend_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/guacsec/guac/pkg/assembler/backends"
	entbackend "github.com/guacsec/guac/pkg/assembler/backends/ent/backend"
	"github.com/segmentio/ksuid"
)

type entBE struct {
	be        backends.Backend
	urlString string
	topSQL    *sql.DB
	topURL    *url.URL
}

func newEnt() backend {
	return &entBE{
		urlString: "postgres://guac:guac@localhost/guac?sslmode=disable",
	}
}

func (m *entBE) Setup() error {
	db, err := sql.Open("postgres", m.urlString)
	if err != nil {
		return err
	}
	m.topSQL = db
	u, err := url.Parse(m.urlString)
	if err != nil {
		return err
	}
	m.topURL = u

	return m.setupNewDB()
}

func (m *entBE) Get() backends.Backend {
	return m.be
}

func (m *entBE) Clear() error {
	return m.setupNewDB()
}

func (m *entBE) Cleanup() {
	m.topSQL.Close()
}

func (m *entBE) setupNewDB() error {
	ctx := context.Background()
	ident := ksuid.New().String()
	_, err := m.topSQL.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE \"%v\"", ident))
	if err != nil {
		return err
	}
	testURL := *m.topURL
	testURL.Path = ident
	opts := &entbackend.BackendOptions{
		DriverName:  "postgres",
		Address:     testURL.String(),
		Debug:       false,
		AutoMigrate: true,
	}
	be, err := backends.Get("ent", ctx, opts)
	m.be = be
	return err
}
