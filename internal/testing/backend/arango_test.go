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

//go:build integration

package backend_test

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/arangodb"
)

type arangoBE struct {
	be   backends.Backend
	args *arangodb.ArangoConfig
}

func newArango() backend {
	return &arangoBE{
		args: &arangodb.ArangoConfig{
			User:   "root",
			Pass:   "test123",
			DBAddr: "http://localhost:8529",
		},
	}
}

func (m *arangoBE) Setup() error {
	if err := arangodb.DeleteDatabase(context.Background(), m.args); err != nil {
		return err
	}
	be, err := backends.Get("arango", context.Background(), m.args)
	m.be = be
	return err
}

func (m *arangoBE) Get() backends.Backend {
	return m.be
}

func (m *arangoBE) Clear() error {
	if err := arangodb.DeleteDatabase(context.Background(), m.args); err != nil {
		return err
	}
	// For some reason, need to call Get again after delete
	be, err := backends.Get("arango", context.Background(), m.args)
	m.be = be
	return err
}

func (m *arangoBE) Cleanup() {
}
