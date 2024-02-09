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

	"github.com/guacsec/guac/pkg/assembler/backends"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	tikvstore "github.com/guacsec/guac/pkg/assembler/kv/tikv"
	"github.com/tikv/client-go/v2/config"
	"github.com/tikv/client-go/v2/rawkv"
)

type tikvBE struct {
	be      backends.Backend
	connStr string
	c       *rawkv.Client
}

func newTikv() backend {
	return &tikvBE{
		connStr: "127.0.0.1:2379",
	}
}

func (m *tikvBE) Setup() error {
	ctx := context.Background()
	c, err := rawkv.NewClient(ctx, []string{m.connStr}, config.Security{})
	if err != nil {
		return err
	}
	m.c = c
	if err := m.c.DeleteRange(ctx, []byte{0}, []byte{255, 255, 255, 255}); err != nil {
		return err
	}
	store, err := tikvstore.GetStore(ctx, m.connStr)
	if err != nil {
		return err
	}
	be, err := backends.Get("keyvalue", nil, store)
	m.be = be
	return err
}

func (m *tikvBE) Get() backends.Backend {
	return m.be
}

func (m *tikvBE) Clear() error {
	return m.c.DeleteRange(context.Background(), []byte{0}, []byte{255, 255, 255, 255})
}

func (m *tikvBE) Cleanup() {
	m.c.Close()
}
