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
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	redisstore "github.com/guacsec/guac/pkg/assembler/kv/redis"
	redislib "github.com/redis/go-redis/v9"
)

type redisBE struct {
	be      backends.Backend
	connStr string
	c       *redislib.Client
}

func newRedis() backend {
	return &redisBE{
		connStr: "redis://user@localhost:6379/0",
	}
}

func (m *redisBE) Setup() error {
	opt, err := redislib.ParseURL(m.connStr)
	if err != nil {
		return err
	}
	m.c = redislib.NewClient(opt)
	if err := m.c.FlushDB(context.Background()).Err(); err != nil {
		return err
	}
	store, err := redisstore.GetStore(m.connStr)
	if err != nil {
		return err
	}
	be, err := backends.Get("keyvalue", nil, store)
	m.be = be
	return err
}

func (m *redisBE) Get() backends.Backend {
	return m.be
}

func (m *redisBE) Clear() error {
	return m.c.FlushDB(context.Background()).Err()
}

func (m *redisBE) Cleanup() {
	m.c.Close()
}
