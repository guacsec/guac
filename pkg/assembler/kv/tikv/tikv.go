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

package tikv

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/kv"
	jsoniter "github.com/json-iterator/go"
	"github.com/tikv/client-go/v2/config"
	kvti "github.com/tikv/client-go/v2/kv"
	"github.com/tikv/client-go/v2/rawkv"
)

var json = jsoniter.ConfigFastest

const count = 1000

type store struct {
	c *rawkv.Client
}

func GetStore(ctx context.Context, s string) (kv.Store, error) {
	// TODO(jeffmendoza) add options for security, etc.
	c, err := rawkv.NewClient(ctx, []string{s}, config.Security{})
	if err != nil {
		return nil, err
	}
	return &store{
		c: c,
	}, nil
}

func (s *store) Get(ctx context.Context, c, k string, v any) error {
	ck := strings.Join([]string{c, k}, ":")
	bts, err := s.c.Get(ctx, []byte(ck))
	// TODO(jeffmendoza), should figure out error type and check it, instead just see if
	// slice is empty for now.
	if len(bts) == 0 {
		return kv.NotFoundError
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(bts, v)
}

func (s *store) Set(ctx context.Context, c, k string, v any) error {
	ck := strings.Join([]string{c, k}, ":")
	bts, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.c.Put(ctx, []byte(ck), bts)
}

func (s *store) Keys(c string) kv.Scanner {
	return &scanner{
		c:      s.c,
		done:   false,
		curKey: []byte(c),
		endKey: kvti.PrefixNextKey([]byte(c)),
	}
}

type scanner struct {
	c      *rawkv.Client
	done   bool
	curKey []byte
	endKey []byte
}

func (s *scanner) Scan(ctx context.Context) ([]string, bool, error) {
	if s.done {
		return nil, true, nil
	}
	ks, _, err := s.c.Scan(ctx, s.curKey, s.endKey, count, rawkv.ScanKeyOnly())
	if err != nil {
		return nil, false, err
	}
	if len(ks) < count {
		s.done = true
	}
	if len(ks) == 0 {
		return nil, true, nil
	}
	rv := make([]string, len(ks))
	var largest []byte
	for i, k := range ks {
		if bytes.Compare(k, largest) > 0 {
			largest = k
		}
		parts := strings.SplitN(string(k), ":", 2)
		if len(parts) != 2 {
			return nil, false, fmt.Errorf("Invalid key found in TiKV: %q", string(k))
		}
		rv[i] = string(parts[1])
	}
	s.curKey = kvti.NextKey(largest)
	return rv, s.done, nil
}
