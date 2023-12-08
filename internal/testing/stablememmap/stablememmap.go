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

package stablememmap

import (
	"context"
	"errors"
	"slices"

	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/guacsec/guac/pkg/assembler/kv/memmap"
)

type store struct {
	mm kv.Store
}

func GetStore() kv.Store {
	return &store{
		mm: memmap.GetStore(),
	}
}

func (s *store) Get(ctx context.Context, c, k string, v any) error {
	return s.mm.Get(ctx, c, k, v)
}

func (s *store) Set(ctx context.Context, c, k string, v any) error {
	return s.mm.Set(ctx, c, k, v)
}

func (s *store) Keys(c string) kv.Scanner {
	return &scanner{mms: s.mm.Keys(c)}
}

type scanner struct {
	mms kv.Scanner
}

func (s *scanner) Scan(ctx context.Context) ([]string, bool, error) {
	keys, done, err := s.mms.Scan(ctx)
	if err != nil {
		return nil, false, err
	}
	if !done {
		return nil, false, errors.New("Expect memmap to always return all keys at once")
	}
	slices.Sort(keys)
	return keys, true, nil
}
