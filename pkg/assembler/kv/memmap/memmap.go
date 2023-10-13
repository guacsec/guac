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

package memmap

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/kv"
	"golang.org/x/exp/maps"
)

type Store struct {
	m map[string]map[string]string
}

// check interface compatability
var _ kv.Store = &Store{}

func (s *Store) init() {
	if s.m == nil {
		s.m = make(map[string]map[string]string)
	}
}

func (s *Store) Get(_ context.Context, c, k string) (string, error) {
	s.init()
	col, ok := s.m[c]
	if !ok {
		return "", fmt.Errorf("%w : %s", kv.CollectionError, c)
	}

	val, ok := col[k]
	if !ok {
		return "", fmt.Errorf("%w : %s", kv.KeyError, k)
	}
	return val, nil
}

func (s *Store) Set(_ context.Context, c, k, v string) error {
	s.init()
	if s.m[c] == nil {
		s.m[c] = make(map[string]string)
	}
	s.m[c][k] = v
	return nil
}

func (s *Store) Keys(_ context.Context, c string) ([]string, error) {
	s.init()
	if s.m[c] == nil {
		return nil, nil
	}
	return maps.Keys(s.m[c]), nil
}
