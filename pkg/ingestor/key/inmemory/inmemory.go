//
// Copyright 2022 The GUAC Authors.
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

package inmemory

import (
	"context"

	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/logging"
)

type inmemory struct {
	collector map[string]*key.Key
}

func NewInmemoryProvider() *inmemory {
	return &inmemory{
		collector: map[string]*key.Key{},
	}
}

func (m *inmemory) RetrieveKey(ctx context.Context, id string) (*key.Key, error) {
	if key, ok := m.collector[id]; ok {
		return key, nil
	}
	return nil, nil
}

func (m *inmemory) StoreKey(ctx context.Context, id string, pk *key.Key) error {
	logger := logging.FromContext(ctx)
	m.collector[id] = pk
	logger.Warnf("key is being overwritten: %s", id)
	return nil
}

func (m *inmemory) DeleteKey(ctx context.Context, id string) error {
	logger := logging.FromContext(ctx)
	delete(m.collector, id)
	logger.Warnf("key is being deleted: %s", id)
	return nil
}

func (m *inmemory) Type() key.KeyProviderType {
	return "inmemory"
}
