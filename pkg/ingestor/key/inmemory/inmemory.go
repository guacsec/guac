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
	"crypto"

	"github.com/guacsec/guac/pkg/ingestor/key"
)

type inmemory struct {
	collector map[string]crypto.PublicKey
}

func newInmemoryProvider() *inmemory {
	return &inmemory{
		collector: map[string]crypto.PublicKey{},
	}
}

func (m *inmemory) RetrieveKey(id string) (crypto.PublicKey, error) {
	if key, ok := m.collector[id]; ok {
		return key, nil
	}
	return nil, nil
}

func (m *inmemory) StoreKey(id string, pk crypto.PublicKey) error {
	m.collector[id] = pk
	return nil
}

func (m *inmemory) DeleteKey(id string) error {
	delete(m.collector, id)
	return nil
}

func (m *inmemory) Type() key.KeyProviderType {
	return "inmemory"
}
