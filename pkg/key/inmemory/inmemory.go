//
// Copyright 2022 The AFF Authors.
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

	"github.com/guacsec/guac/pkg/key"
)

type InMemoryKeyProvider struct {
	keyMap key.KeyMap
}

func New(m key.KeyMap) *InMemoryKeyProvider {
	return &InMemoryKeyProvider{
		keyMap: m,
	}
}

// Returns list of keys associated with id if it exists
// Returns nil, nil if no keys are found
// Return nil, error if the request to the provider failed
func (i *InMemoryKeyProvider) GetKey(id string) (crypto.PublicKey, error) {
	if key, exists := i.keyMap[id]; exists {
		return key, nil
	}

	return nil, nil
}

func (i *InMemoryKeyProvider) PutKey(id string, pk crypto.PublicKey) error {
	i.keyMap[id] = pk

	return nil
}

func (i *InMemoryKeyProvider) DeleteKey(id string) error {
	delete(i.keyMap, id)

	return nil
}
