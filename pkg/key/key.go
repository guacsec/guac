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

package key

import (
	"crypto"
)

// In most cases people use hashes of the key as IDs.
// This will need to be updated in the case of kms uris or other IDs for the key.
type KeyMap = map[string]crypto.PublicKey

// TODO: It seems like some signing verification mechanisms require us to specify the hashing algorithm
// Returns list of PublicKeys associated with the id.
type KeyProvider interface {
	// Returns list of keys associated with id if it exists
	// Returns nil, nil if no keys are found
	// Return nil, error if the request to the provider failed
	GetKey(id string) (crypto.PublicKey, error)
	PutKey(id string, pk crypto.PublicKey) error
	DeleteKey(id string) error
}
