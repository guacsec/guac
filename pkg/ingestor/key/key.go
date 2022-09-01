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

package key

// TODO: It seems like some signing verification mechanisms require us to specify the hashing algorithm
// Returns list of PublicKeys associated with the id.
type KeyProvider interface {
	// Returns list of keys associated with id if it exists
	// Returns nil, nil if no keys are found
	// Return nil, error if the request to the provider failed
	GetKey(id string) ([]byte, error)
	PutKey(id string, pk []byte) error
	DeleteKey(id string) error
}
