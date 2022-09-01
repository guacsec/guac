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

package verifier

import (
	"github.com/guacsec/guac/pkg/ingestor/key"
)

// Verifier allows for multiple signature or identity verifiers that will
// check envelopes, signatures, and other payloads for linking a payload
// back to an identity. In most cases this will be done through verifying
// one or more signatures against known public keys.
type Verifier interface {
	// Verify takes in bytes and returns a list of identities. Those
	// identities are marked as verified if the payload can be tied back to
	// an identity, usually through signature validation. In cases where
	// signatures can't be verified, it is still valuable to return data
	// about the unverified identity. Upstream caller is expected to know
	// which verifier it needs to based on what type of enveloper or
	// signature is being verified.
	Verify(payloadBytes []byte) ([]Identity, error)
	Type() string
}

type Key struct {
	// KeyHash sha256 hash of the canonical representation of the key
	KeyHash string
	// KeyType represents the type of the key
	KeyType key.KeyType
	// KeyVal is the byte array of the public key
	KeyVal []byte
	// TODO: is this needed? Santiago question?
	// Scheme is the supported scheme by the key type.
	Scheme key.KeyScheme
}

// Identity struct elements might be nil/empty if the key is invalid or the
// ID of the identity can't be determined. Verified indicates that the
// identity has been verified, usually based on signature matching the key.
// This shouldn't be used to indicate that the Identity is trusted in any
// way.
type Identity struct {
	ID       string
	Key      Key
	Verified bool
}
