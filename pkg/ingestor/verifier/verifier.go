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
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/key"
)

type VerifierType string

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
	Verify(ctx context.Context, payloadBytes []byte) ([]Identity, error)
	// Type returns the verifier type
	Type() VerifierType
}

// Identity struct elements might be nil/empty if the key is invalid or the
// ID of the identity can't be determined. Verified indicates that the
// identity has been verified, usually based on signature matching the key.
// This shouldn't be used to indicate that the Identity is trusted in any
// way.
type Identity struct {
	ID       string
	Key      key.Key
	Verified bool
}

var (
	verifierProviders = map[VerifierType]Verifier{}
)

// RegisterVerifier registers the providers that are available for verification
func RegisterVerifier(k Verifier, providerType VerifierType) error {
	if _, ok := verifierProviders[providerType]; ok {
		verifierProviders[providerType] = k
		return fmt.Errorf("the verification provider is being overwritten: %s", providerType)
	}
	verifierProviders[providerType] = k
	return nil
}

// VerifyIdentity goes through the registered providers and verifies the signatures in the payload
func VerifyIdentity(ctx context.Context, doc *processor.Document) ([]Identity, error) {
	switch doc.Type {
	case processor.DocumentDSSE:
		if verifier, ok := verifierProviders["sigstore"]; ok {
			return verifier.Verify(ctx, doc.Blob) // nolint:wrapcheck
		}
	}
	return nil, fmt.Errorf("failed verification for document type: %s", doc.Type)
}
