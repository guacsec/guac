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

package mockverifier

import (
	"context"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type mockSigstoreVerifier struct{}

func NewMockSigstoreVerifier() *mockSigstoreVerifier {
	return &mockSigstoreVerifier{}
}

func (m *mockSigstoreVerifier) Verify(ctx context.Context, payloadBytes []byte) ([]verifier.Identity, error) {

	keyHash, _ := dsse.SHA256KeyID(testdata.EcdsaPubKey)
	return []verifier.Identity{
		{
			ID: "test",
			Key: key.Key{
				Hash:   keyHash,
				Type:   "ecdsa",
				Val:    testdata.EcdsaPubKey,
				Scheme: "ecdsa",
			},
			Verified: true,
		},
	}, nil
}

func (m *mockSigstoreVerifier) Type() verifier.VerifierType {
	return "sigstore"
}
