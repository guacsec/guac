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

package sigstore_verifier

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sig_dsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

type SigstoreVerifier struct {
}

func NewSigstoreVerifier() *SigstoreVerifier {
	return &SigstoreVerifier{}
}

// TODO: Add more than DSSE support here.
// Verify validates that the signature is valid for the payload
func (d *SigstoreVerifier) Verify(payloadBytes []byte) ([]verifier.Identity, error) {
	identities := []verifier.Identity{}
	envelope, err := parseDSSE(payloadBytes)
	if err != nil {
		return nil, err
	}
	for _, signature := range envelope.Signatures {
		key, err := key.Find(signature.KeyID)
		if err != nil {
			return nil, err
		}

		foundIdentity := verifier.Identity{
			ID:  signature.KeyID,
			Key: *key,
		}
		err = verifySignature(key.KeyVal, payloadBytes)
		if err != nil {
			foundIdentity.Verified = false
			identities = append(identities, foundIdentity)
		} else {
			foundIdentity.Verified = true
			identities = append(identities, foundIdentity)
		}
	}

	return identities, nil
}

func (d *SigstoreVerifier) Type() verifier.VerifierType {
	return "sigstore"
}

func verifySignature(k crypto.PublicKey, payload []byte) error {
	vfr, err := signature.LoadVerifier(k, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("could not load verifier: %w", err)
	}

	sigVfr := sig_dsse.WrapVerifier(vfr)

	if err := sigVfr.VerifySignature(bytes.NewReader(payload), nil); err != nil {
		return err
	}
	return nil
}

func parseDSSE(b []byte) (*dsse.Envelope, error) {
	envelope := dsse.Envelope{}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return nil, err
	}

	return &envelope, nil
}
