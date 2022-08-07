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

package verifier

import (
	"crypto"
	"fmt"

	"github.com/guacsec/guac/pkg/ingestor/processor"
	"github.com/guacsec/guac/pkg/key"
	"github.com/guacsec/guac/pkg/verifier"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

type SigstoreVerifier struct {
	keyProvider key.KeyProvider
}

// TODO: Add more than DSSE support here.
func (d *SigstoreVerifier) Verify(i *processor.Document) ([]verifier.VerifiedKey, error) {
	if i.Type != processor.DocumentDSSE {
		return nil, fmt.Errorf("expected format: %v, actual format: %v", processor.DocumentDSSE, i.Format)
	}

	verifiedSignatures := make([]verifier.VerifiedKey, 0)

	for _, signature := range i.TrustInformation.DSSE.Signatures {
		// If we have multiple signatures that use the same KeyID we don't need to check it
		// TODO: Is this correct? Is there a reason we would have multiple signatures with the same key?
		key, err := d.keyProvider.GetKey(signature.KeyID)
		if err != nil {
			return nil, err
		}

		err = verifySignature(key, []byte(signature.Sig), []byte(i.TrustInformation.DSSE.Payload))
		if err != nil {
			return nil, err
		}

		verifiedSignatures = append(verifiedSignatures, verifier.VerifiedKey{
			Key: key,
			ID:  signature.KeyID,
		})
	}

	return verifiedSignatures, nil
}

func verifySignature(k crypto.PublicKey, sig []byte, payload []byte) error {
	// TODO: figure out how to use safe verifier and fall back to unsafe
	v, err := signature.LoadUnsafeVerifier(k)
	if err != nil {
		return err
	}
	dsseVerifier := dsse.VerifierAdapter{
		SignatureVerifier: v,
		Pub:               k,
		PubKeyID:          "",
	}
	if err := dsseVerifier.Verify(payload, sig); err != nil {
		return nil
	}
	return fmt.Errorf("No keys match signature")
}
