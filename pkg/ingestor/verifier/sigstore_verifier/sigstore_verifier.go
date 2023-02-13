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
	"context"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sig_dsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

type sigstoreVerifier struct {
}

// NewSigstoreVerifier initializes the sigstore verifier
func NewSigstoreAndKeyVerifier() *sigstoreVerifier {
	return &sigstoreVerifier{}
}

// Verify validates that the signature is valid for the payload
// TODO: this currently only supports SHA256 hash function when validating signatures
func (d *sigstoreVerifier) Verify(ctx context.Context, payloadBytes []byte) ([]verifier.Identity, error) {
	identities := []verifier.Identity{}
	envelope, err := parseDSSE(payloadBytes)
	if err != nil {
		return nil, err
	}
	for _, signature := range envelope.Signatures {
		key, err := key.Find(ctx, signature.KeyID)
		if err != nil {
			return nil, err
		}

		// currently keyID needs to be the hash of the public key
		// see:
		// https://github.com/sigstore/sigstore/blob/main/pkg/signature/dsse/dsse.go#L107
		// and
		// https://github.com/secure-systems-lab/go-securesystemslib/blob/main/dsse/verify.go#L69
		foundIdentity := verifier.Identity{
			ID:  signature.KeyID,
			Key: *key,
		}
		err = verifySignature(key.Val, payloadBytes)
		if err != nil {
			// logging here as we don't want to fail but record that the signature check failed
			logger := logging.FromContext(ctx)
			logger.Errorf("failed to verify signature with provided key: %w", key.Hash)
		}
		// if err (meaning that the keyID or the signature verification failed), verified is set to false
		foundIdentity.Verified = (err == nil)
		identities = append(identities, foundIdentity)
	}

	return identities, nil
}

// Type returns the type of the verifier
func (d *sigstoreVerifier) Type() verifier.VerifierType {
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
