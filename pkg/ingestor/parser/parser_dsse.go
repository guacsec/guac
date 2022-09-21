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

package parser

import (
	"encoding/base64"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func parseDsse(doc *processor.Document) (GraphBuilder, error) {
	b := newGenericGraphBuilder()
	b.doc = doc
	id, err := getIdentity(doc)
	if err != nil {
		return nil, err
	}
	b.foundIdentities = append(b.foundIdentities, id...)

	return b, nil
}

func getIdentity(doc *processor.Document) ([]assembler.IdentityNode, error) {
	foundIdentity := []assembler.IdentityNode{}
	identities, err := verifier.VerifyIdentity(doc)
	if err != nil {
		return nil, err
	}
	for _, i := range identities {
		pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(i.Key.Val)
		if err != nil {
			return nil, fmt.Errorf("MarshalPublicKeyToPEM returned error: %v", err)
		}
		foundIdentity = append(foundIdentity, assembler.IdentityNode{
			ID: i.ID, Digest: i.Key.Hash, Key: base64.StdEncoding.EncodeToString(pemBytes), KeyType: string(i.Key.Type), KeyScheme: string(i.Key.Scheme)})
	}
	return foundIdentity, nil
}
