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

package dsse

import (
	"encoding/base64"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type dsseParser struct {
	identities []assembler.IdentityNode
}

func NewDSSEParser() *dsseParser {
	return &dsseParser{
		identities: []assembler.IdentityNode{},
	}
}

func (d *dsseParser) Parse(doc *processor.Document) error {
	err := d.getIdentity(doc)
	if err != nil {
		return err
	}
	return nil
}

func (d *dsseParser) getIdentity(doc *processor.Document) error {
	identities, err := verifier.VerifyIdentity(doc)
	if err != nil {
		return err
	}
	for _, i := range identities {
		pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(i.Key.Val)
		if err != nil {
			return fmt.Errorf("MarshalPublicKeyToPEM returned error: %v", err)
		}
		d.identities = append(d.identities, assembler.IdentityNode{
			ID: i.ID, Digest: i.Key.Hash, Key: base64.StdEncoding.EncodeToString(pemBytes), KeyType: string(i.Key.Type), KeyScheme: string(i.Key.Scheme)})
	}
	return nil
}

func (d *dsseParser) GetIdentities() []assembler.IdentityNode {
	return d.identities
}

func (d *dsseParser) CreateNodes() []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, i := range d.identities {
		nodes = append(nodes, i)
	}
	return nodes
}

func (d *dsseParser) CreateEdges(foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	return []assembler.GuacEdge{}
}

func (d *dsseParser) GetDocType() processor.DocumentType {
	return processor.DocumentDSSE
}
