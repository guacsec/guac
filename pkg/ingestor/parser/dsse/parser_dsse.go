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
	"context"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

type dsseParser struct {
	doc        *processor.Document
	identities []assembler.IdentityNode
}

// NewDSSEParser initializes the dsseParser
func NewDSSEParser() common.DocumentParser {
	return &dsseParser{
		identities: []assembler.IdentityNode{},
	}
}

// Parse breaks out the document into the graph components
func (d *dsseParser) Parse(ctx context.Context, doc *processor.Document) error {
	d.doc = doc
	err := d.getIdentity(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (d *dsseParser) getIdentity(ctx context.Context) error {
	// We dont have a way to feed in the public key at the this time. So commenting out.
	/* identities, err := verifier.VerifyIdentity(ctx, d.doc)
	if err != nil {
		return err
	}
	for _, i := range identities {
		pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(i.Key.Val)
		if err != nil {
			return fmt.Errorf("MarshalPublicKeyToPEM returned error: %v", err)
		}
		d.identities = append(d.identities, assembler.IdentityNode{
			ID: i.ID, Digest: i.Key.Hash, Key: base64.StdEncoding.EncodeToString(pemBytes),
			KeyType: string(i.Key.Type), KeyScheme: string(i.Key.Scheme), NodeData: *assembler.NewObjectMetadata(d.doc.SourceInformation)})
	} */
	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (d *dsseParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return d.identities
}

// CreateNodes creates the GuacNode for the graph inputs
func (d *dsseParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, i := range d.identities {
		nodes = append(nodes, i)
	}
	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (d *dsseParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	return []assembler.GuacEdge{}
}
