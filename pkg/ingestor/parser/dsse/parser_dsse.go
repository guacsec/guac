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
	"encoding/base64"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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

	if err := d.getIdentity(ctx); err != nil {
		return fmt.Errorf("getIdentity returned error: %v", err)
	}
	return nil
}

func (d *dsseParser) getIdentity(ctx context.Context) error {
	identities, err := verifier.VerifyIdentity(ctx, d.doc)
	if err != nil {
		return fmt.Errorf("failed to verify identity: %w", err)
	}
	for _, i := range identities {
		if i.Verified {
			pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(i.Key.Val)
			if err != nil {
				return fmt.Errorf("MarshalPublicKeyToPEM returned error: %w", err)
			}
			d.identities = append(d.identities, assembler.IdentityNode{
				ID: i.ID, Digest: i.Key.Hash, Key: base64.StdEncoding.EncodeToString(pemBytes),
				KeyType: string(i.Key.Type), KeyScheme: string(i.Key.Scheme), NodeData: *assembler.NewObjectMetadata(d.doc.SourceInformation)})
		} else {
			logger := logging.FromContext(ctx)
			logger.Errorf("failed to verify DSSE with provided key: %w", i.ID)
		}
	}
	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (d *dsseParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return d.identities
}

// CreateNodes creates the GuacNode for the graph inputs
func (d *dsseParser) CreateNodes(_ context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, i := range d.identities {
		nodes = append(nodes, i)
	}
	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (d *dsseParser) CreateEdges(_ context.Context, _ []assembler.IdentityNode) []assembler.GuacEdge {
	return []assembler.GuacEdge{}
}

func (d *dsseParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}
