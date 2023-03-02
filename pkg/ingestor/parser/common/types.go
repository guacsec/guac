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

package common

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type DocumentParser interface {
	// Parse breaks out the document into the graph components
	Parse(ctx context.Context, doc *processor.Document) error

	// GetIdentities gets the identity node from the document if they exist
	GetIdentities(ctx context.Context) []TrustInformation

	// CreatePredicates returns the predicates of the GUAC ontology to be created
	GetPredicates(ctx context.Context) *assembler.PlaceholderStruct

	// GetIdentifiers returns a set of identifiers that the parser has found to help provide context
	// for collectors to gather more information around found software identifiers.
	// This is an optional function to implement and it should return an error if not implemented.
	//
	// Ref: https://github.com/guacsec/guac/issues/244
	GetIdentifiers(ctx context.Context) (*IdentifierStrings, error)
}

// Identifiers represent a set of strings that can be used to a set of
// identifiers that the parser has found to help provide context for collectors
// to gather more information around found software identifiers.
//
// Ref: https://github.com/guacsec/guac/issues/244
type IdentifierStrings struct {
	// OciStrings should contain pointers to OCI packages
	OciStrings []string
	// VcsStrings should contain VCS strings for source control
	VcsStrings []string
	// UnclassifiedStrings contains other strings that have identifiers that
	// parsers may not be sure what category they fall under.
	UnclassifiedStrings []string
}

type TrustInformation struct{}
