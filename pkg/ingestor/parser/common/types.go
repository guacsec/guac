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
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type DocumentParser interface {
	// Parse breaks out the document into the graph components
	Parse(doc *processor.Document) error
	// GetIdentities gets the identity node from the document if they exist
	GetIdentities() []assembler.IdentityNode
	// CreateNodes creates the GuacNode for the graph inputs
	CreateNodes() []assembler.GuacNode
	// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
	CreateEdges(foundIdentities []assembler.IdentityNode) []assembler.GuacEdge
}
