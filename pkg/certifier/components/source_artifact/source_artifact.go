//
// Copyright 2023 The GUAC Authors.
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

package source_artifact

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
)

type sourceArtifacts struct {
	client graphdb.Client
}

func (s sourceArtifacts) GetComponents(_ context.Context, compChan chan<- interface{}) error {
	// TODO: Add integration tests, have not added it yet because the code needs data to be present in the graphdb to test it
	if compChan == nil {
		return fmt.Errorf("compChan cannot be nil")
	}
	roots, err := graphdb.ReadQuery(s.client, "MATCH (n:Artifact) WHERE n.name CONTAINS 'git+' RETURN n", nil)
	if err != nil {
		return fmt.Errorf("failed to read query: %w", err)
	}

	for _, result := range roots {
		foundNode, ok := result.(dbtype.Node)
		if !ok {
			return fmt.Errorf("failed to cast to node type")
		}
		artifactNode := assembler.ArtifactNode{}
		artifactNode.Name, ok = foundNode.Props["name"].(string)
		if !ok {
			return fmt.Errorf("failed to cast name property to string type")
		}
		artifactNode.Digest, ok = foundNode.Props["digest"].(string)
		if !ok {
			return fmt.Errorf("failed to cast digest property to string type")
		}
		compChan <- &artifactNode
	}
	return nil
}

// NewCertifier returns a new sourceArtifacts certifier
func NewCertifier(client graphdb.Client) (certifier.QueryComponents, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}
	return &sourceArtifacts{
		client: client,
	}, nil
}
