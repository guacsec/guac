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

package scorecard

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/ossf/scorecard/v4/docs/checks"
	"github.com/ossf/scorecard/v4/log"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// scorecard is a struct that implements the Certifier interface.
type scorecard struct {
	scorecard Scorecard
	ghToken   string
	client    graphdb.Client
}

var ErrArtifactNodeTypeMismatch = fmt.Errorf("rootComponent type is not *assembler.ArtifactNode")

// CertifyComponent is a certifier that generates scorecard attestations
func (s scorecard) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	if docChannel == nil {
		return fmt.Errorf("docChannel cannot be nil")
	}
	if rootComponent == nil {
		return fmt.Errorf("rootComponent cannot be nil")
	}

	var artifactNode *assembler.ArtifactNode

	if component, ok := rootComponent.(*assembler.ArtifactNode); ok {
		artifactNode = component
	} else {
		return ErrArtifactNodeTypeMismatch
	}

	// Remove the git+ prefix from the artifact name
	repoName := strings.TrimLeft(artifactNode.Name, "git+")

	// s.artifact.Digest is the commit SHA
	if artifactNode.Digest == "" {
		return fmt.Errorf("artifact digest cannot be empty")
	}

	if repoName == "" {
		return fmt.Errorf("artifact name cannot be empty")
	}

	score, err := s.scorecard.GetScore(repoName, artifactNode.Digest)
	if err != nil {
		return fmt.Errorf("error getting scorecard result: %w", err)
	}

	var scorecardResults bytes.Buffer
	docs, err := checks.Read()
	if err != nil {
		return fmt.Errorf("error getting scorecard docs: %w", err)
	}

	if err = score.AsJSON2(true, log.DefaultLevel, docs, &scorecardResults); err != nil {
		return fmt.Errorf("error getting scorecard results: %w", err)
	}

	res := processor.Document{
		Blob:   scorecardResults.Bytes(),
		Format: processor.FormatJSON,
		Type:   processor.DocumentScorecard,
		SourceInformation: processor.SourceInformation{
			Collector: "scorecard",
			Source:    artifactNode.Name + "@" + artifactNode.Digest,
		},
	}

	docChannel <- &res

	return nil
}

func (s scorecard) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
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

// NewScorecardCertifier initializes the scorecard certifier.
// It checks if the GITHUB_AUTH_TOKEN is set in the environment. If it is not, it returns an error.w
// The token is used to access the GitHub API, https://github.com/ossf/scorecard#authentication.
func NewScorecardCertifier(sc Scorecard, client graphdb.Client) (CertQuerier, error) {
	if sc == nil {
		return nil, fmt.Errorf("scorecard cannot be nil")
	}
	// TODO: Add nil check for client, not checking for the client being nil because unit tests cant initialize a client

	// check if the GITHUB_AUTH_TOKEN is set
	s, ok := os.LookupEnv("GITHUB_AUTH_TOKEN")
	if !ok || s == "" {
		return nil, fmt.Errorf("GITHUB_AUTH_TOKEN is not set")
	}

	return &scorecard{
		scorecard: sc,
		ghToken:   s,
		client:    client,
	}, nil
}
