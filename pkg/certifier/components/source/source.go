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

package source

import (
	"context"
	"fmt"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/certifier"
)

type sourceArtifacts struct {
	client graphql.Client
}

type SourceNode struct {
	Repo   string
	Commit string
	Tag    string
}

func (s sourceArtifacts) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	// TODO: Add integration tests, have not added it yet because the code needs data to be present in the graphdb to test it
	if compChan == nil {
		return fmt.Errorf("compChan cannot be nil")
	}
	// TODO: specify scorecard time-scanned to determine when they are out of data and need to be re-scanned again.
	response, err := generated.sources(ctx, s.client, nil)
	if err != nil {
		return fmt.Errorf("failed to read query: %w", err)
	}
	sources := response.GetSourcesRequiringScorecard()

	for _, src := range sources {
		for _, namespace := range src.Namespaces {
			for _, names := range namespace.Names {
				sourceNode := SourceNode{
					Repo:   namespace.Namespace + "/" + names.Name,
					Commit: trimAlgorithm(nilOrEmpty(names.Commit)),
					Tag:    nilOrEmpty(names.Tag),
				}
				compChan <- &sourceNode
			}
		}
	}
	return nil
}

func nilOrEmpty(value *string) string {
	if value != nil {
		return *value
	} else {
		return ""
	}
}

// remove the "sha1:" prefix from the digest before passing it to the scorecard runner.
func trimAlgorithm(commit string) string {
	if commit == "" {
		return commit
	} else {
		commitSplit := strings.Split(commit, ":")
		return commitSplit[1]
	}
}

// NewCertifier returns a new sourceArtifacts certifier
func NewCertifier(client graphql.Client) (certifier.QueryComponents, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}
	return &sourceArtifacts{
		client: client,
	}, nil
}
