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
	"path"
	"strings"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/certifier"
)

type sourceQuery struct {
	client graphql.Client
	// set the batch size for the package pagination query
	batchSize int
	// add artificial latency to throttle the pagination query
	addedLatency *time.Duration
}

type SourceNode struct {
	Repo   string
	Commit string
	Tag    string
}

var getSources func(ctx context.Context, client graphql.Client, filter generated.SourceSpec, after *string, first *int) (*generated.SourcesListResponse, error)

// GetComponents get all the sources
func (s sourceQuery) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	if compChan == nil {
		return fmt.Errorf("compChan cannot be nil")
	}

	var afterCursor *string

	first := s.batchSize
	//first := 60000
	for {
		srcConn, err := getSources(ctx, s.client, generated.SourceSpec{}, afterCursor, &first)
		if err != nil {
			return fmt.Errorf("failed to query packages with error: %w", err)
		}
		srcEdges := srcConn.SourcesList.Edges

		for _, srcNode := range srcEdges {
			for _, namespace := range srcNode.Node.Namespaces {
				for _, names := range namespace.Names {
					sourceNode := SourceNode{
						Repo:   path.Join(namespace.Namespace, names.Name),
						Commit: trimAlgorithm(nilOrEmpty(names.Commit)),
						Tag:    nilOrEmpty(names.Tag),
					}
					compChan <- &sourceNode
				}
			}
		}
		if !srcConn.SourcesList.PageInfo.HasNextPage {
			break
		}
		afterCursor = srcConn.SourcesList.PageInfo.EndCursor
		// add artificial latency to throttle the pagination query
		if s.addedLatency != nil {
			time.Sleep(*s.addedLatency)
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
		if len(commitSplit) == 2 {
			return commitSplit[1]
		} else {
			return commitSplit[0]
		}
	}
}

// NewCertifier returns a new sourceArtifacts certifier
func NewCertifier(client graphql.Client, batchSize int, addedLatency *time.Duration) (certifier.QueryComponents, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}
	getSources = generated.SourcesList
	return &sourceQuery{
		client:       client,
		batchSize:    batchSize,
		addedLatency: addedLatency,
	}, nil
}
