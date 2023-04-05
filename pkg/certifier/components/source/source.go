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
	"math"
	"strings"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/certifier"
)

type sourceQuery struct {
	client            graphql.Client
	daysSinceLastScan int
}

type SourceNode struct {
	Repo   string
	Commit string
	Tag    string
}

var getSources func(ctx context.Context, client graphql.Client, filter *generated.SourceSpec) (*generated.SourcesResponse, error)
var getNeighbors func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error)

// GetComponents get all the sources that do not have a certify scorecard attached or last scanned is more than daysSinceLastScan
func (s sourceQuery) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	if compChan == nil {
		return fmt.Errorf("compChan cannot be nil")
	}
	response, err := getSources(ctx, s.client, nil)
	if err != nil {
		return fmt.Errorf("failed sources query: %w", err)
	}
	sources := response.GetSources()

	for _, src := range sources {
		for _, namespace := range src.Namespaces {
			for _, names := range namespace.Names {
				response, err := getNeighbors(ctx, s.client, names.Id)
				if err != nil {
					return fmt.Errorf("failed neighbors query: %w", err)
				}
				scorecardList := []*generated.NeighborsNeighborsCertifyScorecard{}
				scoreCardFound := false
				for _, neighbor := range response.Neighbors {
					scorecardNode, ok := neighbor.(*generated.NeighborsNeighborsCertifyScorecard)
					if ok {
						scorecardList = append(scorecardList, scorecardNode)
					}
				}
				// collect all scorecardNodes and then check timestamp else if not checking timestamp,
				// if a scorecard is found break out
				for _, scorecardNode := range scorecardList {
					if s.daysSinceLastScan != 0 {
						now := time.Now()
						difference := scorecardNode.Scorecard.TimeScanned.Sub(now)
						if math.Abs(difference.Hours()) < float64(s.daysSinceLastScan*24) {
							scoreCardFound = true
						}
					} else {
						scoreCardFound = true
						break
					}
				}
				if !scoreCardFound {
					sourceNode := SourceNode{
						Repo:   names.Name,
						Commit: trimAlgorithm(nilOrEmpty(names.Commit)),
						Tag:    nilOrEmpty(names.Tag),
					}
					compChan <- &sourceNode
				}
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
		if len(commitSplit) == 2 {
			return commitSplit[1]
		} else {
			return commitSplit[0]
		}
	}
}

// NewCertifier returns a new sourceArtifacts certifier
func NewCertifier(client graphql.Client, daysSinceLastScan int) (certifier.QueryComponents, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}
	getSources = generated.Sources
	getNeighbors = generated.Neighbors
	return &sourceQuery{
		client:            client,
		daysSinceLastScan: daysSinceLastScan,
	}, nil
}
