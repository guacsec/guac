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

	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/source_artifact"

	"github.com/ossf/scorecard/v4/docs/checks"
	"github.com/ossf/scorecard/v4/log"

	"github.com/guacsec/guac/pkg/handler/processor"
)

// scorecard is a struct that implements the Certifier interface.
type scorecard struct {
	scorecard Scorecard
	ghToken   string
}

var ErrArtifactNodeTypeMismatch = fmt.Errorf("rootComponent type is not *assembler.ArtifactNode")

// CertifyComponent is a certifier that generates scorecard attestations
func (s scorecard) CertifyComponent(_ context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	if docChannel == nil {
		return fmt.Errorf("docChannel cannot be nil")
	}
	if rootComponent == nil {
		return fmt.Errorf("rootComponent cannot be nil")
	}

	var sourceNode *source_artifact.SourceNode

	if component, ok := rootComponent.(*source_artifact.SourceNode); ok {
		sourceNode = component
	} else {
		return ErrArtifactNodeTypeMismatch
	}

	// s.artifact.Digest is the commit SHA
	if sourceNode.Commit == "" {
		return fmt.Errorf("source commit cannot be empty")
	}

	if sourceNode.Repo == "" {
		return fmt.Errorf("source repo cannot be empty")
	}

	score, err := s.scorecard.GetScore(sourceNode.Repo, sourceNode.Commit)
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
			Source:    sourceNode.Repo + "@" + sourceNode.Commit,
		},
	}

	docChannel <- &res

	return nil
}

// NewScorecardCertifier initializes the scorecard certifier.
// It checks if the GITHUB_AUTH_TOKEN is set in the environment. If it is not, it returns an error.w
// The token is used to access the GitHub API, https://github.com/ossf/scorecard#authentication.
func NewScorecardCertifier(sc Scorecard) (certifier.Certifier, error) {
	if sc == nil {
		return nil, fmt.Errorf("scorecard cannot be nil")
	}

	// check if the GITHUB_AUTH_TOKEN is set
	s, ok := os.LookupEnv("GITHUB_AUTH_TOKEN")
	if !ok || s == "" {
		return nil, fmt.Errorf("GITHUB_AUTH_TOKEN is not set")
	}

	return &scorecard{
		scorecard: sc,
		ghToken:   s,
	}, nil
}
