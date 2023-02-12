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
	"context"
	"fmt"
	"os"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/handler/processor"
)

var ErrArtifactNodeTypeMismatch = fmt.Errorf("rootComponent type is not *assembler.ArtifactNode")

// CertifyComponent is a certifier that generates scorecard attestations
func (s scorecard) CertifyComponent(_ context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	if docChannel == nil {
		return fmt.Errorf("docChannel cannot be nil")
	}
	if rootComponent == nil {
		return fmt.Errorf("rootComponent cannot be nil")
	}
	if component, ok := rootComponent.(*assembler.ArtifactNode); ok {
		s.artifact = component
	} else {
		return ErrArtifactNodeTypeMismatch
	}

	_, err := s.scorecard.GetScore(s.artifact.Name, s.artifact.Digest)
	if err != nil {
		return fmt.Errorf("error getting scorecard result: %w", err)
	}
	//TODO :- Need to push the scorecard results into the docChannel
	return nil
}

// NewScorecard initializes the scorecard certifier.
// It checks if the GITHUB_AUTH_TOKEN is set in the environment. If it is not, it returns an error.
// The token is used to access the GitHub API, https://github.com/ossf/scorecard#authentication.
func NewScorecard(sc Scorecard) (certifier.Certifier, error) {
	if sc == nil {
		return nil, fmt.Errorf("scorecard cannot be nil")
	}
	// check if the GITHUB_AUTH_TOKEN is set
	s, ok := os.LookupEnv("GITHUB_AUTH_TOKEN")
	if !ok || s == "" {
		return nil, fmt.Errorf("GITHUB_AUTH_TOKEN is not set")
	}

	return &scorecard{scorecard: sc, ghToken: s}, nil
}
