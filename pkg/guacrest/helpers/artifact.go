//
// Copyright 2024 The GUAC Authors.
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

package helpers

import (
	"context"
	"fmt"

	"github.com/Khan/genqlient/graphql"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
)

// Queries for an artifact by digest and returns its id. The digest must uniquely
// identify an artifact, otherwise an error is returned.
func FindArtifactWithDigest(ctx context.Context, gqlClient graphql.Client,
	digest string) (gql.AllArtifactTree, error) {
	logger := logging.FromContext(ctx)
	filter := gql.ArtifactSpec{Digest: &digest}

	artifacts, err := gql.Artifacts(ctx, gqlClient, filter)
	if err != nil {
		logger.Errorf(fmt.Sprintf("Artifacts query returned error: %v", err))
		return gql.AllArtifactTree{}, Err502
	}
	if len(artifacts.GetArtifacts()) == 0 {
		return gql.AllArtifactTree{}, fmt.Errorf("no artifacts matched the digest")
	}
	if len(artifacts.GetArtifacts()) > 1 {
		logger.Errorf("More than one artifact was found with digest %s", digest)
		return gql.AllArtifactTree{}, Err500
	}
	return artifacts.GetArtifacts()[0].AllArtifactTree, nil
}
