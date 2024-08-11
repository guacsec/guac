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

package helpers_test

import (
	"context"
	"testing"

	test_helpers "github.com/guacsec/guac/internal/testing/graphqlClients"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/stretchr/testify/assert"
)

func Test_FindArtifactWithDigest_ArtifactNotFound(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	gqlClient := test_helpers.SetupTest(t)

	_, err := helpers.FindArtifactWithDigest(ctx, gqlClient, "xyz")
	assert.ErrorContains(t, err, "no artifacts matched the digest")
}

func Test_FindArtifactWithDigest_ArtifactFound(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	gqlClient := test_helpers.SetupTest(t)

	idOrArtifactSpec := gql.IDorArtifactInput{ArtifactInput: &gql.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "abc",
	}}
	_, err := gql.IngestArtifact(ctx, gqlClient, idOrArtifactSpec)
	if err != nil {
		t.Fatalf("Error ingesting test data")
	}

	res, err := helpers.FindArtifactWithDigest(ctx, gqlClient, "abc")
	assert.NoError(t, err)
	assert.Equal(t, res.Algorithm, "sha256")
	assert.Equal(t, res.Digest, "abc")
}
