// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package server_test

import (
	stdcmp "cmp"
	"context"
	"net/url"
	"testing"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// Tests the edges in ByName that are not in ByDigest
func Test_RetrieveDependencies(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name string
		data GuacData

		// Only specify a Purl or a Digest. But, both purls and digests are tested
		purl   string
		digest string

		expectedByName   []string
		expectedByDigest []string
	}{
		/*******
		 * Tests of specific edges.
		 *
		 * The test case name is the edge or edges intended to be tested, not necessarily all
		 * of the edges in the graph. Equivalence edges (e.g. IsOccurrence) can't be
		 * tested without some dependency edges, so some edges / graphs can't be tested in
		 * isolation.
		 *******/
		{
			name: "Package -> SBOM -> package",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/bar"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
			},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{"pkg:guac/bar"},
			expectedByDigest: []string{},
		},
		{
			name: "Package -> SBOM -> package, package",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/bar", "pkg:guac/baz"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar", "pkg:guac/baz"}},
				},
			},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{"pkg:guac/bar", "pkg:guac/baz"},
			expectedByDigest: []string{},
		},
		{
			name: "Artifact -> SBOM -> package",
			data: GuacData{
				Packages:  []string{"pkg:guac/bar"},
				Artifacts: []string{"sha-xyz"},
				HasSboms: []HasSbom{
					{Subject: "sha-xyz", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
			},
			digest:           "sha-xyz",
			expectedByName:   []string{"pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/bar"},
		},
		{
			name: "Package -> SBOM -> package -> SBOM -> package",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/bar", "pkg:guac/baz"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}},
					{Subject: "pkg:guac/bar", IncludedSoftware: []string{"pkg:guac/baz"}},
				},
			},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{"pkg:guac/bar", "pkg:guac/baz"},
			expectedByDigest: []string{},
		},
		{
			name: "Artifact -> SBOM -> digest -> SBOM -> package",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo"},
				Artifacts: []string{"sha-xyz", "sha-123"},
				HasSboms: []HasSbom{
					{Subject: "sha-xyz", IncludedSoftware: []string{"sha-123"}},
					{Subject: "sha-123", IncludedSoftware: []string{"pkg:guac/foo"}},
				},
			},
			digest:           "sha-xyz",
			expectedByName:   []string{"pkg:guac/foo"},
			expectedByDigest: []string{"pkg:guac/foo"},
		},
		{
			name: "Artifact -> SBOM -> package -> SBOM -> package",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo", "pkg:guac/bar"},
				Artifacts: []string{"sha-xyz"},
				HasSboms: []HasSbom{
					{Subject: "sha-xyz", IncludedSoftware: []string{"pkg:guac/bar"}},
					{Subject: "pkg:guac/bar", IncludedSoftware: []string{"pkg:guac/foo"}},
				},
			},
			digest:           "sha-xyz",
			expectedByName:   []string{"pkg:guac/foo", "pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/bar"},
		},
		{
			name: "digest -> occurrence -> package",
			data: GuacData{
				Packages:      []string{"pkg:guac/bar"},
				Artifacts:     []string{"sha-123", "sha-xyz"},
				HasSboms:      []HasSbom{{Subject: "sha-xyz", IncludedSoftware: []string{"sha-123"}}},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/bar", Artifact: "sha-123"}},
			},
			digest:           "sha-xyz",
			expectedByName:   []string{"pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/bar"},
		},
		{
			name: "Package -> occurrence -> digest",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo", "pkg:guac/bar"},
				Artifacts:     []string{"sha-xyz"},
				HasSboms:      []HasSbom{{Subject: "sha-xyz", IncludedSoftware: []string{"pkg:guac/bar"}}},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
			},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{"pkg:guac/bar"},
			expectedByDigest: []string{},
		},
		{
			name: "package -> occurrence -> digest, digest",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo", "pkg:guac/bar", "pkg:guac/baz"},
				Artifacts: []string{"sha-xyz", "sha-123"},
				HasSboms: []HasSbom{
					{Subject: "sha-xyz", IncludedSoftware: []string{"pkg:guac/bar"}},
					{Subject: "sha-123", IncludedSoftware: []string{"pkg:guac/baz"}},
				},
				IsOccurrences: []IsOccurrence{
					{Subject: "pkg:guac/foo", Artifact: "sha-xyz"},
					{Subject: "pkg:guac/foo", Artifact: "sha-123"},
				},
			},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{"pkg:guac/bar", "pkg:guac/baz"},
			expectedByDigest: []string{},
		},
		{
			name: "Artifact -> hashEqual -> digest",
			data: GuacData{
				Packages:   []string{"pkg:guac/foo"},
				Artifacts:  []string{"sha-123", "sha-456"},
				HasSboms:   []HasSbom{{Subject: "sha-456", IncludedSoftware: []string{"pkg:guac/foo"}}},
				HashEquals: []HashEqual{{ArtifactA: "sha-123", ArtifactB: "sha-456"}},
			},
			digest:           "sha-123",
			expectedByName:   []string{"pkg:guac/foo"},
			expectedByDigest: []string{"pkg:guac/foo"},
		},
		{
			name: "Artifact -> hashEqual -> digest, digest",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo", "pkg:guac/bar"},
				Artifacts: []string{"sha-123", "sha-456", "sha-789"},
				HasSboms: []HasSbom{
					{Subject: "sha-456", IncludedSoftware: []string{"pkg:guac/foo"}},
					{Subject: "sha-789", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
				HashEquals: []HashEqual{
					{ArtifactA: "sha-123", ArtifactB: "sha-456"},
					{ArtifactA: "sha-123", ArtifactB: "sha-789"},
				},
			},
			digest:           "sha-123",
			expectedByName:   []string{"pkg:guac/foo", "pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/foo", "pkg:guac/bar"},
		},
		{
			name: "Artifact -> hashEqual -> digest -> hashEqual -> digest",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo", "pkg:guac/bar"},
				Artifacts: []string{"sha-123", "sha-456", "sha-789"},
				HasSboms: []HasSbom{
					{Subject: "sha-456", IncludedSoftware: []string{"pkg:guac/foo"}},
					{Subject: "sha-789", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
				HashEquals: []HashEqual{
					{ArtifactA: "sha-123", ArtifactB: "sha-456"},
					{ArtifactA: "sha-456", ArtifactB: "sha-789"},
				},
			},
			digest:           "sha-123",
			expectedByName:   []string{"pkg:guac/foo", "pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/foo", "pkg:guac/bar"},
		},
		{
			name: "digest -> SLSA -> digest -> occurrence -> package",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo"},
				Artifacts:     []string{"sha-123", "sha-xyz"},
				Builders:      []string{"GHA"},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
				HasSlsas:      []HasSlsa{{Subject: "sha-123", BuiltBy: "GHA", BuiltFrom: []string{"sha-xyz"}}},
			},
			digest:           "sha-123",
			expectedByName:   []string{"pkg:guac/foo"},
			expectedByDigest: []string{"pkg:guac/foo"},
		},
		{
			name: "digest -> SLSA -> digest, digest",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo", "pkg:guac/bar"},
				Artifacts: []string{"sha-123", "sha-xyz", "sha-abc"},
				Builders:  []string{"GHA"},
				IsOccurrences: []IsOccurrence{
					{Subject: "pkg:guac/foo", Artifact: "sha-xyz"},
					{Subject: "pkg:guac/bar", Artifact: "sha-abc"},
				},
				HasSlsas: []HasSlsa{{Subject: "sha-123", BuiltBy: "GHA", BuiltFrom: []string{"sha-xyz", "sha-abc"}}},
			},
			digest:           "sha-123",
			expectedByName:   []string{"pkg:guac/foo", "pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/foo", "pkg:guac/bar"},
		},
		/*******
		 * Test some edge cases
		 *******/
		{
			name: "Both Package and occurrence digest in SBOM does not lead to duplicate packages",
			data: GuacData{
				Packages:  []string{"pkg:guac/bar"},
				Artifacts: []string{"sha-123", "sha-xyz"},
				HasSboms: []HasSbom{{
					Subject:               "sha-xyz",
					IncludedSoftware:      []string{"pkg:guac/bar", "sha-123"},
					IncludedIsOccurrences: []IsOccurrence{{Subject: "pkg:guac/bar", Artifact: "sha-123"}},
				}},
			},
			digest:           "sha-xyz",
			expectedByName:   []string{"pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/bar"},
		},
		{
			name: "Dependent is not considered a dependency",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/bar", "pkg:guac/baz"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}},
					{Subject: "pkg:guac/baz", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
			},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{"pkg:guac/bar"},
			expectedByDigest: []string{},
		},
		{
			name: "Transitive dependents are not considered dependencies",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/bar", "pkg:guac/baz"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}},
					{Subject: "pkg:guac/bar", IncludedSoftware: []string{"pkg:guac/baz"}},
				},
			},
			purl:             "pkg:guac/baz",
			expectedByName:   []string{},
			expectedByDigest: []string{},
		},
		{
			name: "Packages with same names but different digests",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo", "pkg:guac/bar", "pkg:guac/baz"},
				Artifacts: []string{"sha-123", "sha-xyz"},
				HasSboms: []HasSbom{
					// foo's sbom contains bar with a digest of sha-123
					{
						Subject:               "pkg:guac/foo",
						IncludedSoftware:      []string{"pkg:guac/bar"},
						IncludedIsOccurrences: []IsOccurrence{{Subject: "pkg:guac/bar", Artifact: "sha-123"}},
					},
					// an digest with digest sha-xyz depends on baz
					{
						Subject:          "sha-xyz",
						IncludedSoftware: []string{"pkg:guac/baz"},
					},
				},
				// sha-xyz is an occurrence of bar
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/bar", Artifact: "sha-xyz"}},
			},
			purl: "pkg:guac/foo",
			// foo depends on baz
			expectedByName:   []string{"pkg:guac/bar", "pkg:guac/baz"},
			expectedByDigest: []string{},
		},
		/*******
		 * Test that equivalent packages aren't considered to be dependencies
		 *******/
		{
			name: "Package IsOccurrence is not considered a dependency",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo"},
				Artifacts:     []string{"sha-123"},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-123"}},
			},
			digest:           "sha-123",
			expectedByName:   []string{},
			expectedByDigest: []string{},
		},
		{
			name: "Artifact IsOccurrence is not considered a dependency",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo", "pkg:guac/bar"},
				Artifacts: []string{"sha-123"},
				IsOccurrences: []IsOccurrence{
					{Subject: "pkg:guac/foo", Artifact: "sha-123"},
					{Subject: "pkg:guac/bar", Artifact: "sha-123"},
				},
			},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{},
			expectedByDigest: []string{},
		},
		{
			name: "Artifact HashEqual is not considered a dependency",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo"},
				Artifacts:     []string{"sha-123", "sha-456"},
				HashEquals:    []HashEqual{{ArtifactA: "sha-123", ArtifactB: "sha-456"}},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-456"}},
			},
			digest:           "sha-123",
			expectedByName:   []string{},
			expectedByDigest: []string{},
		},
		/*******
		 * Test that cycles in the graph are handled correctly
		 *******/
		{
			name: "Equivalence cycle including start node",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo"},
				Artifacts: []string{"sha-123", "sha-456", "sha-789"},
				HashEquals: []HashEqual{
					{ArtifactA: "sha-123", ArtifactB: "sha-456"},
					{ArtifactA: "sha-456", ArtifactB: "sha-789"},
					{ArtifactA: "sha-789", ArtifactB: "sha-123"},
				},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-789"}},
			},
			digest:           "sha-123",
			expectedByName:   []string{},
			expectedByDigest: []string{},
		},
		{
			name: "Equivalence cycle not including start node",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo"},
				Artifacts: []string{"sha-123", "sha-456", "sha-789"},
				HasSboms:  []HasSbom{{Subject: "sha-123", IncludedSoftware: []string{"sha-456"}}},
				HashEquals: []HashEqual{
					{ArtifactA: "sha-456", ArtifactB: "sha-789"},
					{ArtifactA: "sha-789", ArtifactB: "sha-456"},
				},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-789"}},
			},
			digest:           "sha-123",
			expectedByName:   []string{"pkg:guac/foo"},
			expectedByDigest: []string{"pkg:guac/foo"},
		},
		{
			name: "Dependency cycle",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo"},
				Artifacts: []string{"sha-123", "sha-456", "sha-789"},
				HasSboms: []HasSbom{
					{Subject: "sha-123", IncludedSoftware: []string{"sha-456"}},
					{Subject: "sha-456", IncludedSoftware: []string{"sha-789"}},
					{Subject: "sha-789", IncludedSoftware: []string{"sha-123"}},
				},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-789"}},
			},
			digest:           "sha-123",
			expectedByName:   []string{"pkg:guac/foo"},
			expectedByDigest: []string{"pkg:guac/foo"},
		},
		/*******
		 * Test packages with versions
		 *******/
		{
			name: "Package with version is not confused for package without version",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/foo@v1", "pkg:guac/bar", "pkg:guac/bar@v1"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar@v1"}},
					{Subject: "pkg:guac/foo@v1", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
			},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{"pkg:guac/bar@v1"},
			expectedByDigest: []string{},
		},
		{
			name: "Package without version is not confused for package with version",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/foo@v1", "pkg:guac/bar", "pkg:guac/bar@v1"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}},
					{Subject: "pkg:guac/foo@v1", IncludedSoftware: []string{"pkg:guac/bar@v1"}},
				},
			},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{"pkg:guac/bar"},
			expectedByDigest: []string{},
		},
		/*******
		 * Test that the Guac purl special-casing is handled correctly
		 *******/
		{
			name: "Endpoint works for OCI purl",
			data: GuacData{
				Packages: []string{
					"pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye",
					"pkg:oci/static@sha256%3A244fd47e07d10?repository_url=gcr.io%2Fdistroless&tag=latest",
				},
				HasSboms: []HasSbom{{
					Subject:          "pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye",
					IncludedSoftware: []string{"pkg:oci/static@sha256%3A244fd47e07d10?repository_url=gcr.io%2Fdistroless&tag=latest"}},
				}},
			purl:             "pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye",
			expectedByName:   []string{"pkg:oci/static@sha256%3A244fd47e07d10?repository_url=gcr.io%2Fdistroless&tag=latest"},
			expectedByDigest: []string{},
		},
		/*******
		 * A test to record that purls are canonicalized upon ingestion, and so they
		 * may not round-trip.
		 *******/
		{
			name: "Non-canonical purl may not round trip",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:github/Package-url/purl-Spec"},
				HasSboms: []HasSbom{{
					Subject:          "pkg:guac/foo",
					IncludedSoftware: []string{"pkg:github/Package-url/purl-Spec"}},
				}},
			purl:             "pkg:guac/foo",
			expectedByName:   []string{"pkg:github/package-url/purl-spec"}, // lowercased
			expectedByDigest: []string{},
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			/******** set up the test ********/
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)

			encodedPurl := url.QueryEscape(tt.purl)
			encodedArtifact := url.QueryEscape(tt.digest)

			if tt.purl != "" {
				/******** call the endpoint with byName link condition ********/
				resByName, err := server.GetDepsForPackage(ctx, gqlClient, encodedPurl)
				if err != nil {
					t.Fatalf("Endpoint returned unexpected error: %v", err)
				}
				/******** check the output ********/
				var purls []string
				for _, purl := range resByName {
					purls = append(purls, purl)
				}
				if !cmp.Equal(purls, tt.expectedByName, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
					t.Errorf("RetrieveDependencies with byName returned %v, but wanted %v", purls, tt.expectedByName)
				}

			}

			if tt.digest != "" {
				/******** call the endpoint with byDigest link condition ********/
				resByDigest, err := server.GetDepsForArtifact(ctx, gqlClient, encodedArtifact)
				if err != nil {
					t.Fatalf("Endpoint returned unexpected error: %v", err)
				}
				/******** check the output ********/
				var artifacts []string
				for _, artifact := range resByDigest {
					artifacts = append(artifacts, artifact)
				}
				if !cmp.Equal(artifacts, tt.expectedByDigest, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
					t.Errorf("RetrieveDependencies with byDigest returned %v, but wanted %v", artifacts, tt.expectedByDigest)
				}
			}
		})
	}
}
