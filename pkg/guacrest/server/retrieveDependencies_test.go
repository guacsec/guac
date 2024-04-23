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

package server_test

import (
	stdcmp "cmp"
	"context"
	"testing"

	cmp "github.com/google/go-cmp/cmp"

	"github.com/google/go-cmp/cmp/cmpopts"
	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	api "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"
)

// Tests the edges in ByName that are not in ByDigest
func Test_RetrieveDependencies(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name string
		data GuacData

		// Only specify Purl or Digest. The test will set linkCondition, because both are tested
		input api.RetrieveDependenciesParams

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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-xyz")},
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
			expectedByName:   []string{"pkg:guac/bar", "pkg:guac/baz"},
			expectedByDigest: []string{},
		},
		{
			name: "Artifact -> SBOM -> artifact -> SBOM -> package",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo"},
				Artifacts: []string{"sha-xyz", "sha-123"},
				HasSboms: []HasSbom{
					{Subject: "sha-xyz", IncludedSoftware: []string{"sha-123"}},
					{Subject: "sha-123", IncludedSoftware: []string{"pkg:guac/foo"}},
				},
			},
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-xyz")},
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-xyz")},
			expectedByName:   []string{"pkg:guac/foo", "pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/bar"},
		},
		{
			name: "artifact -> occurrence -> package",
			data: GuacData{
				Packages:      []string{"pkg:guac/bar"},
				Artifacts:     []string{"sha-123", "sha-xyz"},
				HasSboms:      []HasSbom{{Subject: "sha-xyz", IncludedSoftware: []string{"sha-123"}}},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/bar", Artifact: "sha-123"}},
			},
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-xyz")},
			expectedByName:   []string{"pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/bar"},
		},
		{
			name: "Package -> occurrence -> artifact",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo", "pkg:guac/bar"},
				Artifacts:     []string{"sha-xyz"},
				HasSboms:      []HasSbom{{Subject: "sha-xyz", IncludedSoftware: []string{"pkg:guac/bar"}}},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
			},
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
			expectedByName:   []string{"pkg:guac/bar"},
			expectedByDigest: []string{},
		},
		{
			name: "package -> occurrence -> artifact, artifact",
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
			expectedByName:   []string{"pkg:guac/bar", "pkg:guac/baz"},
			expectedByDigest: []string{},
		},
		{
			name: "Artifact -> hashEqual -> artifact",
			data: GuacData{
				Packages:   []string{"pkg:guac/foo"},
				Artifacts:  []string{"sha-123", "sha-456"},
				HasSboms:   []HasSbom{{Subject: "sha-456", IncludedSoftware: []string{"pkg:guac/foo"}}},
				HashEquals: []HashEqual{{ArtifactA: "sha-123", ArtifactB: "sha-456"}},
			},
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
			expectedByName:   []string{"pkg:guac/foo"},
			expectedByDigest: []string{"pkg:guac/foo"},
		},
		{
			name: "Artifact -> hashEqual -> artifact, artifact",
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
			expectedByName:   []string{"pkg:guac/foo", "pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/foo", "pkg:guac/bar"},
		},
		{
			name: "Artifact -> hashEqual -> artifact -> hashEqual -> artifact",
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
			expectedByName:   []string{"pkg:guac/foo", "pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/foo", "pkg:guac/bar"},
		},
		{
			name: "artifact -> SLSA -> artifact -> occurrence -> package",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo"},
				Artifacts:     []string{"sha-123", "sha-xyz"},
				Builders:      []string{"GHA"},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
				HasSlsas:      []HasSlsa{{Subject: "sha-123", BuiltBy: "GHA", BuiltFrom: []string{"sha-xyz"}}},
			},
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
			expectedByName:   []string{"pkg:guac/foo"},
			expectedByDigest: []string{"pkg:guac/foo"},
		},
		{
			name: "artifact -> SLSA -> artifact, artifact",
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
			expectedByName:   []string{"pkg:guac/foo", "pkg:guac/bar"},
			expectedByDigest: []string{"pkg:guac/foo", "pkg:guac/bar"},
		},
		/*******
		 * Test some edge cases
		 *******/
		{
			name: "Both Package and occurrence artifact in SBOM does not lead to duplicate packages",
			data: GuacData{
				Packages:  []string{"pkg:guac/bar"},
				Artifacts: []string{"sha-123", "sha-xyz"},
				HasSboms: []HasSbom{{
					Subject:               "sha-xyz",
					IncludedSoftware:      []string{"pkg:guac/bar", "sha-123"},
					IncludedIsOccurrences: []IsOccurrence{{Subject: "pkg:guac/bar", Artifact: "sha-123"}},
				}},
			},
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-xyz")},
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/baz")},
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
					// an artifact with digest sha-xyz depends on baz
					{
						Subject:          "sha-xyz",
						IncludedSoftware: []string{"pkg:guac/baz"},
					},
				},
				// sha-xyz is an occurrence of bar
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/bar", Artifact: "sha-xyz"}},
			},
			input: api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
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
			input:            api.RetrieveDependenciesParams{Digest: ptrfrom.String("sha-123")},
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye")},
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
			input:            api.RetrieveDependenciesParams{Purl: ptrfrom.String("pkg:guac/foo")},
			expectedByName:   []string{"pkg:github/package-url/purl-spec"}, // lowercased
			expectedByDigest: []string{},
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			/******** set up the test ********/
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)

			restApi := server.NewDefaultServer(gqlClient)

			/******** call the endpoint with byName link condition ********/
			inputByName := tt.input
			inputByName.LinkCondition = ptrfrom.Any(api.Name)
			resByName, err := restApi.RetrieveDependencies(ctx, api.RetrieveDependenciesRequestObject{Params: inputByName})
			if err != nil {
				t.Fatalf("Endpoint returned unexpected error: %v", err)
			}
			/******** check the output ********/
			switch v := resByName.(type) {
			case api.RetrieveDependencies200JSONResponse:
				if !cmp.Equal(v.PurlList, tt.expectedByName, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
					t.Errorf("RetrieveDependencies with byName returned %v, but wanted %v", v.PurlList, tt.expectedByName)
				}
			default:
				t.Errorf("RetrieveDependencies with byName returned unexpected error: %v", v)
			}

			/******** call the endpoint with byDigest link condition ********/
			inputByDigest := tt.input
			inputByDigest.LinkCondition = ptrfrom.Any(api.Digest)
			resByDigest, err := restApi.RetrieveDependencies(ctx, api.RetrieveDependenciesRequestObject{Params: inputByDigest})
			if err != nil {
				t.Fatalf("Endpoint returned unexpected error: %v", err)
			}
			/******** check the output ********/
			switch v := resByDigest.(type) {
			case api.RetrieveDependencies200JSONResponse:
				if !cmp.Equal(v.PurlList, tt.expectedByDigest, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
					t.Errorf("RetrieveDependencies with byDigest returned %v, but wanted %v", v.PurlList, tt.expectedByDigest)
				}
			default:
				t.Errorf("RetrieveDependencies with byDigest returned unexpected error: %v", v)
			}
		})
	}
}

func Test_ClientErrors(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name  string
		data  GuacData
		input api.RetrieveDependenciesParams
	}{{
		name: "Package not found",
		input: api.RetrieveDependenciesParams{
			Purl:          ptrfrom.String("pkg:guac/foo"),
			LinkCondition: ptrfrom.Any(api.Name),
		},
	}, {
		name: "Package not found because version was specified",
		data: GuacData{Packages: []string{"pkg:guac/foo"}},
		input: api.RetrieveDependenciesParams{
			Purl:          ptrfrom.String("pkg:guac/foo@v1"),
			LinkCondition: ptrfrom.Any(api.Name),
		},
	}, {
		name: "Package not found because version was not specified",
		data: GuacData{Packages: []string{"pkg:guac/foo@v1"}},
		input: api.RetrieveDependenciesParams{
			Purl:          ptrfrom.String("pkg:guac/foo"),
			LinkCondition: ptrfrom.Any(api.Name),
		},
	}, {
		name: "Package not found due to missing qualifiers",
		data: GuacData{Packages: []string{"pkg:guac/foo?a=b"}},
		input: api.RetrieveDependenciesParams{
			Purl:          ptrfrom.String("pkg:guac/foo"),
			LinkCondition: ptrfrom.Any(api.Name),
		},
	}, {
		name: "Package not found due to providing qualifiers",
		data: GuacData{Packages: []string{"pkg:guac/foo"}},
		input: api.RetrieveDependenciesParams{
			Purl:          ptrfrom.String("pkg:guac/foo?a=b"),
			LinkCondition: ptrfrom.Any(api.Name),
		},
	}, {
		name: "Artifact not found because version was not specified",
		input: api.RetrieveDependenciesParams{
			Digest:        ptrfrom.String("sha-abc"),
			LinkCondition: ptrfrom.Any(api.Name),
		},
	}, {
		name: "Neither Purl nor Digest provided",
	}, {
		name: "Unrecognized link condition",
		input: api.RetrieveDependenciesParams{
			Digest:        ptrfrom.String("sha-abc"),
			LinkCondition: ptrfrom.Any(api.RetrieveDependenciesParamsLinkCondition("foo")),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)
			restApi := server.NewDefaultServer(gqlClient)

			res, err := restApi.RetrieveDependencies(ctx, api.RetrieveDependenciesRequestObject{Params: tt.input})
			if err != nil {
				t.Fatalf("RetrieveDependencies returned unexpected error: %v", err)
			}
			if _, ok := res.(api.RetrieveDependencies400JSONResponse); !ok {
				t.Fatalf("Did not receive a 400 Response: recieved %v of type %T", res, res)
			}

		})
	}
}

func Test_DefaultLinkCondition(t *testing.T) {
	/******** set up the test ********/
	ctx := logging.WithLogger(context.Background())
	gqlClient := SetupTest(t)
	restApi := server.NewDefaultServer(gqlClient)
	data := GuacData{
		Packages: []string{"pkg:guac/foo", "pkg:guac/bar"},
		HasSboms: []HasSbom{{
			Subject:          "pkg:guac/foo",
			IncludedSoftware: []string{"pkg:guac/bar"}},
		}}
	Ingest(ctx, t, gqlClient, data)

	input := api.RetrieveDependenciesParams{
		Purl: ptrfrom.String("pkg:guac/foo"),
	}

	/******** call the endpoint ********/
	res, err := restApi.RetrieveDependencies(ctx, api.RetrieveDependenciesRequestObject{Params: input})
	if err != nil {
		t.Fatalf("RetrieveDependencies returned unexpected error: %v", err)
	}

	/******** check the output ********/
	switch v := res.(type) {
	case api.RetrieveDependencies200JSONResponse:
		// that the default is byDigest is tested by asserting that no edges only in byName are used
		if len(v.PurlList) != 0 {
			t.Errorf("RetrieveDependencies returned %v, but no dependencies were expected", v)
		}
	default:
		t.Errorf("RetrieveDependencies returned unexpected error: %v", v)
	}

}
