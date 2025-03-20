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
	"testing"

	gen "github.com/guacsec/guac/pkg/guacrest/generated"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// Tests the dependencies retrieval by package purl.
func Test_RetrieveDependencies_ByPurl(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name           string
		data           GuacData
		purl           string
		expectedByName []string
	}{
		{
			name: "Package -> SBOM -> package",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/bar"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
			},
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:guac/bar"},
		},
		{
			name: "Package -> SBOM -> package, package",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/bar", "pkg:guac/baz"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar", "pkg:guac/baz"}},
				},
			},
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:guac/bar", "pkg:guac/baz"},
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
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:guac/bar", "pkg:guac/baz"},
		},
		{
			name: "Package -> occurrence -> digest",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo", "pkg:guac/bar"},
				Artifacts:     []string{"sha-xyz"},
				HasSboms:      []HasSbom{{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}}},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
			},
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:guac/bar"},
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
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:guac/bar", "pkg:guac/baz"},
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
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:guac/bar"},
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
			purl:           "pkg:guac/baz",
			expectedByName: []string{},
		},
		{
			name: "Packages with same names but different digests",
			data: GuacData{
				Packages:  []string{"pkg:guac/foo", "pkg:guac/bar", "pkg:guac/baz"},
				Artifacts: []string{"sha-123", "sha-xyz"},
				HasSboms: []HasSbom{
					{
						Subject:               "pkg:guac/foo",
						IncludedSoftware:      []string{"pkg:guac/bar"},
						IncludedIsOccurrences: []IsOccurrence{{Subject: "pkg:guac/bar", Artifact: "sha-123"}},
					},
					{
						Subject:          "sha-xyz",
						IncludedSoftware: []string{"pkg:guac/baz"},
					},
				},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/bar", Artifact: "sha-xyz"}},
			},
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:guac/bar", "pkg:guac/baz"},
		},
		{
			name: "Package IsOccurrence is not considered a dependency",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo"},
				Artifacts:     []string{"sha-123"},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-123"}},
			},
			purl:           "pkg:guac/foo",
			expectedByName: []string{},
		},
		{
			name: "Package with version is not confused for package without version",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/foo@v1", "pkg:guac/bar", "pkg:guac/bar@v1"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar@v1"}},
					{Subject: "pkg:guac/foo@v1", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
			},
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:guac/bar@v1"},
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
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:guac/bar"},
		},
		{
			name: "Endpoint works for OCI purl",
			data: GuacData{
				Packages: []string{
					"pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye",
					"pkg:oci/static@sha256%3A244fd47e07d10?repository_url=gcr.io%2Fdistroless&tag=latest",
				},
				HasSboms: []HasSbom{{
					Subject:          "pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye",
					IncludedSoftware: []string{"pkg:oci/static@sha256%3A244fd47e07d10?repository_url=gcr.io%2Fdistroless&tag=latest"},
				}},
			},
			purl:           "pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye",
			expectedByName: []string{"pkg:oci/static@sha256%3A244fd47e07d10?repository_url=gcr.io%2Fdistroless&tag=latest"},
		},
		{
			name: "Non-canonical purl may not round trip",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:github/Package-url/purl-Spec"},
				HasSboms: []HasSbom{{
					Subject:          "pkg:guac/foo",
					IncludedSoftware: []string{"pkg:github/Package-url/purl-Spec"},
				}},
			},
			purl:           "pkg:guac/foo",
			expectedByName: []string{"pkg:github/package-url/purl-spec"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)

			resByName, err := server.GetDepsForPackage(ctx, gqlClient, tt.purl)
			if err != nil {
				t.Fatalf("Endpoint returned unexpected error: %v", err)
			}

			// Check the output
			var purls []string
			for _, purl := range resByName {
				purls = append(purls, purl)
			}
			if !cmp.Equal(purls, tt.expectedByName, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
				t.Errorf("RetrieveDependencies with byName returned %v, but wanted %v", purls, tt.expectedByName)
			}
		})
	}
}

// Tests the dependencies retrieval by artifact digest.
func Test_RetrieveDependencies_ByDigest(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name             string
		data             GuacData
		digest           string
		expectedByDigest []string
	}{
		{
			name: "Digest -> SBOM -> package",
			data: GuacData{
				Packages:  []string{"pkg:guac/bar"},
				Artifacts: []string{"sha-xyz"},
				HasSboms: []HasSbom{
					{Subject: "sha-xyz", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
			},
			digest:           "sha-xyz",
			expectedByDigest: []string{"pkg:guac/bar"},
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
			expectedByDigest: []string{"pkg:guac/bar"},
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
			digest:           "sha-123",
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
			digest:           "sha-123",
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
			digest:           "sha-123",
			expectedByDigest: []string{"pkg:guac/foo", "pkg:guac/bar"},
		},
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
			expectedByDigest: []string{"pkg:guac/bar"},
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
			expectedByDigest: []string{},
		},
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
			expectedByDigest: []string{"pkg:guac/foo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)

			resByDigest, err := server.GetDepsForArtifact(ctx, gqlClient, tt.digest)
			if err != nil {
				t.Fatalf("Endpoint returned unexpected error: %v", err)
			}

			// Check the output
			var artifacts []string
			for _, artifact := range resByDigest {
				artifacts = append(artifacts, artifact)
			}
			if !cmp.Equal(artifacts, tt.expectedByDigest, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
				t.Errorf("RetrieveDependencies with byDigest returned %v, but wanted %v", artifacts, tt.expectedByDigest)
			}
		})
	}
}

func Test_ClientErrorsForPurl(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name string
		data GuacData
		purl string
	}{{
		name: "Package not found",
		purl: "pkg:guac/foo",
	}, {
		name: "Package not found because version was specified",
		data: GuacData{Packages: []string{"pkg:guac/foo"}},
		purl: "pkg:guac/foo@v1",
	}, {
		name: "Package not found because version was not specified",
		data: GuacData{Packages: []string{"pkg:guac/foo@v1"}},
		purl: "pkg:guac/foo",
	}, {
		name: "Package not found due to missing qualifiers",
		data: GuacData{Packages: []string{"pkg:guac/foo?a=b"}},
		purl: "pkg:guac/foo",
	}, {
		name: "Package not found due to providing qualifiers",
		data: GuacData{Packages: []string{"pkg:guac/foo"}},
		purl: "pkg:guac/foo?a=b",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)
			restApi := server.NewDefaultServer(gqlClient)

			res, err := restApi.GetPackageDeps(ctx, gen.GetPackageDepsRequestObject{Purl: tt.purl})
			if err != nil {
				t.Fatalf("RetrieveDependencies returned unexpected error: %v", err)
			}
			if _, ok := res.(gen.GetPackageDeps400JSONResponse); !ok {
				t.Fatalf("Did not receive a 400 Response: recieved %v of type %T", res, res)
			}

		})
	}
}

func Test_ClientErrorsForArtifact(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name   string
		data   GuacData
		digest string
	}{{
		name:   "Artifact not found because version was not specified",
		digest: "sha-abc",
	}, {
		name: "Neither Purl nor Digest provided",
	}, {
		name:   "Badly formatted digest - missing algorithm prefix",
		digest: "abcdef123456", // Missing sha256: or similar prefix
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)
			restApi := server.NewDefaultServer(gqlClient)

			res, err := restApi.GetArtifactDeps(ctx, gen.GetArtifactDepsRequestObject{Digest: tt.digest})
			if err != nil {
				t.Fatalf("GetArtifactDeps returned unexpected error: %v", err)
			}
			if _, ok := res.(gen.GetArtifactDeps400JSONResponse); !ok {
				t.Fatalf("Did not receive a 400 Response: received %v of type %T", res, res)
			}
		})
	}
}
