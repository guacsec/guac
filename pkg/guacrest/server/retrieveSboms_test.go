//
// Copyright 2026 The GUAC Authors.
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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"
)

type sbomStubClient map[string]string

func (c sbomStubClient) MakeRequest(ctx context.Context, req *graphql.Request, resp *graphql.Response) error {
	raw, ok := c[req.OpName]
	if !ok {
		return fmt.Errorf("stub client has no response for operation %q", req.OpName)
	}
	if raw == "" {
		return fmt.Errorf("graphql server is down")
	}
	return json.Unmarshal([]byte(raw), resp.Data)
}

func Test_ListSboms(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	t.Run("Empty graph returns 200 with empty SbomList", func(t *testing.T) {
		gqlClient := SetupTest(t)
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		success, ok := res.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res, res)
		}
		if len(success.SbomList) != 0 {
			t.Errorf("Expected empty SbomList, got %d items", len(success.SbomList))
		}
		if success.PaginationInfo.TotalCount == nil || *success.PaginationInfo.TotalCount != 0 {
			t.Errorf("TotalCount = %v, want 0", success.PaginationInfo.TotalCount)
		}
	})

	t.Run("SBOM whose subject is a package", func(t *testing.T) {
		gqlClient := SetupTest(t)
		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/foo@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/foo@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:              "https://example.com/sbom1",
						Algorithm:        "sha256",
						Digest:           "digest-1",
						DownloadLocation: "https://example.com/sbom1.json",
						Origin:           "test-origin",
						Collector:        "test-collector",
						DocumentRef:      "doc-ref-1",
						KnownSince:       now,
					},
				},
			},
		})
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		success, ok := res.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res, res)
		}
		if len(success.SbomList) != 1 {
			t.Fatalf("Expected 1 SBOM, got %d", len(success.SbomList))
		}
		sbom := success.SbomList[0]
		if sbom.Subject.Type != gen.Package {
			t.Errorf("Subject.Type = %v, want %v", sbom.Subject.Type, gen.Package)
		}
		if sbom.Subject.Purl == nil || *sbom.Subject.Purl != "pkg:guac/foo@v1" {
			t.Errorf("Subject.Purl = %v, want pkg:guac/foo@v1", sbom.Subject.Purl)
		}
		if sbom.Uri != "https://example.com/sbom1" {
			t.Errorf("Uri = %v, want https://example.com/sbom1", sbom.Uri)
		}
		if sbom.Algorithm != "sha256" {
			t.Errorf("Algorithm = %v, want sha256", sbom.Algorithm)
		}
		if sbom.Digest != "digest-1" {
			t.Errorf("Digest = %v, want digest-1", sbom.Digest)
		}
		if sbom.DownloadLocation == nil || *sbom.DownloadLocation != "https://example.com/sbom1.json" {
			t.Errorf("DownloadLocation = %v, want https://example.com/sbom1.json", sbom.DownloadLocation)
		}
		if sbom.Origin == nil || *sbom.Origin != "test-origin" {
			t.Errorf("Origin = %v, want test-origin", sbom.Origin)
		}
		if sbom.Collector == nil || *sbom.Collector != "test-collector" {
			t.Errorf("Collector = %v, want test-collector", sbom.Collector)
		}
		if sbom.DocumentRef == nil || *sbom.DocumentRef != "doc-ref-1" {
			t.Errorf("DocumentRef = %v, want doc-ref-1", sbom.DocumentRef)
		}
		if success.PaginationInfo.TotalCount == nil || *success.PaginationInfo.TotalCount != 1 {
			t.Errorf("TotalCount = %v, want 1", success.PaginationInfo.TotalCount)
		}
	})

	t.Run("SBOM whose subject is an artifact", func(t *testing.T) {
		gqlClient := SetupTest(t)
		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Artifacts: []string{"art-digest-1"},
			HasSboms: []HasSbom{
				{
					Subject: "art-digest-1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:              "https://example.com/sbom-art",
						Algorithm:        "sha256",
						Digest:           "sbom-digest-art",
						DownloadLocation: "",
						Origin:           "test-origin",
						Collector:        "test-collector",
						DocumentRef:      "",
						KnownSince:       now,
					},
				},
			},
		})
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		success, ok := res.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res, res)
		}
		if len(success.SbomList) != 1 {
			t.Fatalf("Expected 1 SBOM, got %d", len(success.SbomList))
		}
		sbom := success.SbomList[0]
		if sbom.Subject.Type != gen.Artifact {
			t.Errorf("Subject.Type = %v, want %v", sbom.Subject.Type, gen.Artifact)
		}
		expectedArtifact := "sha256:art-digest-1"
		if sbom.Subject.Artifact == nil || *sbom.Subject.Artifact != expectedArtifact {
			t.Errorf("Subject.Artifact = %v, want %v", sbom.Subject.Artifact, expectedArtifact)
		}
		if sbom.DownloadLocation == nil || *sbom.DownloadLocation != "" {
			t.Errorf("DownloadLocation = %v, want empty string", sbom.DownloadLocation)
		}
		if sbom.DocumentRef == nil || *sbom.DocumentRef != "" {
			t.Errorf("DocumentRef = %v, want empty string", sbom.DocumentRef)
		}
	})

	t.Run("Match through includedSoftware only", func(t *testing.T) {
		gqlClient := SetupTest(t)
		now := time.Now().UTC()
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/subject-pkg@v1", "pkg:guac/included-pkg@v1"},
			HasSboms: []HasSbom{
				{
					Subject:          "pkg:guac/subject-pkg@v1",
					IncludedSoftware: []string{"pkg:guac/included-pkg@v1"},
					Spec: &gql.HasSBOMInputSpec{
						Uri:        "https://example.com/sbom-incl",
						Algorithm:  "sha256",
						Digest:     "digest-incl",
						KnownSince: now,
					},
				},
			},
		})
		restApi := server.NewDefaultServer(gqlClient)

		purl := "pkg:guac/included-pkg@v1"
		res, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{
			Params: gen.ListSbomsParams{Package: &purl},
		})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		success, ok := res.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res, res)
		}
		if len(success.SbomList) != 1 {
			t.Fatalf("Expected 1 SBOM, got %d", len(success.SbomList))
		}
		if success.SbomList[0].Uri != "https://example.com/sbom-incl" {
			t.Errorf("Uri = %v, want https://example.com/sbom-incl", success.SbomList[0].Uri)
		}

		// Valid purl matching nothing in graph returns empty list
		unrelated := "pkg:guac/nonexistent@v1"
		resUnrelated, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{
			Params: gen.ListSbomsParams{Package: &unrelated},
		})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		successUnrelated, ok := resUnrelated.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", resUnrelated, resUnrelated)
		}
		if len(successUnrelated.SbomList) != 0 {
			t.Errorf("Expected 0 SBOMs, got %d", len(successUnrelated.SbomList))
		}
		if successUnrelated.PaginationInfo.TotalCount == nil || *successUnrelated.PaginationInfo.TotalCount != 0 {
			t.Errorf("TotalCount = %v, want 0", successUnrelated.PaginationInfo.TotalCount)
		}
	})

	t.Run("Versionless purl matching several versions", func(t *testing.T) {
		gqlClient := SetupTest(t)
		now := time.Now().UTC()
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/multi@v1", "pkg:guac/multi@v2", "pkg:guac/other@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/multi@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:        "https://example.com/sbom-v1",
						Algorithm:  "sha256",
						Digest:     "digest-v1",
						KnownSince: now,
					},
				},
				{
					Subject: "pkg:guac/multi@v2",
					Spec: &gql.HasSBOMInputSpec{
						Uri:        "https://example.com/sbom-v2",
						Algorithm:  "sha256",
						Digest:     "digest-v2",
						KnownSince: now,
					},
				},
				{
					Subject: "pkg:guac/other@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:        "https://example.com/sbom-other",
						Algorithm:  "sha256",
						Digest:     "digest-other",
						KnownSince: now,
					},
				},
			},
		})
		restApi := server.NewDefaultServer(gqlClient)

		versionlessPurl := "pkg:guac/multi"
		res, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{
			Params: gen.ListSbomsParams{Package: &versionlessPurl},
		})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		success, ok := res.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res, res)
		}
		if len(success.SbomList) != 2 {
			t.Fatalf("Expected 2 SBOMs, got %d", len(success.SbomList))
		}
		uris := []string{success.SbomList[0].Uri, success.SbomList[1].Uri}
		expectedUris := []string{"https://example.com/sbom-v1", "https://example.com/sbom-v2"}
		if !cmp.Equal(uris, expectedUris, cmpopts.SortSlices(stdcmp.Less[string])) {
			t.Errorf("Uris = %v, want %v", uris, expectedUris)
		}
	})

	t.Run("SBOM that matches on both subject and includedSoftware returned only once", func(t *testing.T) {
		gqlClient := SetupTest(t)
		now := time.Now().UTC()
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/dup@v1"},
			HasSboms: []HasSbom{
				{
					Subject:          "pkg:guac/dup@v1",
					IncludedSoftware: []string{"pkg:guac/dup@v1"},
					Spec: &gql.HasSBOMInputSpec{
						Uri:        "https://example.com/sbom-dup",
						Algorithm:  "sha256",
						Digest:     "digest-dup",
						KnownSince: now,
					},
				},
			},
		})
		restApi := server.NewDefaultServer(gqlClient)

		purl := "pkg:guac/dup@v1"
		res, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{
			Params: gen.ListSbomsParams{Package: &purl},
		})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		success, ok := res.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res, res)
		}
		if len(success.SbomList) != 1 {
			t.Fatalf("Expected 1 SBOM, got %d", len(success.SbomList))
		}
		if success.PaginationInfo.TotalCount == nil || *success.PaginationInfo.TotalCount != 1 {
			t.Errorf("TotalCount = %v, want 1", success.PaginationInfo.TotalCount)
		}
	})

	t.Run("Pagination across two pages sorted by knownSince descending", func(t *testing.T) {
		gqlClient := SetupTest(t)
		t1 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		t2 := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
		t3 := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/p1@v1", "pkg:guac/p2@v1", "pkg:guac/p3@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/p1@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:        "https://example.com/sbom-1",
						Algorithm:  "sha256",
						Digest:     "digest-1",
						KnownSince: t1,
					},
				},
				{
					Subject: "pkg:guac/p2@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:        "https://example.com/sbom-2",
						Algorithm:  "sha256",
						Digest:     "digest-2",
						KnownSince: t2,
					},
				},
				{
					Subject: "pkg:guac/p3@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:        "https://example.com/sbom-3",
						Algorithm:  "sha256",
						Digest:     "digest-3",
						KnownSince: t3,
					},
				},
			},
		})
		restApi := server.NewDefaultServer(gqlClient)

		pageSize := 2
		// Page 1
		res1, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{
			Params: gen.ListSbomsParams{
				PaginationSpec: &gen.PaginationSpec{PageSize: &pageSize},
			},
		})
		if err != nil {
			t.Fatalf("ListSboms page 1 returned unexpected error: %v", err)
		}
		success1, ok := res1.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res1, res1)
		}
		if len(success1.SbomList) != 2 {
			t.Fatalf("Expected 2 SBOMs on page 1, got %d", len(success1.SbomList))
		}
		if success1.PaginationInfo.NextCursor == nil {
			t.Fatalf("Expected NextCursor on page 1, got nil")
		}
		if success1.PaginationInfo.TotalCount == nil || *success1.PaginationInfo.TotalCount != 3 {
			t.Errorf("TotalCount = %v, want 3", success1.PaginationInfo.TotalCount)
		}
		// Newest first: t3, then t2
		if success1.SbomList[0].Uri != "https://example.com/sbom-3" {
			t.Errorf("Page 1 first item = %v, want https://example.com/sbom-3", success1.SbomList[0].Uri)
		}
		if success1.SbomList[1].Uri != "https://example.com/sbom-2" {
			t.Errorf("Page 1 second item = %v, want https://example.com/sbom-2", success1.SbomList[1].Uri)
		}

		// Page 2
		res2, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{
			Params: gen.ListSbomsParams{
				PaginationSpec: &gen.PaginationSpec{
					PageSize: &pageSize,
					Cursor:   success1.PaginationInfo.NextCursor,
				},
			},
		})
		if err != nil {
			t.Fatalf("ListSboms page 2 returned unexpected error: %v", err)
		}
		success2, ok := res2.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res2, res2)
		}
		if len(success2.SbomList) != 1 {
			t.Fatalf("Expected 1 SBOM on page 2, got %d", len(success2.SbomList))
		}
		if success2.PaginationInfo.NextCursor != nil {
			t.Errorf("Expected nil NextCursor on page 2, got %v", success2.PaginationInfo.NextCursor)
		}
		if success2.SbomList[0].Uri != "https://example.com/sbom-1" {
			t.Errorf("Page 2 item = %v, want https://example.com/sbom-1", success2.SbomList[0].Uri)
		}
	})

	t.Run("Invalid purl returns 400", func(t *testing.T) {
		gqlClient := SetupTest(t)
		restApi := server.NewDefaultServer(gqlClient)

		invalidPurl := "not-a-purl"
		res, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{
			Params: gen.ListSbomsParams{Package: &invalidPurl},
		})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.ListSboms400JSONResponse); !ok {
			t.Fatalf("Expected 400 response, got %T: %v", res, res)
		}
	})

	t.Run("Backend failure returns 502", func(t *testing.T) {
		// Failing HasSBOMs query
		client1 := sbomStubClient{"HasSBOMs": ""}
		restApi1 := server.NewDefaultServer(client1)
		res1, err := restApi1.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		if _, ok := res1.(gen.ListSboms502JSONResponse); !ok {
			t.Fatalf("Expected 502 response, got %T: %v", res1, res1)
		}

		// Failing Packages query when package filter is provided
		client2 := sbomStubClient{"Packages": ""}
		restApi2 := server.NewDefaultServer(client2)
		purl := "pkg:guac/foo@v1"
		res2, err := restApi2.ListSboms(ctx, gen.ListSbomsRequestObject{
			Params: gen.ListSbomsParams{Package: &purl},
		})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		if _, ok := res2.(gen.ListSboms502JSONResponse); !ok {
			t.Fatalf("Expected 502 response, got %T: %v", res2, res2)
		}
	})
}
