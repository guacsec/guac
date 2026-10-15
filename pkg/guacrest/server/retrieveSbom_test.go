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
	"context"
	"testing"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/vektah/gqlparser/v2/gqlerror"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"
)

// malformedIDClient mimics the ent backend rejecting an ID that is not a
// uuid: the lookup fails at the database level, so the GraphQL server reports
// a resolver error instead of an empty result.
type malformedIDClient struct{}

func (malformedIDClient) MakeRequest(_ context.Context, _ *graphql.Request, _ *graphql.Response) error {
	return gqlerror.List{&gqlerror.Error{Message: `invalid input syntax for type uuid: "not-a-uuid"`}}
}

func Test_GetSbom(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	t.Run("SBOM found by id returns 200", func(t *testing.T) {
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

		// The id is the one the list endpoint returns, which is the contract
		// between the two endpoints.
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms returned unexpected error: %v", err)
		}
		list, ok := listRes.(gen.ListSboms200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response from ListSboms, got %T: %v", listRes, listRes)
		}
		if len(list.SbomList) != 1 {
			t.Fatalf("Expected 1 SBOM, got %d", len(list.SbomList))
		}
		id := list.SbomList[0].Id

		res, err := restApi.GetSbom(ctx, gen.GetSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("GetSbom returned unexpected error: %v", err)
		}
		success, ok := res.(gen.GetSbom200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res, res)
		}
		sbom := gen.Sbom(success.SbomJSONResponse)
		if sbom.Id != id {
			t.Errorf("Id = %v, want %v", sbom.Id, id)
		}
		if sbom.Subject.Type != gen.Package {
			t.Errorf("Subject.Type = %v, want %v", sbom.Subject.Type, gen.Package)
		}
		if sbom.Subject.Purl == nil || *sbom.Subject.Purl != "pkg:guac/foo@v1" {
			t.Errorf("Subject.Purl = %v, want pkg:guac/foo@v1", sbom.Subject.Purl)
		}
		if sbom.Uri != "https://example.com/sbom1" {
			t.Errorf("Uri = %v, want https://example.com/sbom1", sbom.Uri)
		}
		if sbom.DownloadLocation == nil || *sbom.DownloadLocation != "https://example.com/sbom1.json" {
			t.Errorf("DownloadLocation = %v, want https://example.com/sbom1.json", sbom.DownloadLocation)
		}
	})

	t.Run("Unknown id returns 404", func(t *testing.T) {
		gqlClient := SetupTest(t)
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.GetSbom(ctx, gen.GetSbomRequestObject{Id: "no-such-id"})
		if err != nil {
			t.Fatalf("GetSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.GetSbom404JSONResponse); !ok {
			t.Fatalf("Expected 404 response, got %T: %v", res, res)
		}
	})

	t.Run("Malformed id on the ent backend returns 404, not 502", func(t *testing.T) {
		restApi := server.NewDefaultServer(malformedIDClient{})

		res, err := restApi.GetSbom(ctx, gen.GetSbomRequestObject{Id: "not-a-uuid"})
		if err != nil {
			t.Fatalf("GetSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.GetSbom404JSONResponse); !ok {
			t.Fatalf("Expected 404 response, got %T: %v", res, res)
		}
	})

	t.Run("Backend failure returns 502", func(t *testing.T) {
		restApi := server.NewDefaultServer(sbomStubClient{"HasSBOMs": ""})

		res, err := restApi.GetSbom(ctx, gen.GetSbomRequestObject{Id: "1"})
		if err != nil {
			t.Fatalf("GetSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.GetSbom502JSONResponse); !ok {
			t.Fatalf("Expected 502 response, got %T: %v", res, res)
		}
	})
}
