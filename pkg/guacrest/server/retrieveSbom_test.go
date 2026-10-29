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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/klauspost/compress/zstd"
	"github.com/vektah/gqlparser/v2/gqlerror"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/blob"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/handler/processor"
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

func Test_DownloadSbom(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	t.Run("guacrest has no usable blob store returns 503", func(t *testing.T) {
		gqlClient := SetupTest(t)
		restApi := server.NewDefaultServer(gqlClient) // blobStore is nil

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: "some-id"})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.DownloadSbom503JSONResponse); !ok {
			t.Fatalf("Expected 503 response, got %T: %v", res, res)
		}
	})

	t.Run("Unknown id returns 404", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}
		restApi := server.NewDefaultServer(gqlClient, blobStore)

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: "no-such-id"})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.DownloadSbom404JSONResponse); !ok {
			t.Fatalf("Expected 404 response, got %T: %v", res, res)
		}
	})

	t.Run("Malformed id on the ent backend returns 404, not 502", func(t *testing.T) {
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}
		restApi := server.NewDefaultServer(malformedIDClient{}, blobStore)

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: "not-a-uuid"})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.DownloadSbom404JSONResponse); !ok {
			t.Fatalf("Expected 404 response, got %T: %v", res, res)
		}
	})

	t.Run("Backend failure returns 502", func(t *testing.T) {
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}
		restApi := server.NewDefaultServer(sbomStubClient{"HasSBOMs": ""}, blobStore)

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: "1"})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.DownloadSbom502JSONResponse); !ok {
			t.Fatalf("Expected 502 response, got %T: %v", res, res)
		}
	})

	t.Run("Empty documentRef returns 404", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/pkg-empty-ref@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/pkg-empty-ref@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:         "https://example.com/sbom-empty",
						Algorithm:   "sha256",
						Digest:      "digest-empty",
						DocumentRef: "",
						KnownSince:  now,
					},
				},
			},
		})
		restApi := server.NewDefaultServer(gqlClient, blobStore)
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms failed: %v", err)
		}
		list := listRes.(gen.ListSboms200JSONResponse)
		var id string
		for _, s := range list.SbomList {
			if s.Uri == "https://example.com/sbom-empty" {
				id = s.Id
				break
			}
		}

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.DownloadSbom404JSONResponse); !ok {
			t.Fatalf("Expected 404 response for empty documentRef, got %T: %v", res, res)
		}
	})

	t.Run("Missing key in blob store returns 404", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/pkg-missing-blob@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/pkg-missing-blob@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:         "https://example.com/sbom-missing",
						Algorithm:   "sha256",
						Digest:      "digest-missing",
						DocumentRef: "sha256_missing_key",
						KnownSince:  now,
					},
				},
			},
		})
		restApi := server.NewDefaultServer(gqlClient, blobStore)
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms failed: %v", err)
		}
		list := listRes.(gen.ListSboms200JSONResponse)
		var id string
		for _, s := range list.SbomList {
			if s.Uri == "https://example.com/sbom-missing" {
				id = s.Id
				break
			}
		}

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.DownloadSbom404JSONResponse); !ok {
			t.Fatalf("Expected 404 response for missing blob key, got %T: %v", res, res)
		}
	})

	t.Run("Corrupted document in blob store returns 500", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}
		docRef := "sha256_corrupt_doc"
		if err := blobStore.Write(ctx, docRef, []byte("not-valid-json")); err != nil {
			t.Fatalf("failed to write corrupted blob: %v", err)
		}

		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/pkg-corrupt-doc@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/pkg-corrupt-doc@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:         "https://example.com/sbom-corrupt",
						Algorithm:   "sha256",
						Digest:      "digest-corrupt",
						DocumentRef: docRef,
						KnownSince:  now,
					},
				},
			},
		})
		restApi := server.NewDefaultServer(gqlClient, blobStore)
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms failed: %v", err)
		}
		list := listRes.(gen.ListSboms200JSONResponse)
		var id string
		for _, s := range list.SbomList {
			if s.Uri == "https://example.com/sbom-corrupt" {
				id = s.Id
				break
			}
		}

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.DownloadSbom500JSONResponse); !ok {
			t.Fatalf("Expected 500 response for corrupted blob, got %T: %v", res, res)
		}
	})

	t.Run("Successful download of JSON SBOM returns 200 with raw document bytes", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}

		docRef := "sha256_valid_json_sbom"
		rawSbom := []byte(`{"spdxVersion":"SPDX-2.3","name":"my-app"}`)
		doc := processor.Document{
			Blob:   rawSbom,
			Format: processor.FormatJSON,
		}
		docBytes, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("failed to marshal doc: %v", err)
		}
		if err := blobStore.Write(ctx, docRef, docBytes); err != nil {
			t.Fatalf("failed to write doc to blob store: %v", err)
		}

		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/pkg-valid-json@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/pkg-valid-json@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:         "https://example.com/sbom-valid-json",
						Algorithm:   "sha256",
						Digest:      "digest-json",
						DocumentRef: docRef,
						KnownSince:  now,
					},
				},
			},
		})

		restApi := server.NewDefaultServer(gqlClient, blobStore)
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms failed: %v", err)
		}
		list := listRes.(gen.ListSboms200JSONResponse)
		var id string
		for _, s := range list.SbomList {
			if s.Uri == "https://example.com/sbom-valid-json" {
				id = s.Id
				break
			}
		}

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}

		rec := httptest.NewRecorder()
		if err := res.VisitDownloadSbomResponse(rec); err != nil {
			t.Fatalf("VisitDownloadSbomResponse returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status code = %v, want %v", rec.Code, http.StatusOK)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %v, want application/json", ct)
		}
		expectedCD := `attachment; filename="` + docRef + `.json"`
		if cd := rec.Header().Get("Content-Disposition"); cd != expectedCD {
			t.Errorf("Content-Disposition = %v, want %v", cd, expectedCD)
		}
		if !bytes.Equal(rec.Body.Bytes(), rawSbom) {
			t.Errorf("body = %s, want %s", rec.Body.String(), string(rawSbom))
		}
	})

	t.Run("Successful download of JSON_LINES SBOM returns 200 with application/x-ndjson", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}

		docRef := "sha256_valid_jsonlines_sbom"
		rawSbom := []byte("{\"line\":1}\n{\"line\":2}\n")
		doc := processor.Document{
			Blob:   rawSbom,
			Format: processor.FormatJSONLines,
		}
		docBytes, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("failed to marshal doc: %v", err)
		}
		if err := blobStore.Write(ctx, docRef, docBytes); err != nil {
			t.Fatalf("failed to write doc to blob store: %v", err)
		}

		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/pkg-valid-jsonlines@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/pkg-valid-jsonlines@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:         "https://example.com/sbom-valid-jsonlines",
						Algorithm:   "sha256",
						Digest:      "digest-jsonlines",
						DocumentRef: docRef,
						KnownSince:  now,
					},
				},
			},
		})

		restApi := server.NewDefaultServer(gqlClient, blobStore)
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms failed: %v", err)
		}
		list := listRes.(gen.ListSboms200JSONResponse)
		var id string
		for _, s := range list.SbomList {
			if s.Uri == "https://example.com/sbom-valid-jsonlines" {
				id = s.Id
				break
			}
		}

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}

		rec := httptest.NewRecorder()
		if err := res.VisitDownloadSbomResponse(rec); err != nil {
			t.Fatalf("VisitDownloadSbomResponse returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status code = %v, want %v", rec.Code, http.StatusOK)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
			t.Errorf("Content-Type = %v, want application/x-ndjson", ct)
		}
		expectedCD := `attachment; filename="` + docRef + `.jsonl"`
		if cd := rec.Header().Get("Content-Disposition"); cd != expectedCD {
			t.Errorf("Content-Disposition = %v, want %v", cd, expectedCD)
		}
		if !bytes.Equal(rec.Body.Bytes(), rawSbom) {
			t.Errorf("body = %s, want %s", rec.Body.String(), string(rawSbom))
		}
	})

	t.Run("Successful download of XML SBOM returns 200 with application/xml", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}

		docRef := "sha256_valid_xml_sbom"
		rawSbom := []byte("<bom><metadata></metadata></bom>")
		doc := processor.Document{
			Blob:   rawSbom,
			Format: processor.FormatXML,
		}
		docBytes, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("failed to marshal doc: %v", err)
		}
		if err := blobStore.Write(ctx, docRef, docBytes); err != nil {
			t.Fatalf("failed to write doc to blob store: %v", err)
		}

		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/pkg-valid-xml@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/pkg-valid-xml@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:         "https://example.com/sbom-valid-xml",
						Algorithm:   "sha256",
						Digest:      "digest-xml",
						DocumentRef: docRef,
						KnownSince:  now,
					},
				},
			},
		})

		restApi := server.NewDefaultServer(gqlClient, blobStore)
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms failed: %v", err)
		}
		list := listRes.(gen.ListSboms200JSONResponse)
		var id string
		for _, s := range list.SbomList {
			if s.Uri == "https://example.com/sbom-valid-xml" {
				id = s.Id
				break
			}
		}

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}

		rec := httptest.NewRecorder()
		if err := res.VisitDownloadSbomResponse(rec); err != nil {
			t.Fatalf("VisitDownloadSbomResponse returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status code = %v, want %v", rec.Code, http.StatusOK)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/xml" {
			t.Errorf("Content-Type = %v, want application/xml", ct)
		}
		expectedCD := `attachment; filename="` + docRef + `.xml"`
		if cd := rec.Header().Get("Content-Disposition"); cd != expectedCD {
			t.Errorf("Content-Disposition = %v, want %v", cd, expectedCD)
		}
		if !bytes.Equal(rec.Body.Bytes(), rawSbom) {
			t.Errorf("body = %s, want %s", rec.Body.String(), string(rawSbom))
		}
	})

	t.Run("Successful download of Unknown / binary format returns 200 with application/octet-stream", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}

		docRef := "sha256_binary_sbom"
		rawSbom := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}
		doc := processor.Document{
			Blob:   rawSbom,
			Format: processor.FormatUnknown,
		}
		docBytes, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("failed to marshal doc: %v", err)
		}
		if err := blobStore.Write(ctx, docRef, docBytes); err != nil {
			t.Fatalf("failed to write doc to blob store: %v", err)
		}

		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/pkg-binary@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/pkg-binary@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:         "https://example.com/sbom-binary",
						Algorithm:   "sha256",
						Digest:      "digest-binary",
						DocumentRef: docRef,
						KnownSince:  now,
					},
				},
			},
		})

		restApi := server.NewDefaultServer(gqlClient, blobStore)
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms failed: %v", err)
		}
		list := listRes.(gen.ListSboms200JSONResponse)
		var id string
		for _, s := range list.SbomList {
			if s.Uri == "https://example.com/sbom-binary" {
				id = s.Id
				break
			}
		}

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}

		rec := httptest.NewRecorder()
		if err := res.VisitDownloadSbomResponse(rec); err != nil {
			t.Fatalf("VisitDownloadSbomResponse returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status code = %v, want %v", rec.Code, http.StatusOK)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
			t.Errorf("Content-Type = %v, want application/octet-stream", ct)
		}
		expectedCD := `attachment; filename="` + docRef + `.bin"`
		if cd := rec.Header().Get("Content-Disposition"); cd != expectedCD {
			t.Errorf("Content-Disposition = %v, want %v", cd, expectedCD)
		}
		if !bytes.Equal(rec.Body.Bytes(), rawSbom) {
			t.Errorf("body = %v, want %v", rec.Body.Bytes(), rawSbom)
		}
	})

	t.Run("Format is guessed as JSON when document format is UNKNOWN", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}

		docRef := "sha256_guessed_json"
		rawSbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`)
		doc := processor.Document{
			Blob:   rawSbom,
			Format: processor.FormatUnknown, // left as UNKNOWN by collector
		}
		docBytes, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("failed to marshal doc: %v", err)
		}
		if err := blobStore.Write(ctx, docRef, docBytes); err != nil {
			t.Fatalf("failed to write doc to blob store: %v", err)
		}

		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/pkg-guessed-json@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/pkg-guessed-json@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:         "https://example.com/sbom-guessed-json",
						Algorithm:   "sha256",
						Digest:      "digest-guessed",
						DocumentRef: docRef,
						KnownSince:  now,
					},
				},
			},
		})

		restApi := server.NewDefaultServer(gqlClient, blobStore)
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms failed: %v", err)
		}
		list := listRes.(gen.ListSboms200JSONResponse)
		var id string
		for _, s := range list.SbomList {
			if s.Uri == "https://example.com/sbom-guessed-json" {
				id = s.Id
				break
			}
		}

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}

		rec := httptest.NewRecorder()
		if err := res.VisitDownloadSbomResponse(rec); err != nil {
			t.Fatalf("VisitDownloadSbomResponse returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status code = %v, want %v", rec.Code, http.StatusOK)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %v, want application/json", ct)
		}
		expectedCD := `attachment; filename="` + docRef + `.json"`
		if cd := rec.Header().Get("Content-Disposition"); cd != expectedCD {
			t.Errorf("Content-Disposition = %v, want %v", cd, expectedCD)
		}
		if !bytes.Equal(rec.Body.Bytes(), rawSbom) {
			t.Errorf("body = %s, want %s", rec.Body.String(), string(rawSbom))
		}
	})

	t.Run("Compressed document with ZSTD encoding is decompressed and returned", func(t *testing.T) {
		gqlClient := SetupTest(t)
		blobStore, err := blob.NewBlobStore(ctx, "mem://")
		if err != nil {
			t.Fatalf("failed to initialize in-memory blob store: %v", err)
		}

		rawSbom := []byte(`{"spdxVersion":"SPDX-2.3","name":"compressed-app"}`)
		var compressed bytes.Buffer
		encoder, err := zstd.NewWriter(&compressed)
		if err != nil {
			t.Fatalf("failed to create zstd encoder: %v", err)
		}
		if _, err := encoder.Write(rawSbom); err != nil {
			t.Fatalf("failed to compress with zstd: %v", err)
		}
		if err := encoder.Close(); err != nil {
			t.Fatalf("failed to close zstd encoder: %v", err)
		}

		docRef := "sha256_compressed_zstd_sbom"
		doc := processor.Document{
			Blob:     compressed.Bytes(),
			Encoding: processor.EncodingZstd,
			Format:   processor.FormatJSON,
		}
		docBytes, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("failed to marshal doc: %v", err)
		}
		if err := blobStore.Write(ctx, docRef, docBytes); err != nil {
			t.Fatalf("failed to write doc to blob store: %v", err)
		}

		now := time.Now().UTC().Truncate(time.Second)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/pkg-compressed-zstd@v1"},
			HasSboms: []HasSbom{
				{
					Subject: "pkg:guac/pkg-compressed-zstd@v1",
					Spec: &gql.HasSBOMInputSpec{
						Uri:         "https://example.com/sbom-compressed-zstd",
						Algorithm:   "sha256",
						Digest:      "digest-zstd",
						DocumentRef: docRef,
						KnownSince:  now,
					},
				},
			},
		})

		restApi := server.NewDefaultServer(gqlClient, blobStore)
		listRes, err := restApi.ListSboms(ctx, gen.ListSbomsRequestObject{})
		if err != nil {
			t.Fatalf("ListSboms failed: %v", err)
		}
		list := listRes.(gen.ListSboms200JSONResponse)
		var id string
		for _, s := range list.SbomList {
			if s.Uri == "https://example.com/sbom-compressed-zstd" {
				id = s.Id
				break
			}
		}

		res, err := restApi.DownloadSbom(ctx, gen.DownloadSbomRequestObject{Id: id})
		if err != nil {
			t.Fatalf("DownloadSbom returned unexpected error: %v", err)
		}

		rec := httptest.NewRecorder()
		if err := res.VisitDownloadSbomResponse(rec); err != nil {
			t.Fatalf("VisitDownloadSbomResponse returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status code = %v, want %v", rec.Code, http.StatusOK)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %v, want application/json", ct)
		}
		expectedCD := `attachment; filename="` + docRef + `.json"`
		if cd := rec.Header().Get("Content-Disposition"); cd != expectedCD {
			t.Errorf("Content-Disposition = %v, want %v", cd, expectedCD)
		}
		if !bytes.Equal(rec.Body.Bytes(), rawSbom) {
			t.Errorf("body = %s, want %s", rec.Body.String(), string(rawSbom))
		}
	})
}
