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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"
)

// Tests the purl-matching logic of GetPackagePurls.
func Test_FindMatchingPurls(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name     string
		data     GuacData
		purl     string
		expected []string
	}{
		{
			name: "Partial purl without version returns all versions of that name",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/foo@v1", "pkg:guac/foo@v2"},
			},
			purl:     "pkg:guac/foo",
			expected: []string{"pkg:guac/foo", "pkg:guac/foo@v1", "pkg:guac/foo@v2"},
		},
		{
			name: "Partial purl without version returns qualified packages too",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/foo?a=b", "pkg:guac/foo?a=b&c=d"},
			},
			purl:     "pkg:guac/foo",
			expected: []string{"pkg:guac/foo", "pkg:guac/foo?a=b", "pkg:guac/foo?a=b&c=d"},
		},
		{
			name: "Exact version selects only that version",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/foo@v1", "pkg:guac/foo@v2"},
			},
			purl:     "pkg:guac/foo@v1",
			expected: []string{"pkg:guac/foo@v1"},
		},
		{
			name: "Qualifier input is matched as a subset",
			data: GuacData{
				Packages: []string{
					"pkg:guac/foo",
					"pkg:guac/foo?a=b",
					"pkg:guac/foo?a=b&c=d",
					"pkg:guac/foo?a=x",
				},
			},
			purl:     "pkg:guac/foo?a=b",
			expected: []string{"pkg:guac/foo?a=b", "pkg:guac/foo?a=b&c=d"},
		},
		{
			name: "Input qualifier value must match exactly",
			data: GuacData{
				Packages: []string{"pkg:guac/foo?a=b", "pkg:guac/foo?a=x"},
			},
			purl:     "pkg:guac/foo?a=b",
			expected: []string{"pkg:guac/foo?a=b"},
		},
		{
			name: "Different name is not matched",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:guac/bar"},
			},
			purl:     "pkg:guac/foo",
			expected: []string{"pkg:guac/foo"},
		},
		{
			name: "Different type is not matched",
			data: GuacData{
				Packages: []string{"pkg:guac/foo", "pkg:generic/foo"},
			},
			purl:     "pkg:guac/foo",
			expected: []string{"pkg:guac/foo"},
		},
		{
			name: "Namespace is respected when input omits it",
			data: GuacData{
				Packages: []string{"pkg:golang/foo", "pkg:golang/ns/foo"},
			},
			purl:     "pkg:golang/foo",
			expected: []string{"pkg:golang/foo"},
		},
		{
			name: "Namespace is respected when input specifies it",
			data: GuacData{
				Packages: []string{"pkg:golang/foo", "pkg:golang/ns/foo"},
			},
			purl:     "pkg:golang/ns/foo",
			expected: []string{"pkg:golang/ns/foo"},
		},
		{
			name: "No matching packages returns empty list",
			data: GuacData{
				Packages: []string{"pkg:guac/bar"},
			},
			purl:     "pkg:guac/foo",
			expected: []string{},
		},
		{
			name:     "No packages ingested returns empty list",
			purl:     "pkg:guac/foo",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)

			got, err := server.FindMatchingPurls(ctx, gqlClient, tt.purl)
			if err != nil {
				t.Fatalf("FindMatchingPurls returned unexpected error: %v", err)
			}
			if !cmp.Equal(got, tt.expected, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
				t.Errorf("FindMatchingPurls returned %v, but wanted %v", got, tt.expected)
			}
		})
	}
}

// Tests the HTTP-level behavior of GetPackagePurls.
func Test_GetPackagePurls(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	t.Run("Returns 200 with PurlList and TotalCount", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages: []string{"pkg:guac/foo", "pkg:guac/foo@v1"},
		})
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.GetPackagePurls(ctx, gen.GetPackagePurlsRequestObject{Purl: "pkg:guac/foo"})
		if err != nil {
			t.Fatalf("GetPackagePurls returned unexpected error: %v", err)
		}
		success, ok := res.(gen.GetPackagePurls200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res, res)
		}

		expected := []string{"pkg:guac/foo", "pkg:guac/foo@v1"}
		if !cmp.Equal(success.PurlList, expected, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
			t.Errorf("PurlList = %v, want %v", success.PurlList, expected)
		}
		if success.PaginationInfo.TotalCount == nil || *success.PaginationInfo.TotalCount != len(expected) {
			t.Errorf("TotalCount = %v, want %d", success.PaginationInfo.TotalCount, len(expected))
		}
	})

	t.Run("Returns 200 with empty list when nothing matches", func(t *testing.T) {
		gqlClient := SetupTest(t)
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.GetPackagePurls(ctx, gen.GetPackagePurlsRequestObject{Purl: "pkg:guac/foo"})
		if err != nil {
			t.Fatalf("GetPackagePurls returned unexpected error: %v", err)
		}
		success, ok := res.(gen.GetPackagePurls200JSONResponse)
		if !ok {
			t.Fatalf("Expected 200 response, got %T: %v", res, res)
		}
		if len(success.PurlList) != 0 {
			t.Errorf("Expected empty PurlList, got %v", success.PurlList)
		}
		if success.PaginationInfo.TotalCount == nil || *success.PaginationInfo.TotalCount != 0 {
			t.Errorf("TotalCount = %v, want 0", success.PaginationInfo.TotalCount)
		}
	})

	t.Run("Returns 400 for unparseable purl", func(t *testing.T) {
		gqlClient := SetupTest(t)
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.GetPackagePurls(ctx, gen.GetPackagePurlsRequestObject{Purl: "not-a-purl"})
		if err != nil {
			t.Fatalf("GetPackagePurls returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.GetPackagePurls400JSONResponse); !ok {
			t.Fatalf("Expected 400 response, got %T: %v", res, res)
		}
	})
}
