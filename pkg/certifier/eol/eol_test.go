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

package eol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEOLStringOrBool_Bool(t *testing.T) {
	now := time.Now()
	pastDate := now.Add(-24 * time.Hour)
	futureDate := now.Add(24 * time.Hour)

	tests := []struct {
		name  string
		value EOLStringOrBool
		want  bool
	}{
		{
			name:  "direct boolean true",
			value: NewBoolValue(true),
			want:  true,
		},
		{
			name:  "direct boolean false",
			value: NewBoolValue(false),
			want:  false,
		},
		{
			name:  "past date string (should be true)",
			value: NewStringValue(pastDate.Format("2006-01-02")),
			want:  true,
		},
		{
			name:  "future date string (should be false)",
			value: NewStringValue(futureDate.Format("2006-01-02")),
			want:  false,
		},
		{
			name:  "string 'true'",
			value: NewStringValue("true"),
			want:  true,
		},
		{
			name:  "string 'false'",
			value: NewStringValue("false"),
			want:  false,
		},
		{
			name:  "empty string",
			value: NewStringValue(""),
			want:  false,
		},
		{
			name:  "invalid date string",
			value: NewStringValue("not-a-date"),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.value.Bool(); got != tt.want {
				t.Errorf("EOLStringOrBool.Bool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewEOLCertifier(t *testing.T) {
	certifier := NewEOLCertifier()
	assert.NotNil(t, certifier, "NewEOLCertifier should return a non-nil certifier")
	_, ok := certifier.(*eolCertifier)
	assert.True(t, ok, "NewEOLCertifier should return an instance of eolCertifier")
}

func TestCertifyComponent(t *testing.T) {
	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		switch r.URL.Path {
		case "/api/all.json":
			// For raw JSON bytes, write directly to the response
			_, err = w.Write(testdata.EOLAll)
		case "/api/sapmachine.json":
			// For raw JSON bytes, write directly to the response
			_, err = w.Write(testdata.EOLSapMachine)
		default:
			http.NotFound(w, r)
		}
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()
	eolAPIBase = server.URL + "/api"

	// Helper function to verify the generated document
	verifyDoc := func(doc *processor.Document) {
		var statement attestation.EOLStatement
		err := json.Unmarshal(doc.Blob, &statement)
		require.NoError(t, err)

		// For debugging
		t.Logf("Statement EOLDate: %s", statement.Predicate.EOLDate)
		t.Logf("Statement LTS: %v", statement.Predicate.LTS)

		// Check all fields
		assert.Equal(t, "21", statement.Predicate.Cycle)
		assert.Equal(t, "21.0.5", statement.Predicate.Latest)
		assert.Equal(t, "2028-09-01", statement.Predicate.EOLDate)
		assert.True(t, statement.Predicate.LTS)
		assert.False(t, statement.Predicate.IsEOL) // Future date should not be EOL

		assert.Equal(t, processor.DocumentITE6EOL, doc.Type)
		assert.Equal(t, processor.FormatJSON, doc.Format)
		assert.Equal(t, EOLCollector, doc.SourceInformation.Collector)

		sha256sum := sha256.Sum256(doc.Blob)
		expectDocumentRef := fmt.Sprintf("sha256_%s", hex.EncodeToString(sha256sum[:]))
		assert.Contains(t, doc.SourceInformation.DocumentRef, expectDocumentRef)
	}

	certifier := &eolCertifier{
		client: server.Client(),
	}

	rootComponent := []*root_package.PackageNode{
		{Purl: "pkg:maven/com.sap.sapmachine/sapmachine@21.0.5"},
		{Purl: "pkg:npm/unknown@2.0.0"},
	}

	docChan := make(chan *processor.Document, 10)

	err := certifier.CertifyComponent(context.Background(), rootComponent, docChan)
	require.NoError(t, err)

	close(docChan)
	docs := make([]*processor.Document, 0)
	for doc := range docChan {
		docs = append(docs, doc)
	}

	require.Len(t, docs, 1, "Expected exactly one document")
	verifyDoc(docs[0])
}

func TestFetchAllProducts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode([]string{"sapmachine", "nodejs"})
		require.NoError(t, err)
	}))
	defer server.Close()
	eolAPIBase = server.URL + "/api"

	certifier := &eolCertifier{
		client: server.Client(),
	}

	products, err := fetchAllProducts(context.Background(), certifier.client)
	require.NoError(t, err)
	assert.Equal(t, []string{"sapmachine", "nodejs"}, products)
}

func TestFetchProductEOL(t *testing.T) {
	tests := []struct {
		name         string
		responseCode int
		responseBody string
		wantErr      bool
		validateData func(*testing.T, EOLData)
	}{
		{
			name:         "successful response with mixed types",
			responseCode: http.StatusOK,
			responseBody: `[
				{
					"cycle": "21",
					"releaseDate": "2023-09-18",
					"eol": "2028-09-01",
					"latest": "21.0.5",
					"latestReleaseDate": "2024-10-15",
					"lts": true,
					"support": "2024-12-31",
					"discontinued": false
				},
				{
					"cycle": "20",
					"releaseDate": "2023-03-17",
					"eol": true,
					"latest": "20.0.2",
					"latestReleaseDate": "2023-07-18",
					"lts": "2023-09-01",
					"support": false
				}
			]`,
			wantErr: false,
			validateData: func(t *testing.T, data EOLData) {
				require.Len(t, data, 2)

				// Check first entry
				assert.Equal(t, "21", data[0].Cycle)
				assert.Equal(t, "2028-09-01", data[0].EOL.String())
				assert.True(t, data[0].LTS.Bool())

				// Check second entry
				assert.Equal(t, "20", data[1].Cycle)
				assert.True(t, data[1].EOL.Bool())
				assert.True(t, data[1].LTS.Bool()) // Non-empty date string should be true
			},
		},
		{
			name:         "non-200 response",
			responseCode: http.StatusNotFound,
			responseBody: `{"error": "Product not found"}`,
			wantErr:      true,
		},
		{
			name:         "invalid JSON response",
			responseCode: http.StatusOK,
			responseBody: `{invalid json}`,
			wantErr:      true,
		},
		{
			name:         "empty response",
			responseCode: http.StatusOK,
			responseBody: `[]`,
			wantErr:      false,
			validateData: func(t *testing.T, data EOLData) {
				assert.Len(t, data, 0)
			},
		},
		{
			name:         "malformed field types",
			responseCode: http.StatusOK,
			responseBody: `[{"cycle": true, "eol": {}}]`,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				_, err := w.Write([]byte(tt.responseBody))
				require.NoError(t, err)
			}))
			defer server.Close()

			eolAPIBase = server.URL + "/api"
			client := &http.Client{}

			data, err := fetchProductEOL(context.Background(), client, "test-product")
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.validateData != nil {
				tt.validateData(t, data)
			}
		})
	}
}

// Test mixed types for EOL and LTS values
func TestEOLDataMixedTypes(t *testing.T) {
	data := []struct {
		name      string
		eolValue  EOLStringOrBool
		ltsValue  EOLStringOrBool
		wantIsEOL bool
		wantIsLTS bool
	}{
		{
			name:      "string date EOL and boolean LTS",
			eolValue:  NewStringValue("2023-01-01"),
			ltsValue:  NewBoolValue(true),
			wantIsEOL: true, // Past date
			wantIsLTS: true,
		},
		{
			name:      "boolean EOL and string date LTS",
			eolValue:  NewBoolValue(true),
			ltsValue:  NewStringValue("2023-01-01"),
			wantIsEOL: true,
			wantIsLTS: true, // Non-empty string
		},
		{
			name:      "future date EOL",
			eolValue:  NewStringValue("2030-01-01"),
			ltsValue:  NewBoolValue(false),
			wantIsEOL: false, // Future date
			wantIsLTS: false,
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			cycleData := CycleData{
				Cycle:       "test",
				EOL:         tt.eolValue,
				LTS:         tt.ltsValue,
				ReleaseDate: "2022-01-01",
				Latest:      "1.0.0",
			}

			assert.Equal(t, tt.wantIsEOL, cycleData.EOL.Bool(), "EOL bool value mismatch")
			assert.Equal(t, tt.wantIsLTS, cycleData.LTS.Bool(), "LTS bool value mismatch")
		})
	}
}
