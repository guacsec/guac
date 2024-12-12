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

package datadog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	ingestor "github.com/guacsec/guac/pkg/assembler/clients/helpers"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/stretchr/testify/assert"
)

func TestDataDogCertifier_CertifyComponent(t *testing.T) {
	// set up test server that handles both npm and pypi manifests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response map[string][]string
		switch path.Base(r.URL.Path) {
		case "manifest.json":
			if strings.Contains(r.URL.Path, "npm") {
				response = map[string][]string{
					"@malicious/package": {"1.0.0", "1.0.1"},
					"evil-package":       {"2.0.0"},
				}
			} else if strings.Contains(r.URL.Path, "pypi") {
				response = map[string][]string{
					"malicious-pypi": {"0.1.0", "0.2.0"},
				}
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	// create a custom client that redirects all requests to our test server
	testClient := &http.Client{
		Transport: &mockTransport{
			server:          server,
			npmManifestURL:  NPM_MANIFEST_URL,
			pypiManifestURL: PYPI_MANIFEST_URL,
		},
	}

	ctx := logging.WithLogger(context.Background())

	tests := []struct {
		name           string
		rootComponent  interface{}
		expectedPreds  int
		wantPackages   []string
		wantErr        bool
		errMessage     error
		assemblerError error
	}{
		{
			name: "certify malicious npm and pypi packages",
			rootComponent: []*root_package.PackageNode{
				{Purl: "pkg:npm/%40malicious/package@1.0.0"},
				{Purl: "pkg:npm/evil-package@2.0.0"},
				{Purl: "pkg:pypi/malicious-pypi@0.1.0"},
				// should be ignored
				{Purl: "pkg:maven/safe/package@1.0.0"},
			},
			expectedPreds: 3,
			wantPackages: []string{
				"pkg:npm/%40malicious/package@1.0.0",
				"pkg:npm/evil-package@2.0.0",
				"pkg:pypi/malicious-pypi@0.1.0",
			},
			wantErr: false,
		},
		{
			name:          "bad component type",
			rootComponent: map[string]string{},
			expectedPreds: 0,
			wantErr:       true,
			errMessage:    ErrDataDogComponentTypeMismatch,
		},
		{
			name: "no malicious packages",
			rootComponent: []*root_package.PackageNode{
				{Purl: "pkg:npm/safe-package@1.0.0"},
				{Purl: "pkg:pypi/good-package@1.0.0"},
			},
			expectedPreds: 0,
			wantErr:       false,
		},
		{
			name: "assembler error",
			rootComponent: []*root_package.PackageNode{
				{Purl: "pkg:npm/%40malicious/package@1.0.0"},
			},
			expectedPreds:  1,
			wantPackages:   []string{"@malicious/package"},
			wantErr:        true,
			assemblerError: errors.New("assembler error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedPreds []assembler.IngestPredicates
			mockAssembler := func(preds []assembler.IngestPredicates) (*ingestor.AssemblerIngestedIDs, error) {
				capturedPreds = preds
				if tt.assemblerError != nil {
					return nil, tt.assemblerError
				}
				return &ingestor.AssemblerIngestedIDs{}, nil
			}

			certifier, err := NewDataDogCertifier(ctx, mockAssembler, WithHTTPClient(testClient))
			if err != nil {
				t.Fatalf("Failed to create certifier: %v", err)
			}

			err = certifier.CertifyComponent(ctx, tt.rootComponent, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("CertifyComponent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				if tt.errMessage != nil && !errors.Is(err, tt.errMessage) {
					t.Errorf("CertifyComponent() error = %v, want error = %v", err, tt.errMessage)
				}
				return
			}

			if tt.expectedPreds > 0 {
				assert.Len(t, capturedPreds, 1, "Should have one IngestPredicates")
				assert.Len(t, capturedPreds[0].CertifyBad, tt.expectedPreds, "Should have expected number of CertifyBad predicates")

				foundPackages := make(map[string]bool)
				for _, certifyBad := range capturedPreds[0].CertifyBad {
					// build package name for verification
					purl := helpers.PkgInputSpecToPurl(certifyBad.Pkg)
					foundPackages[purl] = true

					// verify predicate content
					assert.Equal(t, DataDogCollector, certifyBad.CertifyBad.Collector)
					assert.Equal(t, "DataDog Malicious Software Packages Dataset", certifyBad.CertifyBad.Origin)
					assert.Equal(t, generated.PkgMatchTypeSpecificVersion, certifyBad.PkgMatchFlag.Pkg)
					assert.NotEmpty(t, certifyBad.CertifyBad.Justification)
					assert.Contains(t, certifyBad.CertifyBad.Justification, "Malicious version:")
					assert.NotNil(t, certifyBad.CertifyBad.KnownSince)
				}

				// verify all expected packages were found
				for _, pkg := range tt.wantPackages {
					assert.True(t, foundPackages[pkg], fmt.Sprintf("Package %s was not found in certifications", pkg))
				}
			} else {
				assert.Len(t, capturedPreds, 0, "Should have no IngestPredicates")
			}
		})
	}
}

// mockTransport redirects requests to the test server while preserving paths
type mockTransport struct {
	server          *httptest.Server
	npmManifestURL  string
	pypiManifestURL string
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := t.server.URL
	switch req.URL.String() {
	case t.npmManifestURL:
		newURL += "/npm/manifest.json"
	case t.pypiManifestURL:
		newURL += "/pypi/manifest.json"
	default:
		return nil, fmt.Errorf("unexpected URL: %s", req.URL.String())
	}

	newReq := req.Clone(req.Context())
	var err error
	newReq.URL, err = req.URL.Parse(newURL)
	if err != nil {
		return nil, err
	}

	return t.server.Client().Do(newReq)
}
