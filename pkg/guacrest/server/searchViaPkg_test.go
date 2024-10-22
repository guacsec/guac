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

//go:build integration

package server

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	clients "github.com/guacsec/guac/internal/testing/graphqlClients"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/logging"
)

func TestSearchVulnerabilitiesViaPkg(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name                string
		data                clients.GuacData
		purl                string
		includeDependencies bool
		startSBOM           model.AllHasSBOMTree
		expected            []gen.Vulnerability
	}{
		{
			name: "Basic vulnerability retrieval",
			data: clients.GuacData{
				Packages: []string{
					"pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
				},
				Vulnerabilities: []string{
					"osv/osv-2022-0001",
				},
				CertifyVulns: []clients.CertifyVuln{
					{
						Package:       "pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
						Vulnerability: "osv/osv-2022-0001",
						Metadata: &model.ScanMetadataInput{
							TimeScanned:    time.Now(),
							DbUri:          "https://vuln-db.example.com",
							DbVersion:      "1.0.0",
							ScannerUri:     "test-scanner",
							ScannerVersion: "1.0.0",
							Origin:         "test-origin",
							Collector:      "test-collector",
						},
					},
				},
			},
			purl:                "pkg%3Agolang%2Fgithub.com%2Fhashicorp%2Fconsul%2Fsdk%40v1.0.0", // url encoded purl
			includeDependencies: false,
			startSBOM:           model.AllHasSBOMTree{},
			expected: []gen.Vulnerability{
				{
					Metadata: gen.ScanMetadata{
						TimeScanned:    ptrfrom.Time(time.Now()),
						DbUri:          ptrfrom.String("https://vuln-db.example.com"),
						DbVersion:      ptrfrom.String("1.0.0"),
						ScannerUri:     ptrfrom.String("test-scanner"),
						ScannerVersion: ptrfrom.String("1.0.0"),
						Origin:         ptrfrom.String("test-origin"),
						Collector:      ptrfrom.String("test-collector"),
					},
					Vulnerability: gen.VulnerabilityDetails{
						Type:             ptrfrom.String("osv"),
						VulnerabilityIDs: []string{"osv-2022-0001"},
					},
					Package: "pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := clients.SetupTest(t)
			clients.Ingest(ctx, t, gqlClient, tt.data)

			vulnerabilities, err := searchVulnerabilitiesViaPkg(ctx, gqlClient, tt.purl, &tt.includeDependencies)
			if err != nil {
				t.Fatalf("searchVulnerabilitiesViaPkg returned unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.expected, vulnerabilities, cmpopts.EquateApproxTime(time.Second)); diff != "" {
				t.Errorf("searchVulnerabilitiesViaPkg mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
