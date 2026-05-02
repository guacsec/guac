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
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"
)

func vulnScanMeta() *gql.ScanMetadataInput {
	return &gql.ScanMetadataInput{TimeScanned: time.Now()}
}

func vulnIDsFromResult(vs []gen.Vulnerability) []string {
	out := []string{}
	for _, v := range vs {
		out = append(out, v.Vulnerability.VulnerabilityIDs...)
	}
	return out
}

func Test_GetVulnsForArtifact(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name     string
		data     GuacData
		digest   string
		expected []string
	}{
		{
			name: "Artifact -> IsOccurrence -> package with vuln",
			data: GuacData{
				Packages:        []string{"pkg:guac/foo"},
				Artifacts:       []string{"sha-xyz"},
				Vulnerabilities: []string{"osv/CVE-2024-0001"},
				IsOccurrences:   []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
				CertifyVulns:    []CertifyVuln{{Package: "pkg:guac/foo", Vulnerability: "osv/CVE-2024-0001", Metadata: vulnScanMeta()}},
			},
			digest:   "sha-xyz",
			expected: []string{"cve-2024-0001"},
		},
		{
			name: "Artifact with no IsOccurrence returns empty",
			data: GuacData{
				Artifacts: []string{"sha-xyz"},
			},
			digest:   "sha-xyz",
			expected: []string{},
		},
		{
			name: "Artifact with package that has no vuln returns empty",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo"},
				Artifacts:     []string{"sha-xyz"},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
			},
			digest:   "sha-xyz",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)

			got, err := server.GetVulnsForArtifact(ctx, gqlClient, tt.digest)
			if err != nil {
				t.Fatalf("GetVulnsForArtifact returned unexpected error: %v", err)
			}
			ids := vulnIDsFromResult(got)
			if !cmp.Equal(ids, tt.expected, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
				t.Errorf("vuln IDs = %v, want %v", ids, tt.expected)
			}
		})
	}
}

func Test_GetVulnsForPackage(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name                string
		data                GuacData
		purl                string
		includeDependencies bool
		expected            []string
	}{
		{
			name: "Package with one vuln",
			data: GuacData{
				Packages:        []string{"pkg:guac/foo"},
				Vulnerabilities: []string{"osv/CVE-2024-0001"},
				CertifyVulns: []CertifyVuln{
					{Package: "pkg:guac/foo", Vulnerability: "osv/CVE-2024-0001", Metadata: vulnScanMeta()},
				},
			},
			purl:     "pkg:guac/foo",
			expected: []string{"cve-2024-0001"},
		},
		{
			name: "Package with no vuln returns empty",
			data: GuacData{
				Packages: []string{"pkg:guac/foo"},
			},
			purl:     "pkg:guac/foo",
			expected: []string{},
		},
		{
			name: "includeDependencies=false does not walk deps",
			data: GuacData{
				Packages:        []string{"pkg:guac/foo", "pkg:guac/bar"},
				Vulnerabilities: []string{"osv/CVE-2024-0002"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
				CertifyVulns: []CertifyVuln{
					{Package: "pkg:guac/bar", Vulnerability: "osv/CVE-2024-0002", Metadata: vulnScanMeta()},
				},
			},
			purl:                "pkg:guac/foo",
			includeDependencies: false,
			expected:            []string{},
		},
		{
			name: "includeDependencies=true returns dep vuln",
			data: GuacData{
				Packages:        []string{"pkg:guac/foo", "pkg:guac/bar"},
				Vulnerabilities: []string{"osv/CVE-2024-0002"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
				CertifyVulns: []CertifyVuln{
					{Package: "pkg:guac/bar", Vulnerability: "osv/CVE-2024-0002", Metadata: vulnScanMeta()},
				},
			},
			purl:                "pkg:guac/foo",
			includeDependencies: true,
			expected:            []string{"cve-2024-0002"},
		},
		{
			name: "includeDependencies=true still returns own vuln",
			data: GuacData{
				Packages:        []string{"pkg:guac/foo", "pkg:guac/bar"},
				Vulnerabilities: []string{"osv/CVE-2024-0001", "osv/CVE-2024-0002"},
				HasSboms: []HasSbom{
					{Subject: "pkg:guac/foo", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
				CertifyVulns: []CertifyVuln{
					{Package: "pkg:guac/foo", Vulnerability: "osv/CVE-2024-0001", Metadata: vulnScanMeta()},
					{Package: "pkg:guac/bar", Vulnerability: "osv/CVE-2024-0002", Metadata: vulnScanMeta()},
				},
			},
			purl:                "pkg:guac/foo",
			includeDependencies: true,
			expected:            []string{"cve-2024-0001", "cve-2024-0002"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)

			got, err := server.GetVulnsForPackage(ctx, gqlClient, tt.purl, tt.includeDependencies)
			if err != nil {
				t.Fatalf("GetVulnsForPackage returned unexpected error: %v", err)
			}
			ids := vulnIDsFromResult(got)
			if !cmp.Equal(ids, tt.expected, cmpopts.EquateEmpty(), cmpopts.SortSlices(stdcmp.Less[string])) {
				t.Errorf("vuln IDs = %v, want %v", ids, tt.expected)
			}
		})
	}
}

func Test_GetArtifactVulns_HTTP(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	t.Run("Returns 200 with vuln list", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages:        []string{"pkg:guac/foo"},
			Artifacts:       []string{"sha-xyz"},
			Vulnerabilities: []string{"osv/CVE-2024-0001"},
			IsOccurrences:   []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
			CertifyVulns:    []CertifyVuln{{Package: "pkg:guac/foo", Vulnerability: "osv/CVE-2024-0001", Metadata: vulnScanMeta()}},
		})
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.GetArtifactVulns(ctx, gen.GetArtifactVulnsRequestObject{Digest: "sha-xyz"})
		if err != nil {
			t.Fatalf("GetArtifactVulns returned unexpected error: %v", err)
		}
		ok, success := res.(gen.GetArtifactVulns200JSONResponse)
		if !success {
			t.Fatalf("expected 200 response, got %T: %v", res, res)
		}
		if len(ok.VulnerabilityListJSONResponse) == 0 {
			t.Errorf("expected at least one vulnerability in response")
		}
	})

	t.Run("Returns 400 for unknown digest", func(t *testing.T) {
		gqlClient := SetupTest(t)
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.GetArtifactVulns(ctx, gen.GetArtifactVulnsRequestObject{Digest: "sha-missing"})
		if err != nil {
			t.Fatalf("GetArtifactVulns returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.GetArtifactVulns400JSONResponse); !ok {
			t.Fatalf("expected 400 response, got %T: %v", res, res)
		}
	})
}

func Test_GetPackageVulns_HTTP(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	t.Run("Returns 200 with vuln list", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages:        []string{"pkg:guac/foo"},
			Vulnerabilities: []string{"osv/CVE-2024-0001"},
			CertifyVulns: []CertifyVuln{
				{Package: "pkg:guac/foo", Vulnerability: "osv/CVE-2024-0001", Metadata: vulnScanMeta()},
			},
		})
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.GetPackageVulns(ctx, gen.GetPackageVulnsRequestObject{Purl: "pkg:guac/foo"})
		if err != nil {
			t.Fatalf("GetPackageVulns returned unexpected error: %v", err)
		}
		ok, success := res.(gen.GetPackageVulns200JSONResponse)
		if !success {
			t.Fatalf("expected 200 response, got %T: %v", res, res)
		}
		if len(ok.VulnerabilityListJSONResponse) == 0 {
			t.Errorf("expected at least one vulnerability in response")
		}
	})

	t.Run("Returns 400 for unknown purl", func(t *testing.T) {
		gqlClient := SetupTest(t)
		restApi := server.NewDefaultServer(gqlClient)

		res, err := restApi.GetPackageVulns(ctx, gen.GetPackageVulnsRequestObject{Purl: "pkg:guac/missing"})
		if err != nil {
			t.Fatalf("GetPackageVulns returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.GetPackageVulns400JSONResponse); !ok {
			t.Fatalf("expected 400 response, got %T: %v", res, res)
		}
	})
}
