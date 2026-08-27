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
			digest:   "sha256:sha-xyz",
			expected: []string{"cve-2024-0001"},
		},
		{
			name: "Artifact with no IsOccurrence returns empty",
			data: GuacData{
				Artifacts: []string{"sha-xyz"},
			},
			digest:   "sha256:sha-xyz",
			expected: []string{},
		},
		{
			name: "Artifact with package that has no vuln returns empty",
			data: GuacData{
				Packages:      []string{"pkg:guac/foo"},
				Artifacts:     []string{"sha-xyz"},
				IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
			},
			digest:   "sha256:sha-xyz",
			expected: []string{},
		},
		{
			// Regression test for #3174: the SBOM edge was not traversed.
			name: "Artifact -> HasSBOM -> package with vuln",
			data: GuacData{
				Packages:        []string{"pkg:guac/foo"},
				Artifacts:       []string{"sha-xyz"},
				Vulnerabilities: []string{"osv/CVE-2024-0002"},
				HasSboms:        []HasSbom{{Subject: "sha-xyz", IncludedSoftware: []string{"pkg:guac/foo"}}},
				CertifyVulns:    []CertifyVuln{{Package: "pkg:guac/foo", Vulnerability: "osv/CVE-2024-0002", Metadata: vulnScanMeta()}},
			},
			digest:   "sha256:sha-xyz",
			expected: []string{"cve-2024-0002"},
		},
		{
			// A novuln CertifyVuln means "scanned, nothing found", so it must
			// not be reported for the clean package alongside the real CVE.
			name: "Artifact -> HasSBOM -> packages, novuln is not reported",
			data: GuacData{
				Packages:        []string{"pkg:guac/vulny", "pkg:guac/clean"},
				Artifacts:       []string{"sha-mixed"},
				Vulnerabilities: []string{"osv/CVE-2024-0009", "novuln/"},
				HasSboms: []HasSbom{
					{Subject: "sha-mixed", IncludedSoftware: []string{"pkg:guac/vulny", "pkg:guac/clean"}},
				},
				CertifyVulns: []CertifyVuln{
					{Package: "pkg:guac/vulny", Vulnerability: "osv/CVE-2024-0009", Metadata: vulnScanMeta()},
					{Package: "pkg:guac/clean", Vulnerability: "novuln/", Metadata: vulnScanMeta()},
				},
			},
			digest:   "sha256:sha-mixed",
			expected: []string{"cve-2024-0009"},
		},
		{
			name: "Artifact -> HasSBOM -> artifact -> HasSBOM -> package with vuln",
			data: GuacData{
				Packages:        []string{"pkg:guac/bar"},
				Artifacts:       []string{"sha-parent", "sha-child"},
				Vulnerabilities: []string{"osv/CVE-2024-0003"},
				HasSboms: []HasSbom{
					{Subject: "sha-parent", IncludedSoftware: []string{"sha-child"}},
					{Subject: "sha-child", IncludedSoftware: []string{"pkg:guac/bar"}},
				},
				CertifyVulns: []CertifyVuln{{Package: "pkg:guac/bar", Vulnerability: "osv/CVE-2024-0003", Metadata: vulnScanMeta()}},
			},
			digest:   "sha256:sha-parent",
			expected: []string{"cve-2024-0003"},
		},
		{
			// GetDepsForArtifact drops packages equivalent to the artifact;
			// their vulns still belong to it.
			name: "Artifact -> HashEqual -> artifact -> IsOccurrence -> package with vuln",
			data: GuacData{
				Packages:        []string{"pkg:guac/foo"},
				Artifacts:       []string{"sha-xyz", "sha-abc"},
				Vulnerabilities: []string{"osv/CVE-2024-0004"},
				HashEquals:      []HashEqual{{ArtifactA: "sha-xyz", ArtifactB: "sha-abc"}},
				IsOccurrences:   []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-abc"}},
				CertifyVulns:    []CertifyVuln{{Package: "pkg:guac/foo", Vulnerability: "osv/CVE-2024-0004", Metadata: vulnScanMeta()}},
			},
			digest:   "sha256:sha-xyz",
			expected: []string{"cve-2024-0004"},
		},
		{
			// A SLSA attestation the artifact is the subject of describes how
			// it was built, so its materials count.
			name: "Artifact -> HasSLSA -> material artifact -> IsOccurrence -> package with vuln",
			data: GuacData{
				Packages:        []string{"pkg:guac/base"},
				Artifacts:       []string{"sha-built", "sha-base"},
				Builders:        []string{"guac:builder"},
				Vulnerabilities: []string{"osv/CVE-2024-0005"},
				HasSlsas:        []HasSlsa{{Subject: "sha-built", BuiltFrom: []string{"sha-base"}, BuiltBy: "guac:builder"}},
				IsOccurrences:   []IsOccurrence{{Subject: "pkg:guac/base", Artifact: "sha-base"}},
				CertifyVulns:    []CertifyVuln{{Package: "pkg:guac/base", Vulnerability: "osv/CVE-2024-0005", Metadata: vulnScanMeta()}},
			},
			digest:   "sha256:sha-built",
			expected: []string{"cve-2024-0005"},
		},
		{
			// sha-base is a build input of sha-app, not a consumer of
			// sha-sibling: an unfiltered HasSlsa walk would leak that sibling.
			name: "Artifact does not inherit vulns of a sibling SLSA material",
			data: GuacData{
				Packages:        []string{"pkg:guac/base", "pkg:guac/sibling"},
				Artifacts:       []string{"sha-app", "sha-base", "sha-sibling"},
				Builders:        []string{"guac:builder"},
				Vulnerabilities: []string{"osv/CVE-2024-0006", "osv/CVE-2024-0007"},
				HasSlsas:        []HasSlsa{{Subject: "sha-app", BuiltFrom: []string{"sha-base", "sha-sibling"}, BuiltBy: "guac:builder"}},
				IsOccurrences: []IsOccurrence{
					{Subject: "pkg:guac/base", Artifact: "sha-base"},
					{Subject: "pkg:guac/sibling", Artifact: "sha-sibling"},
				},
				CertifyVulns: []CertifyVuln{
					{Package: "pkg:guac/base", Vulnerability: "osv/CVE-2024-0006", Metadata: vulnScanMeta()},
					{Package: "pkg:guac/sibling", Vulnerability: "osv/CVE-2024-0007", Metadata: vulnScanMeta()},
				},
			},
			digest:   "sha256:sha-base",
			expected: []string{"cve-2024-0006"},
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
			name: "Package certified novuln returns empty",
			data: GuacData{
				Packages:        []string{"pkg:guac/foo"},
				Vulnerabilities: []string{"novuln/"},
				CertifyVulns: []CertifyVuln{
					{Package: "pkg:guac/foo", Vulnerability: "novuln/", Metadata: vulnScanMeta()},
				},
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

		res, err := restApi.GetArtifactVulns(ctx, gen.GetArtifactVulnsRequestObject{Digest: "sha256:sha-xyz"})
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

		res, err := restApi.GetArtifactVulns(ctx, gen.GetArtifactVulnsRequestObject{Digest: "sha256:sha-missing"})
		if err != nil {
			t.Fatalf("GetArtifactVulns returned unexpected error: %v", err)
		}
		if _, ok := res.(gen.GetArtifactVulns400JSONResponse); !ok {
			t.Fatalf("expected 400 response, got %T: %v", res, res)
		}
	})

	t.Run("Returns 400 for digest missing algorithm prefix", func(t *testing.T) {
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

// stubClient answers each GraphQL operation with canned JSON, so the traversal
// can be driven over responses the keyvalue backend will not produce.
type stubClient map[string]string

func (c stubClient) MakeRequest(ctx context.Context, req *graphql.Request, resp *graphql.Response) error {
	raw, ok := c[req.OpName]
	if !ok {
		return fmt.Errorf("stub client has no response for operation %q", req.OpName)
	}
	if raw == "" {
		return fmt.Errorf("graphql server is down")
	}
	return json.Unmarshal([]byte(raw), resp.Data)
}

func Test_GetArtifactVulns_BackendFailures(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	oneArtifact := `{"artifacts":[{"id":"art-1","algorithm":"sha256","digest":"abc"}]}`

	tests := []struct {
		name   string
		client stubClient
		want   any
	}{{
		// GetVulnsForArtifact wraps the error before handleErr sees it, so an
		// identity comparison would report a backend outage as 400 Bad Request.
		name:   "a failing Artifacts query is a 502, not a 400",
		client: stubClient{"Artifacts": ""},
		want:   gen.GetArtifactVulns502JSONResponse{},
	}, {
		name:   "an ambiguous digest is a 500, not a 400",
		client: stubClient{"Artifacts": `{"artifacts":[{"id":"art-1"},{"id":"art-2"}]}`},
		want:   gen.GetArtifactVulns500JSONResponse{},
	}, {
		name:   "a failing Neighbors query is a 502",
		client: stubClient{"Artifacts": oneArtifact, "Neighbors": ""},
		want:   gen.GetArtifactVulns502JSONResponse{},
	}, {
		// A package name node carries no versions, so it maps to a nil node.
		// Before those were dropped, the traversal dequeued one and panicked.
		name: "a package name neighbor is dropped instead of panicking",
		client: stubClient{"Artifacts": oneArtifact, "Neighbors": `{"neighbors":[` +
			`{"__typename":"Package","id":"pkg-name-1","type":"guac","namespaces":[` +
			`{"id":"ns-1","namespace":"","names":[{"id":"name-1","name":"foo","versions":[]}]}]}]}`},
		want: gen.GetArtifactVulns200JSONResponse{},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restApi := server.NewDefaultServer(tt.client)

			res, err := restApi.GetArtifactVulns(ctx, gen.GetArtifactVulnsRequestObject{Digest: "sha256:abc"})
			if err != nil {
				t.Fatalf("GetArtifactVulns returned unexpected error: %v", err)
			}
			if fmt.Sprintf("%T", res) != fmt.Sprintf("%T", tt.want) {
				t.Errorf("GetArtifactVulns returned %T, want %T", res, tt.want)
			}
		})
	}
}
