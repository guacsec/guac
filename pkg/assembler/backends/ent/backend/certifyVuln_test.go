//
// Copyright 2023 The GUAC Authors.
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

package backend

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var t1, _ = time.Parse(time.RFC3339, "2023-01-01T00:00:00Z")

var vmd1 = &model.ScanMetadata{
	Collector:      "test collector",
	Origin:         "test origin",
	ScannerVersion: "v1.0.0",
	ScannerURI:     "test scanner uri",
	DbVersion:      "2023.01.01",
	DbURI:          "test db uri",
	TimeScanned:    t1,
}

func (s *Suite) TestIngestCertifyVulnerability() {
	type call struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}

	tests := []struct {
		InPkg        []*model.PkgInputSpec
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		ExpVuln      []*model.CertifyVuln
		Query        *model.CertifyVulnSpec
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{c1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: c1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					ID:      "1",
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify NoVuln",
			InVuln: []*model.VulnerabilityInputSpec{noVulnInput},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: noVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{noVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify OSV",
			InVuln: []*model.VulnerabilityInputSpec{o1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: o1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify GHSA",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: g1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: g1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &g1.VulnerabilityID,
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query ID",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: g1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				ID: ptrfrom.String("0"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query on Package",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: g1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Package: &model.PkgSpec{
					Name: ptrfrom.String(p2.Name),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: g1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: ptrfrom.String("asdf"),
				},
			},
			ExpVuln: nil,
		},
		{
			Name:   "Query No Vuln",
			InVuln: []*model.VulnerabilityInputSpec{noVulnInput},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: noVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("noVuln"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{noVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query No Vuln - with novuln boolean",
			InVuln: []*model.VulnerabilityInputSpec{noVulnInput, c1},
			InPkg:  []*model.PkgInputSpec{p2, p1},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: noVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
				{
					Pkg:  p1,
					Vuln: c1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					NoVuln: ptrfrom.Bool(true),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{noVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query only cve (exclude novuln) - with novuln boolean",
			InVuln: []*model.VulnerabilityInputSpec{noVulnInput, c1},
			InPkg:  []*model.PkgInputSpec{p2, p1},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: noVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
				{
					Pkg:  p1,
					Vuln: c1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					NoVuln: ptrfrom.Bool(false),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query all vulns - with novuln boolean omitted",
			InVuln: []*model.VulnerabilityInputSpec{noVulnInput, c1, g1},
			InPkg:  []*model.PkgInputSpec{p2, p1, p1},
			Calls: []call{
				{
					Pkg:  p2,
					Vuln: noVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
				{
					Pkg:  p1,
					Vuln: c1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
				{
					Pkg:  p1,
					Vuln: g1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    t1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{noVulnOut},
					},
					Metadata: vmd1,
				},
				{
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					Metadata: vmd1,
				},
				{
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:  "Ingest without vuln",
			InPkg: []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkg:         p2,
					Vuln:        &model.VulnerabilityInputSpec{},
					CertifyVuln: &model.ScanMetadataInput{},
				},
			},
			Query:        &model.CertifyVulnSpec{},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest missing pkg",
			InPkg: []*model.PkgInputSpec{},
			Calls: []call{
				{
					Pkg:         p2,
					Vuln:        &model.VulnerabilityInputSpec{},
					CertifyVuln: &model.ScanMetadataInput{},
				},
			},
			Query:        &model.CertifyVulnSpec{},
			ExpIngestErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		s.Run(test.Name, func() {
			ctx := s.Ctx
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}

			for _, g := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, *g); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			if _, err := b.IngestPackages(ctx, test.InPkg); err != nil {
				t.Fatalf("Could not ingest packages: %v", err)
			}

			recordIDs := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				record, err := b.IngestCertifyVuln(ctx, *o.Pkg, *o.Vuln, *o.CertifyVuln)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				recordIDs[i] = record.ID
			}

			if test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx < 0 || idIdx >= len(recordIDs) {
						s.T().Logf("ID index out of range, want: %d, got: %d. So ID %d will be directly used to query.", len(recordIDs), idIdx, idIdx)
					} else {
						realID := recordIDs[idIdx]
						test.Query.ID = &realID
					}
				}
			}

			got, err := b.CertifyVuln(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpVuln, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestIngestCertifyVulns() {
	type call struct {
		Pkgs         []*model.PkgInputSpec
		Vulns        []*model.VulnerabilityInputSpec
		CertifyVulns []*model.ScanMetadataInput
	}

	tests := []struct {
		InPkg        []*model.PkgInputSpec
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		ExpVuln      []*model.CertifyVuln
		Query        *model.CertifyVulnSpec
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{c1, c2},
			InPkg:  []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{p2, p1},
					Vulns: []*model.VulnerabilityInputSpec{c1, c2},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					ID:      "1",
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					Metadata: vmd1,
				},
				{
					ID:      "10",
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c2out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify NoVuln",
			InVuln: []*model.VulnerabilityInputSpec{noVulnInput, noVulnInput},
			InPkg:  []*model.PkgInputSpec{p2, p1},
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{p2, p1},
					Vulns: []*model.VulnerabilityInputSpec{noVulnInput, noVulnInput},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{noVulnOut},
					},
					Metadata: vmd1,
				},
				{
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{noVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify OSV",
			InVuln: []*model.VulnerabilityInputSpec{o1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{p2},
					Vulns: []*model.VulnerabilityInputSpec{o1},
					CertifyVulns: []*model.ScanMetadataInput{
						&model.ScanMetadataInput{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify GHSA",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{p2},
					Vulns: []*model.VulnerabilityInputSpec{g1},
					CertifyVulns: []*model.ScanMetadataInput{
						&model.ScanMetadataInput{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{g1, g2},
			InPkg:  []*model.PkgInputSpec{p2, p1},
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{p2, p1},
					Vulns: []*model.VulnerabilityInputSpec{g1, g2},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &g1.VulnerabilityID,
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query ID",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			InPkg:  []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{p2},
					Vulns: []*model.VulnerabilityInputSpec{g1},
					CertifyVulns: []*model.ScanMetadataInput{
						&model.ScanMetadataInput{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				ID: ptrfrom.String("0"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query on Package",
			InVuln: []*model.VulnerabilityInputSpec{g1, g2},
			InPkg:  []*model.PkgInputSpec{p2, p4},
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{p2, p4},
					Vulns: []*model.VulnerabilityInputSpec{g1, g2},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Package: &model.PkgSpec{
					Name: ptrfrom.String(p2.Name),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{g1, g2},
			InPkg:  []*model.PkgInputSpec{p2, p1},
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{p2, p1},
					Vulns: []*model.VulnerabilityInputSpec{g1, g2},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: ptrfrom.String("asdf"),
				},
			},
			ExpVuln: nil,
		},
		{
			Name:   "Query No Vuln",
			InVuln: []*model.VulnerabilityInputSpec{noVulnInput, noVulnInput},
			InPkg:  []*model.PkgInputSpec{p2, p1},
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{p2, p1},
					Vulns: []*model.VulnerabilityInputSpec{noVulnInput, noVulnInput},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("noVuln"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: p2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{noVulnOut},
					},
					Metadata: vmd1,
				},
				{
					Package: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{noVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
	}
	ctx := context.Background()
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("GetBackend() error = %v", err)
			}

			if _, err := b.IngestVulnerabilities(ctx, test.InVuln); err != nil {
				t.Fatalf("Could not ingest vulnerabilities: %a", err)
			}
			if _, err := b.IngestPackages(ctx, test.InPkg); err != nil {
				t.Fatalf("Could not ingest packages: %v", err)
			}

			recordIDs := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				cvs, err := b.IngestCertifyVulns(ctx, o.Pkgs, o.Vulns, o.CertifyVulns)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				recordIDs[i] = cvs[0].ID
			}

			if test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx < 0 || idIdx >= len(recordIDs) {
						s.T().Logf("ID index out of range, want: %d, got: %d. So ID %d will be directly used to query.", len(recordIDs), idIdx, idIdx)
					} else {
						test.Query.ID = &recordIDs[idIdx]
					}
				}
			}

			got, err := b.CertifyVuln(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpVuln, got, IngestPredicatesCmpOpts...); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
