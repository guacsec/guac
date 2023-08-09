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

package inmem_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
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

func TestIngestCertifyVulnerability(t *testing.T) {
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
			Name:   "Query No Vuln",
			InVuln: []*model.VulnerabilityInputSpec{g1},
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
						Type:             "noVuln",
						VulnerabilityIDs: []*model.VulnerabilityID{noVulnOut},
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
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			// b, err := inmem.GetBackend(nil)
			b, err := inmem.GetBackend(nil)
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

			ids := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				record, err := b.IngestCertifyVuln(ctx, *o.Pkg, *o.Vuln, *o.CertifyVuln)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				ids[i] = record.ID
			}
			if test.Query != nil {
				if test.Query.ID != nil {
					idIndex, err := strconv.Atoi(*test.Query.ID)
					if err == nil && idIndex > -1 && idIndex < len(ids) {
						test.Query.ID = ptrfrom.String(ids[idIndex])
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

func TestCertifyVulnNeighbors(t *testing.T) {
	type call struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		ExpNeighbors map[string][]string
	}{
		{
			Name:   "HappyPath",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				call{
					Pkg:  p1,
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
			ExpNeighbors: map[string][]string{
				"4": []string{"1", "7"}, // pkg version -> pkg name, vex
				"6": []string{"5", "7"}, // Vuln -> vex
				"7": []string{"1", "5"}, // Vex -> pkg version, vuln
			},
		},
		{
			Name:   "Two vex on same package",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1, o2},
			Calls: []call{
				call{
					Pkg:  p1,
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
				call{
					Pkg:  p1,
					Vuln: o2,
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
			ExpNeighbors: map[string][]string{
				"4": []string{"1", "7", "8"}, // pkg version -> pkg name, vex1, vex2
				"5": []string{"7"},           // Vuln1 -> vex1
				"6": []string{"8"},           // Vuln2 -> vex2
				"7": []string{"1", "5"},      // Vex1 -> pkg version, vuln1
				"8": []string{"1", "6"},      // Vex2 -> pkg version, vuln2
			},
		},
	}
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, o := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, *o); err != nil {
					t.Fatalf("Could not ingest osv: %v", err)
				}
			}
			for _, o := range test.Calls {
				if _, err := b.IngestCertifyVuln(ctx, *o.Pkg, *o.Vuln, *o.CertifyVuln); err != nil {
					t.Fatalf("Could not ingest certifyVuln")
				}
			}
			for q, r := range test.ExpNeighbors {
				got, err := b.Neighbors(ctx, q, nil)
				if err != nil {
					t.Fatalf("Could not query neighbors: %s", err)
				}
				gotIDs := convNodes(got)
				slices.Sort(r)
				slices.Sort(gotIDs)
				if diff := cmp.Diff(r, gotIDs); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}
