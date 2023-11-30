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

package arangodb

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestVulnEqual(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := deleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Vuln      *model.VulnerabilityInputSpec
		OtherVuln *model.VulnerabilityInputSpec
		In        *model.VulnEqualInputSpec
	}
	tests := []struct {
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		Query        *model.VulnEqualSpec
		QueryID      bool
		QueryVulnID  bool
		ExpVulnEqual []*model.VulnEqual
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Ingest same twice",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query on Justification",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query on OSV",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O2,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						VulnerabilityID: ptrfrom.String("CVE-2022-26499"),
					},
				},
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
						},
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query on vulnerability IDs",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O2,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryVulnID: true,
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
						},
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query on OSV and other vulnerability ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O2,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						VulnerabilityID: ptrfrom.String("CVE-2022-26499"),
					},
					{
						VulnerabilityID: ptrfrom.String("CVE-2019-13110"),
					},
				},
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
						},
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query on OSV and other vulnerability ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O2,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						VulnerabilityID: ptrfrom.String("CVE-2022-26499"),
					},
					{
						Type:            ptrfrom.String("cve"),
						VulnerabilityID: ptrfrom.String("CVE-2019-13110"),
					},
				},
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
						},
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query on OSV and novuln (return nothing as not valid)",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O2,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						VulnerabilityID: ptrfrom.String("CVE-2022-26499"),
					},
					{
						NoVuln: ptrfrom.Bool(true),
					},
				},
			},
			ExpVulnEqual: nil,
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.C2, testdata.G1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.G1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						Type: ptrfrom.String("ghsa"),
					},
				},
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "ghsa",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
						},
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.C2, testdata.G1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.G1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						VulnerabilityID: ptrfrom.String("AEV-2022-26499"),
					},
				},
			},
			ExpVulnEqual: nil,
		},
		{
			Name:   "Query multiple",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.C2, testdata.G1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.G1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						Type:            ptrfrom.String("cve"),
						VulnerabilityID: ptrfrom.String("cve-2014-8139"),
					},
				},
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
						},
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query on ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.C2, testdata.G1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.G1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryID: true,
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						{
							Type:             "ghsa",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query ID not found",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.C2, testdata.G1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.G1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				ID: ptrfrom.String("123456"),
			},
			ExpVulnEqual: nil,
			ExpQueryErr:  true,
		},
		{
			Name: "Query Error",
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						ID: ptrfrom.String("6"),
					},
				},
			},
			ExpQueryErr: false,
		},
		{
			Name: "Query Bad ID",
			Query: &model.VulnEqualSpec{
				ID: ptrfrom.String("-123"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var collectedVulnIDs []*model.VulnerabilityIDs
			for _, g := range test.InVuln {
				if vulnIDs, err := b.IngestVulnerability(ctx, *g); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				} else {
					collectedVulnIDs = append(collectedVulnIDs, vulnIDs)
				}
			}
			for _, o := range test.Calls {
				veID, err := b.IngestVulnEqual(ctx, *o.Vuln, *o.OtherVuln, *o.In)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.VulnEqualSpec{
						ID: ptrfrom.String(veID),
					}
				}
				if test.QueryVulnID {
					test.Query = &model.VulnEqualSpec{
						Vulnerabilities: []*model.VulnerabilitySpec{
							{
								ID: ptrfrom.String(collectedVulnIDs[1].VulnerabilityNodeID),
							},
							{
								ID: ptrfrom.String(collectedVulnIDs[2].VulnerabilityNodeID),
							},
						},
					}
				}
			}
			got, err := b.VulnEqual(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpVulnEqual, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestVulnEquals(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := deleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Vulns      []*model.VulnerabilityInputSpec
		OtherVulns []*model.VulnerabilityInputSpec
		Ins        []*model.VulnEqualInputSpec
	}
	tests := []struct {
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		Query        *model.VulnEqualSpec
		ExpVulnEqual []*model.VulnEqual
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.O1, testdata.C2},
			Calls: []call{
				{
					Vulns:      []*model.VulnerabilityInputSpec{testdata.O1, testdata.O1},
					OtherVulns: []*model.VulnerabilityInputSpec{testdata.C1, testdata.C2},
					Ins: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
						},
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Ingest same twice",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.O1, testdata.C1},
			Calls: []call{
				{
					Vulns:      []*model.VulnerabilityInputSpec{testdata.O1, testdata.O1},
					OtherVulns: []*model.VulnerabilityInputSpec{testdata.C1, testdata.C1},
					Ins: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
						},
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
					},
					Justification: "test justification",
				},
			},
		},

		{
			Name:   "Query on OSV",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.O2, testdata.G2},
			Calls: []call{
				{
					Vulns:      []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2},
					OtherVulns: []*model.VulnerabilityInputSpec{testdata.C1, testdata.G2},
					Ins: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						VulnerabilityID: ptrfrom.String("GHSA-xrw3-wqph-3fxg"),
					},
				},
			},
			ExpVulnEqual: []*model.VulnEqual{
				{
					Vulnerabilities: []*model.Vulnerability{
						{
							Type:             "ghsa",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.G2out},
						},
						{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
						},
					},
					Justification: "test justification",
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if _, err := b.IngestVulnerabilities(ctx, test.InVuln); err != nil {
				t.Fatalf("Could not ingest vulnerability: %a", err)
			}
			for _, o := range test.Calls {
				_, err := b.IngestVulnEquals(ctx, o.Vulns, o.OtherVulns, o.Ins)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.VulnEqual(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpVulnEqual, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildVulnEqualByID(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := deleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Vuln      *model.VulnerabilityInputSpec
		OtherVuln *model.VulnerabilityInputSpec
		In        *model.VulnEqualInputSpec
	}
	tests := []struct {
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		Query        *model.VulnEqualSpec
		ExpVulnEqual *model.VulnEqual
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "Query on vuln Equal ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O2, testdata.C1},
			Calls: []call{
				{
					Vuln:      testdata.O2,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpVulnEqual: &model.VulnEqual{
				Vulnerabilities: []*model.Vulnerability{
					{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
					},
				},
				Justification: "test justification",
			},
		},
		{
			Name:   "Query on ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.G1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.G1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpVulnEqual: &model.VulnEqual{
				Vulnerabilities: []*model.Vulnerability{
					{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
				},
				Justification: "test justification",
			},
		},
		{
			Name:   "Query ID not found",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.C2, testdata.G1},
			Calls: []call{
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					Vuln:      testdata.O1,
					OtherVuln: testdata.G1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				ID: ptrfrom.String("123456"),
			},
			ExpVulnEqual: nil,
			ExpQueryErr:  true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, g := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, *g); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			for _, o := range test.Calls {
				veID, err := b.IngestVulnEqual(ctx, *o.Vuln, *o.OtherVuln, *o.In)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.(*arangoClient).buildVulnEqualByID(ctx, veID, test.Query)
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpVulnEqual, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}
