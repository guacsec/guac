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

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestVulnEqual() {
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
		ExpVulnEqual []*model.VulnEqual
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1},
			Calls: []call{
				call{
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
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						&model.Vulnerability{
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
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
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
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						&model.Vulnerability{
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
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
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
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						&model.Vulnerability{
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
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
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
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
						},
						&model.Vulnerability{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.C2, testdata.G1},
			Calls: []call{
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
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
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						&model.Vulnerability{
							Type:             "ghsa",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
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
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
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
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
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
						Type: ptrfrom.String("cve"),
					},
				},
			},
			ExpVulnEqual: []*model.VulnEqual{
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						&model.Vulnerability{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
						},
					},
					Justification: "test justification",
				},
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						&model.Vulnerability{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.C1, testdata.C2, testdata.G1},
			Calls: []call{
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.G1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				ID: ptrfrom.String("0"),
			},
			ExpVulnEqual: []*model.VulnEqual{
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
						},
						&model.Vulnerability{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
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
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      testdata.O1,
					OtherVuln: testdata.C2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
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
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("GetBackend() error = %v", err)
			}

			for _, g := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, *g); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			recordIDs := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				ve, err := b.IngestVulnEqual(ctx, *o.Vuln, *o.OtherVuln, *o.In)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				recordIDs[i] = ve.ID
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

func (s *Suite) TestIngestVulnEquals() {
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
			InVuln: []*model.VulnerabilityInputSpec{o1, c1, o1, c2},
			Calls: []call{
				call{
					Vulns:      []*model.VulnerabilityInputSpec{o1, o1},
					OtherVulns: []*model.VulnerabilityInputSpec{c1, c2},
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
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{o1out},
						},
						&model.Vulnerability{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{c1out},
						},
					},
					Justification: "test justification",
				},
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{o1out},
						},
						&model.Vulnerability{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{c2out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Ingest same twice",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1, o1, c1},
			Calls: []call{
				call{
					Vulns:      []*model.VulnerabilityInputSpec{o1, o1},
					OtherVulns: []*model.VulnerabilityInputSpec{c1, c1},
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
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{o1out},
						},
						&model.Vulnerability{
							Type:             "cve",
							VulnerabilityIDs: []*model.VulnerabilityID{c1out},
						},
					},
					Justification: "test justification",
				},
			},
		},

		{
			Name:   "Query on OSV",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1, o2, g2},
			Calls: []call{
				call{
					Vulns:      []*model.VulnerabilityInputSpec{o1, o2},
					OtherVulns: []*model.VulnerabilityInputSpec{c1, g2},
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
				&model.VulnEqual{
					Vulnerabilities: []*model.Vulnerability{
						&model.Vulnerability{
							Type:             "osv",
							VulnerabilityIDs: []*model.VulnerabilityID{o2out},
						},
						&model.Vulnerability{
							Type:             "ghsa",
							VulnerabilityIDs: []*model.VulnerabilityID{g2out},
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
	ctx := context.Background()
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("GetBackend() error = %v", err)
			}

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
