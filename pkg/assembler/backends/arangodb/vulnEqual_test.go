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

package arangodb

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

func TestVulnEqual(t *testing.T) {
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
			InVuln: []*model.VulnerabilityInputSpec{o1, c1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
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
			Name:   "Igest same twice",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: c1,
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
			Name:   "Query on Justification",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: c1,
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
			InVuln: []*model.VulnerabilityInputSpec{o1, o2, c1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o2,
					OtherVuln: c1,
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
							VulnerabilityIDs: []*model.VulnerabilityID{o2out},
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
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1, c2, g1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: c2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: g1,
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
							VulnerabilityIDs: []*model.VulnerabilityID{o1out},
						},
						&model.Vulnerability{
							Type:             "ghsa",
							VulnerabilityIDs: []*model.VulnerabilityID{g1out},
						},
					},
					Justification: "test justification",
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1, c2, g1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: c2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: g1,
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
			InVuln: []*model.VulnerabilityInputSpec{o1, c1, c2, g1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: c2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: g1,
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
			Name:   "Query ID",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1, c2, g1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: c2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: g1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.VulnEqualSpec{
				ID: ptrfrom.String("8"),
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
			Name:   "Query ID not found",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1, c2, g1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: c2,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: g1,
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
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, g := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, *g); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestVulnEqual(ctx, *o.Vuln, *o.OtherVuln, *o.In)
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

func TestVulnerabilityEqualNeighbors(t *testing.T) {
	type call struct {
		Vuln      *model.VulnerabilityInputSpec
		OtherVuln *model.VulnerabilityInputSpec
		In        *model.VulnEqualInputSpec
	}
	tests := []struct {
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		ExpNeighbors map[string][]string
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"2": []string{"1", "5"}, // osv to isVuln
				"4": []string{"3", "5"}, // cve to isVuln
				"5": []string{"1", "3"}, // isVuln to osv and cve
			},
		},
		{
			Name:   "Two IsVuln",
			InVuln: []*model.VulnerabilityInputSpec{o1, c1, g1},
			Calls: []call{
				call{
					Vuln:      o1,
					OtherVuln: c1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
				call{
					Vuln:      o1,
					OtherVuln: g1,
					In: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"2": []string{"1", "7", "8"}, // osv to both isVuln
				"4": []string{"3", "7"},
				"6": []string{"5", "8"},
				"7": []string{"1", "3"},
				"8": []string{"1", "5"},
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
			for _, g := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, *g); err != nil {
					t.Fatalf("Could not ingest vulnerability: %s", err)
				}
			}
			for _, o := range test.Calls {
				if _, err := b.IngestVulnEqual(ctx, *o.Vuln, *o.OtherVuln, *o.In); err != nil {
					t.Fatalf("Could not ingest vuln Equal: %s", err)
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
