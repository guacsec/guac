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
	"strconv"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var (
	greater      model.Comparator = model.ComparatorGreater
	greaterEqual model.Comparator = model.ComparatorGreaterEqual
	less         model.Comparator = model.ComparatorLess
	lessEqual    model.Comparator = model.ComparatorLessEqual
	equal        model.Comparator = model.ComparatorEqual
)

var cvss2ScoreType model.VulnerabilityScoreType = model.VulnerabilityScoreTypeCVSSv2

func (s *Suite) TestIngestVulnMetadata() {
	type call struct {
		Vuln         *model.VulnerabilityInputSpec
		VulnMetadata *model.VulnerabilityMetadataInputSpec
	}

	tests := []struct {
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		ExpVuln      []*model.VulnerabilityMetadata
		Query        *model.VulnerabilityMetadataSpec
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{c1},
			Calls: []call{
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					ID: "1",
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Duplicate",
			InVuln: []*model.VulnerabilityInputSpec{c1, c1},
			Calls: []call{
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					ID: "1",
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Certify OSV",
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Vuln: o1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Certify GHSA",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			Calls: []call{
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeEPSSv1,
						ScoreValue: 0.95,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv1,
					ScoreValue: 0.95,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			Calls: []call{
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeEPSSv2,
						ScoreValue: 0.98,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type:            ptrfrom.String("ghsa"),
					VulnerabilityID: &g1.VulnerabilityID,
				},
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv2,
					ScoreValue: 0.98,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query ID",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			Calls: []call{
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				ID: ptrfrom.String("0"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{g1},
			Calls: []call{
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: ptrfrom.String("asdf"),
				},
			},
			ExpVuln: nil,
		},
		{
			Name:   "Query greater than",
			InVuln: []*model.VulnerabilityInputSpec{c2, c1},
			Calls: []call{
				{
					Vuln: c2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Comparator: &greater,
				ScoreValue: ptrfrom.Float64(7.0),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query greater than - specific type",
			InVuln: []*model.VulnerabilityInputSpec{c2, c1},
			Calls: []call{
				{
					Vuln: c2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Comparator: &greater,
				ScoreValue: ptrfrom.Float64(7.0),
				ScoreType:  &cvss2ScoreType,
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query greater than or equal",
			InVuln: []*model.VulnerabilityInputSpec{c2, c1, g1},
			Calls: []call{
				{
					Vuln: c2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Comparator: &greaterEqual,
				ScoreValue: ptrfrom.Float64(7.9),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query less than",
			InVuln: []*model.VulnerabilityInputSpec{c2, c1, g1},
			Calls: []call{
				{
					Vuln: c2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Comparator: &less,
				ScoreValue: ptrfrom.Float64(6.5),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 6.3,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query less than or equal",
			InVuln: []*model.VulnerabilityInputSpec{c2, c1, g1},
			Calls: []call{
				{
					Vuln: c2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Comparator: &lessEqual,
				ScoreValue: ptrfrom.Float64(7.9),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 6.3,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query equal",
			InVuln: []*model.VulnerabilityInputSpec{c2, c1, g1},
			Calls: []call{
				{
					Vuln: c2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Comparator: &equal,
				ScoreValue: ptrfrom.Float64(7.9),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query without comparator",
			InVuln: []*model.VulnerabilityInputSpec{c2, c1, g1},
			Calls: []call{
				{
					Vuln: c2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				ScoreValue: ptrfrom.Float64(7.9),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query all vulns - with novuln boolean omitted",
			InVuln: []*model.VulnerabilityInputSpec{c2, c1, g1},
			Calls: []call{
				{
					Vuln: c2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: c1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeEPSSv2,
						ScoreValue: 0.96,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: g1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 2.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{},
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv2,
					ScoreValue: 0.96,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 2.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name: "Ingest without vuln",
			Calls: []call{
				{
					Vuln:         &model.VulnerabilityInputSpec{},
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{},
				},
			},
			Query:        &model.VulnerabilityMetadataSpec{},
			ExpIngestErr: true,
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
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

			ids := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				record, err := b.IngestVulnerabilityMetadata(ctx, *o.Vuln, *o.VulnMetadata)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				ids[i] = record
			}

			if test.Query != nil {
				if test.Query.ID != nil {
					idIndex, err := strconv.Atoi(*test.Query.ID)
					if err == nil && idIndex > -1 && idIndex < len(ids) {
						test.Query.ID = ptrfrom.String(ids[idIndex])
					}
				}
			}

			got, err := b.VulnerabilityMetadata(ctx, test.Query)
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

func (s *Suite) TestIngestVulnMetadatas() {
	type call struct {
		Vulns         []*model.VulnerabilityInputSpec
		VulnMetadatas []*model.VulnerabilityMetadataInputSpec
	}

	tests := []struct {
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		ExpVuln      []*model.VulnerabilityMetadata
		Query        *model.VulnerabilityMetadataSpec
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{c1, c2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{c1, c2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					ID: "1",
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					ID: "10",
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Certify OSV",
			InVuln: []*model.VulnerabilityInputSpec{o1, o2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{o1, o2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Certify GHSA",
			InVuln: []*model.VulnerabilityInputSpec{g1, g2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{g1, g2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{g1, g2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{g1, g2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &g1.VulnerabilityID,
				},
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{g1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  t1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{g1, g2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{g1, g2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: ptrfrom.String("asdf"),
				},
			},
			ExpVuln: nil,
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}

			if _, err := b.IngestVulnerabilities(ctx, test.InVuln); err != nil {
				t.Fatalf("Could not ingest vulnerabilities: %a", err)
			}
			for _, o := range test.Calls {
				_, err := b.IngestBulkVulnerabilityMetadata(ctx, o.Vulns, o.VulnMetadatas)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}

			}

			got, err := b.VulnerabilityMetadata(ctx, test.Query)
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
