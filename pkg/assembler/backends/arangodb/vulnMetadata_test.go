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
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func scoreTypePointer(v model.VulnerabilityScoreType) *model.VulnerabilityScoreType { return &v }

var greater model.Comparator = model.ComparatorGreater
var greaterEqual model.Comparator = model.ComparatorGreaterEqual
var less model.Comparator = model.ComparatorLess
var lessEqual model.Comparator = model.ComparatorLessEqual
var equal model.Comparator = model.ComparatorEqual

var cvss2ScoreType model.VulnerabilityScoreType = model.VulnerabilityScoreTypeCVSSv2

func TestIngestVulnMetadata(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
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
		QueryID      bool
		QueryVulnID  bool
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1},
			Calls: []call{
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
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
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Duplicate",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1, testdata.C1},
			Calls: []call{
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
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
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Certify OSV",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Vuln: testdata.O1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("osv"),
				},
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query on Vulnerability ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Vuln: testdata.O1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			QueryVulnID: true,
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Certify GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeEPSSv1,
						ScoreValue: 0.95,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("ghsa"),
				},
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv1,
					ScoreValue: 0.95,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeEPSSv2,
						ScoreValue: 0.98,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type:            ptrfrom.String("ghsa"),
					VulnerabilityID: &testdata.G1.VulnerabilityID,
				},
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv2,
					ScoreValue: 0.98,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv1,
					ScoreValue: 0.95,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query on ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			QueryID: true,
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
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
			Name:   "Query greater than - no score value",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C2, testdata.C1},
			Calls: []call{
				{
					Vuln: testdata.C2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Comparator: &greater,
			},
			ExpQueryErr: true,
			ExpVuln:     []*model.VulnerabilityMetadata{},
		},
		{
			Name:   "Query greater than",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C2, testdata.C1},
			Calls: []call{
				{
					Vuln: testdata.C2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
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
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query greater than - specific type",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C2, testdata.C1},
			Calls: []call{
				{
					Vuln: testdata.C2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
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
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query greater than or equal",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C2, testdata.C1, testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.C2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  testdata.T1,
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
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query less than",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C2, testdata.C1, testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.C2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  testdata.T1,
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
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv1,
					ScoreValue: 0.95,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv2,
					ScoreValue: 0.98,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 6.3,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query less than or equal",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C2, testdata.C1, testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.C2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  testdata.T1,
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
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv1,
					ScoreValue: 0.95,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeEPSSv2,
					ScoreValue: 0.98,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 6.3,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query equal",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C2, testdata.C1, testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.C2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  testdata.T1,
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
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query without comparator",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C2, testdata.C1, testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.C2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 6.3,
						Timestamp:  testdata.T1,
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
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query all vulns - with novuln boolean omitted",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C2, testdata.C1, testdata.G1},
			Calls: []call{
				{
					Vuln: testdata.C2,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
						ScoreValue: 8.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.C1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeEPSSv2,
						ScoreValue: 0.96,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
				{
					Vuln: testdata.G1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 2.9,
						Timestamp:  testdata.T1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type:            ptrfrom.String("cve"),
					VulnerabilityID: &testdata.C2.VulnerabilityID,
				},
				ScoreType:  scoreTypePointer(model.VulnerabilityScoreTypeCVSSv2),
				ScoreValue: ptrfrom.Float64(8.9),
				Timestamp:  ptrfrom.Time(testdata.T1),
				Collector:  ptrfrom.String("test collector"),
				Origin:     ptrfrom.String("test origin"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, g := range test.InVuln {
				ingestedVuln, err := b.IngestVulnerability(ctx, *g)
				if err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
				if test.QueryVulnID {
					test.Query = &model.VulnerabilityMetadataSpec{
						Vulnerability: &model.VulnerabilitySpec{
							ID: ptrfrom.String(ingestedVuln.VulnerabilityIDs[0].ID),
						},
					}
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
				if test.QueryID {
					test.Query = &model.VulnerabilityMetadataSpec{
						ID: ptrfrom.String(record),
					}
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

func TestIngestVulnMetadatas(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
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
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1, testdata.C2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{testdata.C1, testdata.C2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  testdata.T1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  testdata.T1,
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
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					ID: "10",
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Certify OSV",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  testdata.T1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  testdata.T1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("osv"),
				},
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Certify GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1, testdata.G2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{testdata.G1, testdata.G2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  testdata.T1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  testdata.T1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("ghsa"),
				},
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G2out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
					ScoreValue: 8.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1, testdata.G2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{testdata.G1, testdata.G2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  testdata.T1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  testdata.T1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &testdata.G1.VulnerabilityID,
				},
			},
			ExpVuln: []*model.VulnerabilityMetadata{
				{
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
					ScoreValue: 7.9,
					Timestamp:  testdata.T1,
					Collector:  "test collector",
					Origin:     "test origin",
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1, testdata.G2},
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{testdata.G1, testdata.G2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  testdata.T1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
							ScoreValue: 8.9,
							Timestamp:  testdata.T1,
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
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
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

// TODO (pxp928): add tests back in when implemented

// func TestVulnMetadataNeighbors(t *testing.T) {
// 	type call struct {
// 		Vuln         *model.VulnerabilityInputSpec
// 		VulnMetadata *model.VulnerabilityMetadataInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InVuln       []*model.VulnerabilityInputSpec
// 		Calls        []call
// 		ExpNeighbors map[string][]string
// 	}{
// 		{
// 			Name:   "HappyPath",
// 			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
// 			Calls: []call{
// 				call{
// 					Vuln: testdata.O1,
// 					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
// 						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
// 						ScoreValue: 7.9,
// 						Timestamp:  testdata.T1,
// 						Collector:  "test collector",
// 						Origin:     "test origin",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"2": []string{"1", "3"}, // Vuln -> vunType, vulnMeta1
// 				"3": []string{"1"},      // vulnMeta1 -> vuln
// 			},
// 		},
// 		{
// 			Name:   "Two vuln metadata on same vulnerability",
// 			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
// 			Calls: []call{
// 				call{
// 					Vuln: testdata.O1,
// 					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
// 						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
// 						ScoreValue: 7.9,
// 						Timestamp:  testdata.T1,
// 						Collector:  "test collector",
// 						Origin:     "test origin",
// 					},
// 				},
// 				call{
// 					Vuln: testdata.O1,
// 					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
// 						ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
// 						ScoreValue: 8.9,
// 						Timestamp:  testdata.T1,
// 						Collector:  "test collector",
// 						Origin:     "test origin",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"2": []string{"1", "3", "4"}, // Vuln1 -> vunType, vulnMeta1
// 				"3": []string{"1"},           // vulnMeta1 -> vuln1
// 				"4": []string{"1"},           // vulnMeta2 -> vuln2
// 			},
// 		},
// 	}
// 	ctx := context.Background()
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			b, err := inmem.getBackend(nil)
// 			if err != nil {
// 				t.Fatalf("Could not instantiate testing backend: %v", err)
// 			}
// 			for _, o := range test.InVuln {
// 				if _, err := b.IngestVulnerability(ctx, *o); err != nil {
// 					t.Fatalf("Could not ingest osv: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				if _, err := b.IngestVulnerabilityMetadata(ctx, *o.Vuln, *o.VulnMetadata); err != nil {
// 					t.Fatalf("Could not ingest certifyVuln")
// 				}
// 			}
// 			for q, r := range test.ExpNeighbors {
// 				got, err := b.Neighbors(ctx, q, nil)
// 				if err != nil {
// 					t.Fatalf("Could not query neighbors: %s", err)
// 				}
// 				gotIDs := convNodes(got)
// 				slices.Sort(r)
// 				slices.Sort(gotIDs)
// 				if diff := cmp.Diff(r, gotIDs); diff != "" {
// 					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 				}
// 			}
// 		})
// 	}
// }
