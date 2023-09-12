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

package resolvers_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

var greater = model.ComparatorGreater

func TestIngestVulnerabilityMetadata(t *testing.T) {
	type call struct {
		Vuln         *model.VulnerabilityInputSpec
		VulnMetadata *model.VulnerabilityMetadataInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with type novuln",
			Calls: []call{
				{
					Vuln: &model.VulnerabilityInputSpec{
						Type: "novuln",
					},
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with type cve with no ID",
			Calls: []call{
				{
					Vuln: &model.VulnerabilityInputSpec{
						Type: "cve",
					},
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Happy path",
			Calls: []call{
				{
					Vuln: testdata.O1,
					VulnMetadata: &model.VulnerabilityMetadataInputSpec{
						ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
						ScoreValue: 7.9,
						Timestamp:  t1,
						Collector:  "test collector",
						Origin:     "test origin",
					},
				},
			},
			ExpIngestErr: false,
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			for _, o := range test.Calls {
				times := 1
				if test.ExpIngestErr {
					times = 0
				}
				b.
					EXPECT().
					IngestVulnerabilityMetadata(ctx, gomock.Any(), *o.VulnMetadata).
					Return("xyz", nil).
					Times(times)
				_, err := r.Mutation().IngestVulnerabilityMetadata(ctx, *o.Vuln, *o.VulnMetadata)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
		})
	}
}

func TestIngestVulnerabilityMetadatas(t *testing.T) {
	type call struct {
		Vulns         []*model.VulnerabilityInputSpec
		VulnMetadatas []*model.VulnerabilityMetadataInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with two vulnerabilities and one vulnerabilityMetadata",
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{testdata.C1, testdata.C2},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with vulnerability type novuln",
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{
						{
							Type: "novuln",
						},
					},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with vulnerability type cve with no id",
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{
						{
							Type: "cve",
						},
					},
					VulnMetadatas: []*model.VulnerabilityMetadataInputSpec{
						{
							ScoreType:  model.VulnerabilityScoreTypeCVSSv3,
							ScoreValue: 7.9,
							Timestamp:  t1,
							Collector:  "test collector",
							Origin:     "test origin",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "HappyPath",
			Calls: []call{
				{
					Vulns: []*model.VulnerabilityInputSpec{testdata.C1, testdata.C2},
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
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			for _, o := range test.Calls {
				times := 1
				if test.ExpIngestErr {
					times = 0
				}
				b.
					EXPECT().
					IngestBulkVulnerabilityMetadata(ctx, gomock.Any(), o.VulnMetadatas).
					Return([]string{}, nil).
					Times(times)
				_, err := r.Mutation().IngestBulkVulnerabilityMetadata(ctx, o.Vulns, o.VulnMetadatas)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
		})
	}
}

func TestVulnerabilityMetadata(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.VulnerabilityMetadataSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query with Comparator but without ScoreValue",
			Query: &model.VulnerabilityMetadataSpec{
				Comparator: &greater,
				Collector:  ptrfrom.String("test collector"),
			},
			ExpQueryErr: true,
		},
		{
			Name: "Query with type Novuln and NoVuln false",
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type:   ptrfrom.String("Novuln"),
					NoVuln: ptrfrom.Bool(false),
				},
				Collector: ptrfrom.String("test collector"),
			},
			ExpQueryErr: true,
		},
		{
			Name: "Happy path - Vulnerability",
			Query: &model.VulnerabilityMetadataSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: ptrfrom.String("GHSA-h45f-rjvw-2rv2"),
					Type:            ptrfrom.String("GHSA"),
				},
				Collector: ptrfrom.String("test collector"),
			},
			ExpQueryErr: false,
		},
		{
			Name: "Happy path",
			Query: &model.VulnerabilityMetadataSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpQueryErr: false,
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			times := 1
			if test.ExpQueryErr {
				times = 0
			}
			b.
				EXPECT().
				VulnerabilityMetadata(ctx, gomock.Any()).
				Times(times)
			_, err := r.Query().VulnerabilityMetadata(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
