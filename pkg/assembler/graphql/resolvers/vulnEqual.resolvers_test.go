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

func TestVulnEqual(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.VulnEqualSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query with three vulnerabilities",
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						VulnerabilityID: ptrfrom.String("CVE-2022-26499"),
					},
					{
						VulnerabilityID: ptrfrom.String("CVE-2021-26499"),
					},
					{
						VulnerabilityID: ptrfrom.String("CVE-2020-26499"),
					},
				},
				Justification: ptrfrom.String("test justification"),
			},
			ExpQueryErr: true,
		},
		{
			Name: "Happy path with vulnerabilities",
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						Type:            ptrfrom.String("cve"),
						VulnerabilityID: ptrfrom.String("CVE-2022-26499"),
					},
					{
						Type:            ptrfrom.String("osv"),
						VulnerabilityID: ptrfrom.String("CVE-2021-26499"),
					},
				},
				Justification: ptrfrom.String("test justification"),
			},
			ExpQueryErr: false,
		},
		{
			Name: "Happy path",
			Query: &model.VulnEqualSpec{
				Justification: ptrfrom.String("test justification"),
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
				VulnEqual(ctx, gomock.Any()).
				Times(times)
			_, err := r.Query().VulnEqual(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}

func TestIngestVulnEqual(t *testing.T) {
	type call struct {
		V1 *model.VulnerabilityInputSpec
		V2 *model.VulnerabilityInputSpec
		VE *model.VulnEqualInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "novuln vulnerability",
			Calls: []call{
				{
					V1: testdata.NoVulnInput,
					V2: testdata.O2,
					VE: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "novuln other vulnerability",
			Calls: []call{
				{
					V1: testdata.O1,
					V2: testdata.NoVulnInput,
					VE: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with no vuln ID",
			Calls: []call{
				{
					V1: &model.VulnerabilityInputSpec{
						Type:            "cve",
						VulnerabilityID: "",
					},
					V2: testdata.O1,
					VE: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with no vuln ID other vuln",
			Calls: []call{
				{
					V1: testdata.O1,
					V2: &model.VulnerabilityInputSpec{
						Type:            "cve",
						VulnerabilityID: "",
					},
					VE: &model.VulnEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with vuln ID",
			Calls: []call{
				{
					V1: testdata.O1,
					V2: testdata.O2,
					VE: &model.VulnEqualInputSpec{
						Justification: "test justification",
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
					IngestVulnEqualID(ctx, gomock.Any(), gomock.Any(), *o.VE).
					Return("", nil).
					Times(times)
				_, err := r.Mutation().IngestVulnEqual(ctx, *o.V1, *o.V2, *o.VE)
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

func TestIngestVulnEquals(t *testing.T) {
	type call struct {
		V1 []*model.VulnerabilityInputSpec
		V2 []*model.VulnerabilityInputSpec
		VE []*model.VulnEqualInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "uneven vulnerabilities",
			Calls: []call{
				{
					V1: []*model.VulnerabilityInputSpec{testdata.O1, testdata.NoVulnInput},
					V2: []*model.VulnerabilityInputSpec{testdata.O2},
					VE: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "uneven vulnEqual",
			Calls: []call{
				{
					V1: []*model.VulnerabilityInputSpec{testdata.O1, testdata.NoVulnInput},
					V2: []*model.VulnerabilityInputSpec{testdata.O2, testdata.NoVulnInput},
					VE: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "novuln vulnerability",
			Calls: []call{
				{
					V1: []*model.VulnerabilityInputSpec{testdata.O1, testdata.NoVulnInput},
					V2: []*model.VulnerabilityInputSpec{testdata.O2, testdata.O2},
					VE: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "novuln other vulnerability",
			Calls: []call{
				{
					V1: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2},
					V2: []*model.VulnerabilityInputSpec{testdata.O2, testdata.NoVulnInput},
					VE: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with no vuln ID",
			Calls: []call{
				{
					V1: []*model.VulnerabilityInputSpec{{
						Type:            "cve",
						VulnerabilityID: "",
					}},
					V2: []*model.VulnerabilityInputSpec{testdata.O1},
					VE: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with no vuln ID other vuln",
			Calls: []call{
				{
					V1: []*model.VulnerabilityInputSpec{testdata.O1},
					V2: []*model.VulnerabilityInputSpec{{
						Type:            "cve",
						VulnerabilityID: "",
					}},
					VE: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with vuln ID",
			Calls: []call{
				{
					V1: []*model.VulnerabilityInputSpec{testdata.O1},
					V2: []*model.VulnerabilityInputSpec{testdata.O2},
					VE: []*model.VulnEqualInputSpec{
						{
							Justification: "test justification",
						},
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
					IngestVulnEquals(ctx, gomock.Any(), gomock.Any(), o.VE).
					Return([]string{}, nil).
					Times(times)
				_, err := r.Mutation().IngestVulnEquals(ctx, o.V1, o.V2, o.VE)
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
