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

func TestIngestHasSbom(t *testing.T) {
	type call struct {
		Sub model.PackageOrArtifactInput
		HS  *model.HasSBOMInputSpec
		Inc *model.HasSBOMIncludesInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with two subjects",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package:  testdata.P1,
						Artifact: testdata.A1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
					Inc: &model.HasSBOMIncludesInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Happy path",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI:        "test uri",
						KnownSince: ZeroTime,
					},
					Inc: &model.HasSBOMIncludesInputSpec{},
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
					IngestHasSbom(ctx, o.Sub, *o.HS, *o.Inc).
					Return(&model.HasSbom{ID: "a"}, nil).
					Times(times)
				_, err := r.Mutation().IngestHasSbom(ctx, o.Sub, *o.HS, *o.Inc)
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

func TestIngestHasSBOMs(t *testing.T) {
	type call struct {
		Sub model.PackageOrArtifactInputs
		HS  []*model.HasSBOMInputSpec
		Inc []*model.HasSBOMIncludesInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with two packages, one HasSbom and one includes",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
					},
					Inc: []*model.HasSBOMIncludesInputSpec{{}},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with two artifacts, one HasSbom and one includes",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
					},
					Inc: []*model.HasSBOMIncludesInputSpec{{}},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with one package, one HasSbom and two includes",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
					},
					Inc: []*model.HasSBOMIncludesInputSpec{{}, {}},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with one package, one artifact and one HasSbom",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages:  []*model.PkgInputSpec{testdata.P1},
						Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI:        "test uri",
							KnownSince: ZeroTime,
						},
					},
					Inc: []*model.HasSBOMIncludesInputSpec{{}},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "HappyPath",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI:        "test uri",
							KnownSince: ZeroTime,
						},
					},
					Inc: []*model.HasSBOMIncludesInputSpec{{}},
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
					IngestHasSBOMs(ctx, o.Sub, o.HS, o.Inc).
					Return([]*model.HasSbom{{ID: "a"}}, nil).
					Times(times)
				_, err := r.Mutation().IngestHasSBOMs(ctx, o.Sub, o.HS, o.Inc)
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

func TestHasSbom(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.HasSBOMSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query with two subjects",
			Query: &model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("asdf"),
					},
				},
			},
			ExpQueryErr: true,
		},
		{
			Name: "Happy path",
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri"),
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
				HasSBOM(ctx, test.Query).
				Times(times)
			_, err := r.Query().HasSbom(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
