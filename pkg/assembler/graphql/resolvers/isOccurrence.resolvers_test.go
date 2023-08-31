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

func TestIngestOccurrence(t *testing.T) {
	type call struct {
		PkgSrc     model.PackageOrSourceInput
		Artifact   *model.ArtifactInputSpec
		Occurrence *model.IsOccurrenceInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with one package and one source",
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
						Source:  testdata.S1,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Happy path",
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
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
					IngestOccurrence(ctx, o.PkgSrc, *o.Artifact, *o.Occurrence).
					Return(&model.IsOccurrence{ID: "1"}, nil).
					Times(times)
				_, err := r.Mutation().IngestOccurrence(ctx, o.PkgSrc, *o.Artifact, *o.Occurrence)
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

func TestIngestOccurrences(t *testing.T) {
	type call struct {
		PkgSrcs     model.PackageOrSourceInputs
		Artifacts   []*model.ArtifactInputSpec
		Occurrences []*model.IsOccurrenceInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with two packages and one artifact",
			Calls: []call{
				{
					PkgSrcs: model.PackageOrSourceInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					Occurrences: []*model.IsOccurrenceInputSpec{
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
			Name: "Ingest with two packages, two artifacts and one occurrence",
			Calls: []call{
				{
					PkgSrcs: model.PackageOrSourceInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					Occurrences: []*model.IsOccurrenceInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with one source and two artifacts",
			Calls: []call{
				{
					PkgSrcs: model.PackageOrSourceInputs{
						Sources: []*model.SourceInputSpec{testdata.S1},
					},
					Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					Occurrences: []*model.IsOccurrenceInputSpec{
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
			Name: "Ingest with one source, one artifact and two occurrence",
			Calls: []call{
				{
					PkgSrcs: model.PackageOrSourceInputs{
						Sources: []*model.SourceInputSpec{testdata.S1},
					},
					Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					Occurrences: []*model.IsOccurrenceInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "another justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with both packages and sources",
			Calls: []call{
				{
					PkgSrcs: model.PackageOrSourceInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
						Sources:  []*model.SourceInputSpec{testdata.S1},
					},
					Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					Occurrences: []*model.IsOccurrenceInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "HappyPath - packages",
			Calls: []call{
				{
					PkgSrcs: model.PackageOrSourceInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					Occurrences: []*model.IsOccurrenceInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
		},
		{
			Name: "HappyPath - sources",
			Calls: []call{
				{
					PkgSrcs: model.PackageOrSourceInputs{
						Sources: []*model.SourceInputSpec{testdata.S1},
					},
					Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					Occurrences: []*model.IsOccurrenceInputSpec{{
						Justification: "test justification",
					}},
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
					IngestOccurrences(ctx, o.PkgSrcs, o.Artifacts, o.Occurrences).
					Return([]*model.IsOccurrence{{ID: "d"}}, nil).
					Times(times)
				_, err := r.Mutation().IngestOccurrences(ctx, o.PkgSrcs, o.Artifacts, o.Occurrences)
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

func TestIsOccurrence(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.IsOccurrenceSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query error",
			Query: &model.IsOccurrenceSpec{
				Subject: &model.PackageOrSourceSpec{
					Package: &model.PkgSpec{},
					Source:  &model.SourceSpec{},
				},
			},
			ExpQueryErr: true,
		},
		{
			Name: "Happy path",
			Query: &model.IsOccurrenceSpec{
				ID: ptrfrom.String("asdf"),
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
				IsOccurrence(ctx, test.Query).
				Times(times)
			_, err := r.Query().IsOccurrence(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
