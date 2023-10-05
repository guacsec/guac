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
	"time"

	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func TestIngestMetadata(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		HM    *model.HasMetadataInputSpec
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
					Sub: model.PackageSourceOrArtifactInput{
						Source:   testdata.S1,
						Artifact: testdata.A1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
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
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Timestamp:     time.Unix(1e9, 0),
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
					IngestHasMetadata(ctx, o.Sub, o.Match, *o.HM).
					Return(&model.HasMetadata{ID: "a"}, nil).
					Times(times)
				_, err := r.Mutation().IngestHasMetadata(ctx, o.Sub, *o.Match, *o.HM)
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

func TestIngestBulkMetadata(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInputs
		Match model.MatchFlags
		HM    []*model.HasMetadataInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with two packages and one hasMetadata",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with two sources and one hasMetadata",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S1, testdata.S2},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with two artifacts and one hasMetadata",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with one package, one source, one artifact and one hasMetadata",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages:  []*model.PkgInputSpec{testdata.P1},
						Sources:   []*model.SourceInputSpec{testdata.S1},
						Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "HappyPath All Version",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
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
					IngestBulkHasMetadata(ctx, o.Sub, &o.Match, o.HM).
					Return([]string{}, nil).
					Times(times)
				_, err := r.Mutation().IngestBulkHasMetadata(ctx, o.Sub, o.Match, o.HM)
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

func TestMetadata(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.HasMetadataSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query with two subjects",
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
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
			Query: &model.HasMetadataSpec{
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
				HasMetadata(ctx, test.Query).
				Times(times)
			_, err := r.Query().HasMetadata(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
