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

func TestIngestPointOfContact(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match model.MatchFlags
		HM    *model.PointOfContactInputSpec
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
					HM: &model.PointOfContactInputSpec{
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
						Source: testdata.S1,
					},
					HM: &model.PointOfContactInputSpec{
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
					IngestPointOfContact(ctx, o.Sub, &o.Match, *o.HM).
					Return(&model.PointOfContact{ID: "a"}, nil).
					Times(times)
				_, err := r.Mutation().IngestPointOfContact(ctx, o.Sub, o.Match, *o.HM)
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

func TestIngestPointOfContacts(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInputs
		Match model.MatchFlags
		PC    []*model.PointOfContactInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with two packages and one pointOfContact",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with two sources and one pointOfContact",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S1, testdata.S2},
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with two artifacts and one pointOfContact",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with one package, one source, one artifact and one pointOfContact",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages:  []*model.PkgInputSpec{testdata.P1},
						Sources:   []*model.SourceInputSpec{testdata.S1},
						Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					},
					PC: []*model.PointOfContactInputSpec{
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
					PC: []*model.PointOfContactInputSpec{
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
					IngestPointOfContacts(ctx, o.Sub, &o.Match, o.PC).
					Return([]string{}, nil).
					Times(times)
				_, err := r.Mutation().IngestPointOfContacts(ctx, o.Sub, o.Match, o.PC)
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

func TestPointOfContact(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.PointOfContactSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query with two subjects",
			Query: &model.PointOfContactSpec{
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
			Query: &model.PointOfContactSpec{
				Email:         ptrfrom.String("a@b.com"),
				Info:          ptrfrom.String("info1"),
				Since:         ptrfrom.Time(time.Unix(1e9, 0)),
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
				PointOfContact(ctx, test.Query).
				Times(times)
			_, err := r.Query().PointOfContact(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
