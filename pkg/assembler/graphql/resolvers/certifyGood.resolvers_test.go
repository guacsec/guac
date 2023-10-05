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

func TestIngestCertifyGood(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match model.MatchFlags
		CG    *model.CertifyGoodInputSpec
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
					CG: &model.CertifyGoodInputSpec{
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
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
						KnownSince:    ZeroTime,
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
					IngestCertifyGood(ctx, o.Sub, &o.Match, *o.CG).
					Return(testdata.CG1out, nil).
					Times(times)
				_, err := r.Mutation().IngestCertifyGood(ctx, o.Sub, o.Match, *o.CG)
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

func TestIngestCertifyGoods(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInputs
		Match model.MatchFlags
		CG    []*model.CertifyGoodInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with two packages and one CertifyGood",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with two sources and one CertifyGood",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S1, testdata.S2},
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with two artifacts and one CertifyGood",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with one package, one source, one artifact and one CertifyGood",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages:  []*model.PkgInputSpec{testdata.P1},
						Sources:   []*model.SourceInputSpec{testdata.S1},
						Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					},
					CG: []*model.CertifyGoodInputSpec{
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
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
							KnownSince:    ZeroTime,
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
					IngestCertifyGoods(ctx, o.Sub, &o.Match, o.CG).
					Return([]*model.CertifyGood{testdata.CG1out}, nil).
					Times(times)
				_, err := r.Mutation().IngestCertifyGoods(ctx, o.Sub, o.Match, o.CG)
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

func TestCertifyGood(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.CertifyGoodSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query with two subjects",
			Query: &model.CertifyGoodSpec{
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
			Query: &model.CertifyGoodSpec{
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
				CertifyGood(ctx, test.Query).
				Times(times)
			_, err := r.Query().CertifyGood(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
