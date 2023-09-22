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

func TestIngestCertifyLegal(t *testing.T) {
	type call struct {
		Sub model.PackageOrSourceInput
		Dec []*model.LicenseInputSpec
		Dis []*model.LicenseInputSpec
		CL  *model.CertifyLegalInputSpec
	}
	tests := []struct {
		Name         string
		Call         call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with two subjects",
			Call: call{
				Sub: model.PackageOrSourceInput{
					Source:  testdata.S1,
					Package: testdata.P1,
				},
				CL: &model.CertifyLegalInputSpec{
					Justification: "test justification",
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Happy path",
			Call: call{
				Sub: model.PackageOrSourceInput{
					Package: testdata.P1,
				},
				CL: &model.CertifyLegalInputSpec{
					Justification: "test justification",
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
			times := 1
			if test.ExpIngestErr {
				times = 0
			}
			b.
				EXPECT().
				IngestCertifyLegal(ctx, test.Call.Sub, test.Call.Dec, test.Call.Dis, test.Call.CL).
				Return(&model.CertifyLegal{ID: "123"}, nil).
				Times(times)
			_, err := r.Mutation().IngestCertifyLegal(ctx, test.Call.Sub, test.Call.Dec, test.Call.Dis, *test.Call.CL)
			if (err != nil) != test.ExpIngestErr {
				t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}

func TestIngestCertifyLegals(t *testing.T) {
	type call struct {
		Sub model.PackageOrSourceInputs
		Dec [][]*model.LicenseInputSpec
		Dis [][]*model.LicenseInputSpec
		CL  []*model.CertifyLegalInputSpec
	}
	tests := []struct {
		Name         string
		Call         call
		ExpIngestErr bool
	}{
		{
			Name: "HappyPath Pkg",
			Call: call{
				Sub: model.PackageOrSourceInputs{
					Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
				},
				Dec: [][]*model.LicenseInputSpec{nil, nil},
				Dis: [][]*model.LicenseInputSpec{nil, nil},
				CL: []*model.CertifyLegalInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification 2",
					},
				},
			},
		},
		{
			Name: "HappyPath Src",
			Call: call{
				Sub: model.PackageOrSourceInputs{
					Sources: []*model.SourceInputSpec{testdata.S1, testdata.S2},
				},
				Dec: [][]*model.LicenseInputSpec{nil, nil},
				Dis: [][]*model.LicenseInputSpec{nil, nil},
				CL: []*model.CertifyLegalInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification 2",
					},
				},
			},
		},
		{
			Name: "Ingest with two packages and one CertifyLegal",
			Call: call{
				Sub: model.PackageOrSourceInputs{
					Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
				},
				Dec: [][]*model.LicenseInputSpec{nil, nil},
				Dis: [][]*model.LicenseInputSpec{nil, nil},
				CL: []*model.CertifyLegalInputSpec{
					{
						Justification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with two sources and one CertifyLegal",
			Call: call{
				Sub: model.PackageOrSourceInputs{
					Sources: []*model.SourceInputSpec{testdata.S1, testdata.S2},
				},
				Dec: [][]*model.LicenseInputSpec{nil, nil},
				Dis: [][]*model.LicenseInputSpec{nil, nil},
				CL: []*model.CertifyLegalInputSpec{
					{
						Justification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with one Dis",
			Call: call{
				Sub: model.PackageOrSourceInputs{
					Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
				},
				Dec: [][]*model.LicenseInputSpec{nil, nil},
				Dis: [][]*model.LicenseInputSpec{nil},
				CL: []*model.CertifyLegalInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification 2",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with one package and one source, two everything else",
			Call: call{
				Sub: model.PackageOrSourceInputs{
					Packages: []*model.PkgInputSpec{testdata.P1},
					Sources:  []*model.SourceInputSpec{testdata.S1},
				},
				Dec: [][]*model.LicenseInputSpec{nil, nil},
				Dis: [][]*model.LicenseInputSpec{nil, nil},
				CL: []*model.CertifyLegalInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification 2",
					},
				},
			},
			ExpIngestErr: true,
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			times := 1
			if test.ExpIngestErr {
				times = 0
			}
			b.
				EXPECT().
				IngestCertifyLegals(ctx, test.Call.Sub, test.Call.Dec, test.Call.Dis, test.Call.CL).
				Return(nil, nil).
				Times(times)
			_, err := r.Mutation().IngestCertifyLegals(ctx, test.Call.Sub, test.Call.Dec, test.Call.Dis, test.Call.CL)
			if (err != nil) != test.ExpIngestErr {
				t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}

func TestCertifyLegal(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.CertifyLegalSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query with two subjects",
			Query: &model.CertifyLegalSpec{
				Subject: &model.PackageOrSourceSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
					Source: &model.SourceSpec{
						Name: ptrfrom.String("asdf"),
					},
				},
			},
			ExpQueryErr: true,
		},
		{
			Name: "Query with pkg",
			Query: &model.CertifyLegalSpec{
				Subject: &model.PackageOrSourceSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
		},
		{
			Name: "Query with src",
			Query: &model.CertifyLegalSpec{
				Subject: &model.PackageOrSourceSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("asdf"),
					},
				},
			},
		},
		{
			Name: "Happy path no sub",
			Query: &model.CertifyLegalSpec{
				Justification: ptrfrom.String("test justification"),
			},
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
				CertifyLegal(ctx, test.Query).
				Times(times)
			_, err := r.Query().CertifyLegal(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
