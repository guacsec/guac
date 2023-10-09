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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// var pNone = &model.PkgInputSpec{
// 	Type: "none",
// 	Name: "none",
// }

// var sNone = &model.SourceInputSpec{
// 	Type:      "none",
// 	Namespace: "github.com/nope",
// 	Name:      "none",
// }

// var lNone = &model.LicenseInputSpec{
// 	Name:        "LIC_NONE",
// 	ListVersion: ptrfrom.String("1.2.3"),
// }

func TestLegal(t *testing.T) {
	type call struct {
		PkgSrc model.PackageOrSourceInput
		Dec    []*model.LicenseInputSpec
		Dis    []*model.LicenseInputSpec
		Legal  *model.CertifyLegalInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InLic        []*model.LicenseInputSpec
		Calls        []call
		IDInFilter   int
		Query        *model.CertifyLegalSpec
		ExpLegal     []*model.CertifyLegal
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.P1out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.P1out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification 2",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Justification: ptrfrom.String("test justification 2"),
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.P1out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification 2",
				},
			},
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification 2",
					},
				},
			},
			IDInFilter: 2,
			Query:      &model.CertifyLegalSpec{},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.P1out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification 2",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P2,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Subject: &model.PackageOrSourceSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.P2out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S2,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Subject: &model.PackageOrSourceSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("myrepo"),
					},
				},
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.S1out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on License",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InLic: []*model.LicenseInputSpec{testdata.L1, testdata.L2, testdata.L3},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1, testdata.L2},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L3},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				DeclaredLicenses: []*model.LicenseSpec{
					{Name: ptrfrom.String("GPL-2.0-or-later")},
				},
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.S1out,
					DeclaredLicenses: []*model.License{testdata.L1out, testdata.L2out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on License inline",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InLic: []*model.LicenseInputSpec{testdata.L1, testdata.L2, testdata.L4},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1, testdata.L4},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L2},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				DeclaredLicenses: []*model.LicenseSpec{
					{Inline: &testdata.InlineLicense},
				},
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.S1out,
					DeclaredLicenses: []*model.License{testdata.L1out, testdata.L4out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on expression",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Legal: &model.CertifyLegalInputSpec{
						DeclaredLicense: "GPL OR MIT",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Legal: &model.CertifyLegalInputSpec{
						DeclaredLicense: "GPL AND MIT",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				DeclaredLicense: ptrfrom.String("GPL AND MIT"),
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:         testdata.P1out,
					DeclaredLicense: "GPL AND MIT",
				},
			},
		},
		{
			Name:  "Query on attribution",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Legal: &model.CertifyLegalInputSpec{
						Attribution: "Copyright Jeff",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Legal: &model.CertifyLegalInputSpec{
						Attribution: "Copyright Bob",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Attribution: ptrfrom.String("Copyright Jeff"),
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:     testdata.P1out,
					Attribution: "Copyright Jeff",
				},
			},
		},
		{
			Name:  "Query on time",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Legal: &model.CertifyLegalInputSpec{
						TimeScanned: testdata.T3,
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Legal: &model.CertifyLegalInputSpec{
						TimeScanned: testdata.T2,
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				TimeScanned: &testdata.T2,
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:     testdata.P1out,
					TimeScanned: testdata.T2,
				},
			},
		},
		{
			Name:  "Query multiple",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification special",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P2,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification special",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P3,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification other",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Justification: ptrfrom.String("test justification special"),
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.P1out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification special",
				},
				{
					Subject:          testdata.P2out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification special",
				},
			},
		},
		// {
		// 	Name: "Ingest without Package",
		// 	Calls: []call{
		// 		{
		// 			PkgSrc: model.PackageOrSourceInput{
		// 				Package: pNone,
		// 			},
		// 			Legal: &model.CertifyLegalInputSpec{},
		// 		},
		// 	},
		// 	ExpIngestErr: true,
		// },
		// {
		// 	Name: "Ingest without Source",
		// 	Calls: []call{
		// 		{
		// 			PkgSrc: model.PackageOrSourceInput{
		// 				Source: sNone,
		// 			},
		// 			Legal: &model.CertifyLegalInputSpec{},
		// 		},
		// 	},
		// 	ExpIngestErr: true,
		// },
		// {
		// 	Name:  "Ingest without License",
		// 	InPkg: []*model.PkgInputSpec{testdata.P1},
		// 	Calls: []call{
		// 		{
		// 			PkgSrc: model.PackageOrSourceInput{
		// 				Package: testdata.P1,
		// 			},
		// 			Dec:   []*model.LicenseInputSpec{lNone},
		// 			Legal: &model.CertifyLegalInputSpec{},
		// 		},
		// 	},
		// 	ExpIngestErr: true,
		// },
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := getBackend(ctx, arangArg)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InLic {
				if _, err := b.IngestLicense(ctx, a); err != nil {
					t.Fatalf("Could not ingest license: %v", err)
				}
			}
			for i, o := range test.Calls {
				cl, err := b.IngestCertifyLegal(ctx, o.PkgSrc, o.Dec, o.Dis, o.Legal)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if (i + 1) == test.IDInFilter {
					test.Query.ID = &cl.ID
				}
			}
			got, err := b.CertifyLegal(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpLegal, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLegals(t *testing.T) {
	type call struct {
		PkgSrc model.PackageOrSourceInputs
		Dec    [][]*model.LicenseInputSpec
		Dis    [][]*model.LicenseInputSpec
		Legal  []*model.CertifyLegalInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InLic        []*model.LicenseInputSpec
		Calls        []call
		Query        *model.CertifyLegalSpec
		ExpLegal     []*model.CertifyLegal
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Dec: [][]*model.LicenseInputSpec{{testdata.L1}, {testdata.L1}},
					Dis: [][]*model.LicenseInputSpec{{}, {}},
					Legal: []*model.CertifyLegalInputSpec{
						{Justification: "test justification"},
						{Justification: "test justification"},
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          testdata.P1out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification",
				},
				{
					Subject:          testdata.P2out,
					DeclaredLicenses: []*model.License{testdata.L1out},
					Justification:    "test justification",
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := getBackend(ctx, arangArg)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InLic {
				if _, err := b.IngestLicense(ctx, a); err != nil {
					t.Fatalf("Could not ingest license: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestCertifyLegals(ctx, o.PkgSrc, o.Dec, o.Dis, o.Legal)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.CertifyLegal(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpLegal, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildCertifyLegalByID(t *testing.T) {
	type call struct {
		PkgSrc model.PackageOrSourceInput
		Dec    []*model.LicenseInputSpec
		Dis    []*model.LicenseInputSpec
		Legal  *model.CertifyLegalInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InLic        []*model.LicenseInputSpec
		Calls        []call
		Query        *model.CertifyLegalSpec
		ExpLegal     *model.CertifyLegal
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification 2",
					},
				},
			},
			ExpLegal: &model.CertifyLegal{
				Subject:          testdata.P1out,
				DeclaredLicenses: []*model.License{testdata.L1out},
				Justification:    "test justification 2",
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P2},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P2,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Subject: &model.PackageOrSourceSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpLegal: &model.CertifyLegal{
				Subject:          testdata.P2out,
				DeclaredLicenses: []*model.License{testdata.L1out},
				Justification:    "test justification",
			},
		},
		{
			Name:  "Query on Source",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				Subject: &model.PackageOrSourceSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("myrepo"),
					},
				},
			},
			ExpLegal: &model.CertifyLegal{
				Subject:          testdata.S1out,
				DeclaredLicenses: []*model.License{testdata.L1out},
				Justification:    "test justification",
			},
		},
		{
			Name:  "Query on License",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InLic: []*model.LicenseInputSpec{testdata.L1, testdata.L2},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1, testdata.L2},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				DeclaredLicenses: []*model.LicenseSpec{
					{Name: ptrfrom.String("GPL-2.0-or-later")},
				},
			},
			ExpLegal: &model.CertifyLegal{
				Subject:          testdata.S1out,
				DeclaredLicenses: []*model.License{testdata.L1out, testdata.L2out},
				Justification:    "test justification",
			},
		},
		{
			Name:  "Query on License inline",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InLic: []*model.LicenseInputSpec{testdata.L1, testdata.L4},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
					},
					Dec: []*model.LicenseInputSpec{testdata.L1, testdata.L4},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				DeclaredLicenses: []*model.LicenseSpec{
					{Inline: &testdata.InlineLicense},
				},
			},
			ExpLegal: &model.CertifyLegal{
				Subject:          testdata.S1out,
				DeclaredLicenses: []*model.License{testdata.L1out, testdata.L4out},
				Justification:    "test justification",
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := getBackend(ctx, arangArg)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InLic {
				if _, err := b.IngestLicense(ctx, a); err != nil {
					t.Fatalf("Could not ingest license: %v", err)
				}
			}
			for _, o := range test.Calls {
				cl, err := b.IngestCertifyLegal(ctx, o.PkgSrc, o.Dec, o.Dis, o.Legal)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.(*arangoClient).buildCertifyLegalByID(ctx, cl.ID, test.Query)
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpLegal, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}
