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
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var t2 = time.Unix(1e9, 0)
var t3 = time.Unix(1e9+5, 0)

var p1 = &model.PkgInputSpec{
	Type: "pypi",
	Name: "tensorflow",
}
var p1out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{{
				Version:    "",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var p2 = &model.PkgInputSpec{
	Type:    "pypi",
	Name:    "tensorflow",
	Version: ptrfrom.String("2.11.1"),
}
var p2out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{{
				Version:    "2.11.1",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var p3 = &model.PkgInputSpec{
	Type:    "pypi",
	Name:    "tensorflow",
	Version: ptrfrom.String("2.11.1"),
	Subpath: ptrfrom.String("saved_model_cli.py"),
}

// var pNone = &model.PkgInputSpec{
// 	Type: "none",
// 	Name: "none",
// }

var s1 = &model.SourceInputSpec{
	Type:      "git",
	Namespace: "github.com/jeff",
	Name:      "myrepo",
	Tag:       ptrfrom.String("v1.0"),
}
var s1out = &model.Source{
	Type: "git",
	Namespaces: []*model.SourceNamespace{{
		Namespace: "github.com/jeff",
		Names: []*model.SourceName{{
			Name:   "myrepo",
			Tag:    ptrfrom.String("v1.0"),
			Commit: ptrfrom.String(""),
		}},
	}},
}

var s2 = &model.SourceInputSpec{
	Type:      "git",
	Namespace: "github.com/bob",
	Name:      "bobsrepo",
	Commit:    ptrfrom.String("5e7c41f"),
}

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
			InPkg: []*model.PkgInputSpec{p1},
			InLic: []*model.LicenseInputSpec{l1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Dec: []*model.LicenseInputSpec{l1},
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
					Subject:          p1out,
					DeclaredLicenses: []*model.License{l1out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{p1},
			InLic: []*model.LicenseInputSpec{l1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Dec: []*model.LicenseInputSpec{l1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Dec: []*model.LicenseInputSpec{l1},
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
					Subject:          p1out,
					DeclaredLicenses: []*model.License{l1out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.PkgInputSpec{p1},
			InLic: []*model.LicenseInputSpec{l1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Dec: []*model.LicenseInputSpec{l1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Dec: []*model.LicenseInputSpec{l1},
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
					Subject:          p1out,
					DeclaredLicenses: []*model.License{l1out},
					Justification:    "test justification 2",
				},
			},
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{p1},
			InLic: []*model.LicenseInputSpec{l1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Dec: []*model.LicenseInputSpec{l1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Dec: []*model.LicenseInputSpec{l1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification 2",
					},
				},
			},
			IDInFilter: 2,
			Query:      &model.CertifyLegalSpec{},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          p1out,
					DeclaredLicenses: []*model.License{l1out},
					Justification:    "test justification 2",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{p1, p2},
			InLic: []*model.LicenseInputSpec{l1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Dec: []*model.LicenseInputSpec{l1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p2,
					},
					Dec: []*model.LicenseInputSpec{l1},
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
					Subject:          p2out,
					DeclaredLicenses: []*model.License{l1out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InSrc: []*model.SourceInputSpec{s1, s2},
			InLic: []*model.LicenseInputSpec{l1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: s1,
					},
					Dec: []*model.LicenseInputSpec{l1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: s2,
					},
					Dec: []*model.LicenseInputSpec{l1},
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
					Subject:          s1out,
					DeclaredLicenses: []*model.License{l1out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on License",
			InSrc: []*model.SourceInputSpec{s1},
			InLic: []*model.LicenseInputSpec{l1, l2, l3},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: s1,
					},
					Dec: []*model.LicenseInputSpec{l1, l2},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: s1,
					},
					Dec: []*model.LicenseInputSpec{l3},
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
					Subject:          s1out,
					DeclaredLicenses: []*model.License{l1out, l2out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on License inline",
			InSrc: []*model.SourceInputSpec{s1},
			InLic: []*model.LicenseInputSpec{l1, l2, l4},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: s1,
					},
					Dec: []*model.LicenseInputSpec{l1, l4},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: s1,
					},
					Dec: []*model.LicenseInputSpec{l2},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				DeclaredLicenses: []*model.LicenseSpec{
					{Inline: &inlineLicense},
				},
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:          s1out,
					DeclaredLicenses: []*model.License{l1out, l4out},
					Justification:    "test justification",
				},
			},
		},
		{
			Name:  "Query on expression",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Legal: &model.CertifyLegalInputSpec{
						DeclaredLicense: "GPL OR MIT",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
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
					Subject:         p1out,
					DeclaredLicense: "GPL AND MIT",
				},
			},
		},
		{
			Name:  "Query on attribution",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Legal: &model.CertifyLegalInputSpec{
						Attribution: "Copyright Jeff",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
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
					Subject:     p1out,
					Attribution: "Copyright Jeff",
				},
			},
		},
		{
			Name:  "Query on time",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Legal: &model.CertifyLegalInputSpec{
						TimeScanned: t3,
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Legal: &model.CertifyLegalInputSpec{
						TimeScanned: t2,
					},
				},
			},
			Query: &model.CertifyLegalSpec{
				TimeScanned: &t2,
			},
			ExpLegal: []*model.CertifyLegal{
				{
					Subject:     p1out,
					TimeScanned: t2,
				},
			},
		},
		{
			Name:  "Query multiple",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			InLic: []*model.LicenseInputSpec{l1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Dec: []*model.LicenseInputSpec{l1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification special",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p2,
					},
					Dec: []*model.LicenseInputSpec{l1},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification special",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: p3,
					},
					Dec: []*model.LicenseInputSpec{l1},
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
					Subject:          p1out,
					DeclaredLicenses: []*model.License{l1out},
					Justification:    "test justification special",
				},
				{
					Subject:          p2out,
					DeclaredLicenses: []*model.License{l1out},
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
		// 	InPkg: []*model.PkgInputSpec{p1},
		// 	Calls: []call{
		// 		{
		// 			PkgSrc: model.PackageOrSourceInput{
		// 				Package: p1,
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
			InPkg: []*model.PkgInputSpec{p1, p2},
			InLic: []*model.LicenseInputSpec{l1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInputs{
						Packages: []*model.PkgInputSpec{p1, p2},
					},
					Dec: [][]*model.LicenseInputSpec{{l1}, {l1}},
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
					Subject:          p1out,
					DeclaredLicenses: []*model.License{l1out},
					Justification:    "test justification",
				},
				{
					Subject:          p2out,
					DeclaredLicenses: []*model.License{l1out},
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
