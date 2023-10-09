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
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestHasSourceAt(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	testTime := time.Unix(1e9+5, 0)
	type call struct {
		Pkg   *model.PkgInputSpec
		Src   *model.SourceInputSpec
		Match *model.MatchFlags
		HSA   *model.HasSourceAtInputSpec
	}
	tests := []struct {
		Name          string
		InPkg         []*model.PkgInputSpec
		InSrc         []*model.SourceInputSpec
		Calls         []call
		Query         *model.HasSourceAtSpec
		QueryID       bool
		QueryPkgID    bool
		QuerySourceID bool
		ExpHSA        []*model.HasSourceAt
		ExpIngestErr  bool
		ExpQueryErr   bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P1out,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Versions",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P1out,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
				{
					Package:       testdata.P1outName,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest Same Twice",
			InPkg: []*model.PkgInputSpec{testdata.P3},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P3,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
				{
					Pkg: testdata.P3,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Package: &model.PkgSpec{
					Version: ptrfrom.String("2.11.1"),
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P3out,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
				{
					Package:       testdata.P1outName,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query On Justification",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification two"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P1out,
					Source:        testdata.S1out,
					Justification: "test justification two",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P4},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: testdata.P4,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				Package: &model.PkgSpec{
					Type:      ptrfrom.String("conan"),
					Namespace: ptrfrom.String("openssl.org"),
					Name:      ptrfrom.String("openssl"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package: testdata.P4out,
					Source:  testdata.S1out,
				},
			},
		},
		{
			Name:  "Query on Package version ID",
			InPkg: []*model.PkgInputSpec{testdata.P4},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P4,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			QueryPkgID: true,
			ExpHSA: []*model.HasSourceAt{
				{
					Package: testdata.P4out,
					Source:  testdata.S1out,
				},
			},
		},
		{
			Name:  "Query on Source - tag",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S3},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: testdata.P1,
					Src: testdata.S3,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				Source: &model.SourceSpec{
					Type:      ptrfrom.String("git"),
					Namespace: ptrfrom.String("github.com/jeff"),
					Name:      ptrfrom.String("myrepo"),
					Tag:       ptrfrom.String("v1.0"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package: testdata.P1out,
					Source:  testdata.S3out,
				},
			},
		},
		{
			Name:  "Query on Source - commit",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S4, testdata.S3},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S4,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: testdata.P1,
					Src: testdata.S3,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				Source: &model.SourceSpec{
					Type:      ptrfrom.String("svn"),
					Namespace: ptrfrom.String("github.com/bob"),
					Name:      ptrfrom.String("bobsrepo"),
					Commit:    ptrfrom.String("5e7c41f"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package: testdata.P1out,
					Source:  testdata.S4out,
				},
			},
		},
		{
			Name:  "Query on Source ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S2},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S2,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			QuerySourceID: true,
			ExpHSA: []*model.HasSourceAt{
				{
					Package: testdata.P1out,
					Source:  testdata.S2out,
				},
			},
		},
		{
			Name:  "Query on KnownSince",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						KnownSince: time.Unix(1e9, 0),
					},
				},
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						KnownSince: testTime,
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				KnownSince: &testTime,
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:    testdata.P1out,
					Source:     testdata.S1out,
					KnownSince: testTime,
				},
			},
		},
		{
			Name:  "Query Multiple",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification two",
					},
				},
				{
					Pkg: testdata.P2,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification two"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P1out,
					Source:        testdata.S1out,
					Justification: "test justification two",
				},
				{
					Package:       testdata.P2out,
					Source:        testdata.S1out,
					Justification: "test justification two",
				},
			},
		},
		{
			Name:  "Query None",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification three"),
			},
			ExpHSA: nil,
		},
		{
			Name:  "Query ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: testdata.P2,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			QueryID: true,
			ExpHSA: []*model.HasSourceAt{
				{
					Package: testdata.P2out,
					Source:  testdata.S1out,
				},
			},
		},
		{
			Name:  "Query Name and Version",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P4},
			InSrc: []*model.SourceInputSpec{testdata.S4},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: testdata.P4,
					Src: testdata.S4,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				Package: &model.PkgSpec{
					Type:      ptrfrom.String("conan"),
					Namespace: ptrfrom.String("openssl.org"),
					Name:      ptrfrom.String("openssl"),
				},
				Source: &model.SourceSpec{
					Type:      ptrfrom.String("svn"),
					Namespace: ptrfrom.String("github.com/bob"),
					Name:      ptrfrom.String("bobsrepo"),
					Commit:    ptrfrom.String("5e7c41f"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package: testdata.P4out,
					Source:  testdata.S4out,
				},
			},
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
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
			for _, o := range test.Calls {
				found, err := b.IngestHasSourceAt(ctx, *o.Pkg, *o.Match, *o.Src, *o.HSA)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.HasSourceAtSpec{
						ID: ptrfrom.String(found.ID),
					}
				}
				if test.QueryPkgID {
					test.Query = &model.HasSourceAtSpec{
						Package: &model.PkgSpec{
							ID: ptrfrom.String(found.Package.Namespaces[0].Names[0].Versions[0].ID),
						},
					}

				}
				if test.QuerySourceID {
					test.Query = &model.HasSourceAtSpec{
						Source: &model.SourceSpec{
							ID: ptrfrom.String(found.Source.Namespaces[0].Names[0].ID),
						},
					}
				}
			}
			got, err := b.HasSourceAt(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHSA, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestHasSourceAts(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	testTime := time.Unix(1e9+5, 0)
	type call struct {
		Pkgs  []*model.PkgInputSpec
		Srcs  []*model.SourceInputSpec
		Match *model.MatchFlags
		HSAs  []*model.HasSourceAtInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		Calls        []call
		Query        *model.HasSourceAtSpec
		ExpHSA       []*model.HasSourceAt
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{testdata.P1},
					Srcs: []*model.SourceInputSpec{testdata.S1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P1out,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Versions",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{testdata.P1},
					Srcs: []*model.SourceInputSpec{testdata.S1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P1out,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
				{
					Package:       testdata.P1outName,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest Same Twice",
			InPkg: []*model.PkgInputSpec{testdata.P3},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{testdata.P3, testdata.P1},
					Srcs: []*model.SourceInputSpec{testdata.S1, testdata.S1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Package: &model.PkgSpec{
					Version: ptrfrom.String("2.11.1"),
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P3out,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
				{
					Package:       testdata.P1outName,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P4},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{testdata.P1, testdata.P4},
					Srcs: []*model.SourceInputSpec{testdata.S1, testdata.S1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Package: &model.PkgSpec{
					Type:      ptrfrom.String("conan"),
					Namespace: ptrfrom.String("openssl.org"),
					Name:      ptrfrom.String("openssl"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P4out,
					Source:        testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S3},
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					Srcs: []*model.SourceInputSpec{testdata.S1, testdata.S3},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Source: &model.SourceSpec{
					Type:      ptrfrom.String("git"),
					Namespace: ptrfrom.String("github.com/jeff"),
					Name:      ptrfrom.String("myrepo"),
					Tag:       ptrfrom.String("v1.0"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       testdata.P1out,
					Source:        testdata.S3out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on KnownSince",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					Srcs: []*model.SourceInputSpec{testdata.S1, testdata.S1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							KnownSince: time.Unix(1e9, 0),
						},
						{
							KnownSince: testTime,
						},
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				KnownSince: &testTime,
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:    testdata.P1out,
					Source:     testdata.S1out,
					KnownSince: testTime,
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
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
			for _, o := range test.Calls {
				_, err := b.IngestHasSourceAts(ctx, o.Pkgs, o.Match, o.Srcs, o.HSAs)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.HasSourceAt(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHSA, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildHasSourceAtByID(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Pkg   *model.PkgInputSpec
		Src   *model.SourceInputSpec
		Match *model.MatchFlags
		HSA   *model.HasSourceAtInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		Calls        []call
		Query        *model.HasSourceAtSpec
		ExpHSA       *model.HasSourceAt
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P4},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P4,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				Package: &model.PkgSpec{
					Type:      ptrfrom.String("conan"),
					Namespace: ptrfrom.String("openssl.org"),
					Name:      ptrfrom.String("openssl"),
				},
			},
			ExpHSA: &model.HasSourceAt{
				Package: testdata.P4out,
				Source:  testdata.S1out,
			},
		},
		{
			Name:  "Query on Package version ID",
			InPkg: []*model.PkgInputSpec{testdata.P4},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P4,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			ExpHSA: &model.HasSourceAt{
				Package: testdata.P4out,
				Source:  testdata.S1out,
			},
		},
		{
			Name:  "Query on Source - tag",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S3},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S3,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				Source: &model.SourceSpec{
					Type:      ptrfrom.String("git"),
					Namespace: ptrfrom.String("github.com/jeff"),
					Name:      ptrfrom.String("myrepo"),
					Tag:       ptrfrom.String("v1.0"),
				},
			},
			ExpHSA: &model.HasSourceAt{
				Package: testdata.P1out,
				Source:  testdata.S3out,
			},
		},
		{
			Name:  "Query on Source ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S2},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S2,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			ExpHSA: &model.HasSourceAt{
				Package: testdata.P1out,
				Source:  testdata.S2out,
			},
		},
		{
			Name:  "Query ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P2,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			ExpHSA: &model.HasSourceAt{
				Package: testdata.P2out,
				Source:  testdata.S1out,
			},
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Pkg: testdata.P1,
					Src: testdata.S1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
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
			for _, o := range test.Calls {
				found, err := b.IngestHasSourceAt(ctx, *o.Pkg, *o.Match, *o.Src, *o.HSA)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.(*arangoClient).buildHasSourceAtByID(ctx, found.ID, test.Query)
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpHSA, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TODO (pxp928): add tests back in when implemented

// func TestHasSourceAtNeighbors(t *testing.T) {
// 	type call struct {
// 		Pkg   *model.PkgInputSpec
// 		Src   *model.SourceInputSpec
// 		Match *model.MatchFlags
// 		HSA   *model.HasSourceAtInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InPkg        []*model.PkgInputSpec
// 		InSrc        []*model.SourceInputSpec
// 		Calls        []call
// 		ExpNeighbors map[string][]string
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			InSrc: []*model.SourceInputSpec{testdata.S1},
// 			Calls: []call{
// 				{
// 					Pkg: testdata.P1,
// 					Src: testdata.S1,
// 					Match: &model.MatchFlags{
// 						Pkg: model.PkgMatchTypeSpecificVersion,
// 					},
// 					HSA: &model.HasSourceAtInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"4": []string{"1", "8"}, // Package Version
// 				"7": []string{"5", "8"}, // Source Name
// 				"8": []string{"1", "5"}, // HSA
// 			},
// 		},
// 		{
// 			Name:  "Package Name and Version",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			InSrc: []*model.SourceInputSpec{testdata.S1},
// 			Calls: []call{
// 				{
// 					Pkg: testdata.P1,
// 					Src: testdata.S1,
// 					Match: &model.MatchFlags{
// 						Pkg: model.PkgMatchTypeSpecificVersion,
// 					},
// 					HSA: &model.HasSourceAtInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 				{
// 					Pkg: testdata.P1,
// 					Src: testdata.S1,
// 					Match: &model.MatchFlags{
// 						Pkg: model.PkgMatchTypeAllVersions,
// 					},
// 					HSA: &model.HasSourceAtInputSpec{},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"3": []string{"1", "1", "9"}, // Package Name
// 				"4": []string{"1", "8"},      // Package Version
// 				"7": []string{"5", "8", "9"}, // Source Name
// 				"8": []string{"1", "5"},      // HSA -> Version
// 				"9": []string{"1", "5"},      // HSA -> Name
// 			},
// 		},
// 	}
// 	ctx := context.Background()
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			b, err := backends.Get("inmem", nil, nil)
// 			if err != nil {
// 				t.Fatalf("Could not instantiate testing backend: %v", err)
// 			}
// 			for _, p := range test.InPkg {
// 				if _, err := b.IngestPackage(ctx, *p); err != nil {
// 					t.Fatalf("Could not ingest package: %v", err)
// 				}
// 			}
// 			for _, s := range test.InSrc {
// 				if _, err := b.IngestSource(ctx, *s); err != nil {
// 					t.Fatalf("Could not ingest source: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				if _, err := b.IngestHasSourceAt(ctx, *o.Pkg, *o.Match, *o.Src, *o.HSA); err != nil {
// 					t.Fatalf("Could not ingest HasSourceAt: %v", err)
// 				}
// 			}
// 			for q, r := range test.ExpNeighbors {
// 				got, err := b.Neighbors(ctx, q, nil)
// 				if err != nil {
// 					t.Fatalf("Could not query neighbors: %s", err)
// 				}
// 				gotIDs := convNodes(got)
// 				slices.Sort(r)
// 				slices.Sort(gotIDs)
// 				if diff := cmp.Diff(r, gotIDs); diff != "" {
// 					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 				}
// 			}
// 		})
// 	}
// }
