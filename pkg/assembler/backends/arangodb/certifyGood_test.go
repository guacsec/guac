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

func TestCertifyGood(t *testing.T) {
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
	curTime := time.Now()
	timeAfterOneSecond := curTime.Add(time.Second)
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		CG    *model.CertifyGoodInputSpec
	}
	tests := []struct {
		Name          string
		InPkg         []*model.PkgInputSpec
		InSrc         []*model.SourceInputSpec
		InArt         []*model.ArtifactInputSpec
		Calls         []call
		Query         *model.CertifyGoodSpec
		QueryID       bool
		QueryPkgID    bool
		QuerySourceID bool
		QueryArtID    bool
		ExpCG         []*model.CertifyGood
		ExpIngestErr  bool
		ExpQueryErr   bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P1out,
					Justification: "test justification one",
				},
			},
		},
		{
			Name:  "Query on KnownSince",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification one",
						KnownSince:    curTime,
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification two",
						KnownSince:    timeAfterOneSecond,
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Justification: ptrfrom.String("test justification one"),
				KnownSince:    ptrfrom.Time(curTime),
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P1out,
					Justification: "test justification one",
					KnownSince:    curTime,
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P2outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package version ID",
			InPkg: []*model.PkgInputSpec{testdata.P4},
			InSrc: []*model.SourceInputSpec{},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryPkgID: true,
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source ID",
			InPkg: []*model.PkgInputSpec{},
			InSrc: []*model.SourceInputSpec{testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			QuerySourceID: true,
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A1,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact ID",
			InSrc: []*model.SourceInputSpec{},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A1,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryArtID: true,
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query none",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A1,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("asdf"),
					},
				},
			},
			ExpCG: nil,
		},
		{
			Name:  "Query multiple",
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Type: ptrfrom.String("git"),
					},
				},
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query Packages",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Type:    ptrfrom.String("pypi"),
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P2outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query ID",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A1,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryID: true,
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query bad ID",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					CG: &model.CertifyGoodInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyGoodSpec{
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
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				found, err := b.IngestCertifyGood(ctx, o.Sub, o.Match, *o.CG)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.CertifyGoodSpec{
						ID: ptrfrom.String(found.ID),
					}
				}
				if test.QueryPkgID {
					if _, ok := found.Subject.(*model.Package); ok {
						test.Query = &model.CertifyGoodSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Package: &model.PkgSpec{
									ID: ptrfrom.String(found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID),
								},
							},
						}
					}
				}
				if test.QuerySourceID {
					if _, ok := found.Subject.(*model.Source); ok {
						test.Query = &model.CertifyGoodSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Source: &model.SourceSpec{
									ID: ptrfrom.String(found.Subject.(*model.Source).Namespaces[0].Names[0].ID),
								},
							},
						}
					}
				}
				if test.QueryArtID {
					if _, ok := found.Subject.(*model.Artifact); ok {
						test.Query = &model.CertifyGoodSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Artifact: &model.ArtifactSpec{
									ID: ptrfrom.String(found.Subject.(*model.Artifact).ID),
								},
							},
						}
					}
				}
			}
			got, err := b.CertifyGood(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpCG, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestCertifyGoods(t *testing.T) {
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
		Sub   model.PackageSourceOrArtifactInputs
		Match *model.MatchFlags
		CG    []*model.CertifyGoodInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.CertifyGoodSpec
		ExpCG        []*model.CertifyGood
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S1},
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.P2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P2outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S2, testdata.S2},
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S1},
					},
					CG: []*model.CertifyGoodInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpCG: []*model.CertifyGood{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
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
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestCertifyGoods(ctx, o.Sub, o.Match, o.CG)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.CertifyGood(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpCG, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildCertifyGoodByID(t *testing.T) {
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
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		CG    *model.CertifyGoodInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Call         call
		Query        *model.CertifyGoodSpec
		ExpCG        *model.CertifyGood
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Call: call{
				Sub: model.PackageSourceOrArtifactInput{
					Package: testdata.P1,
				},
				Match: &model.MatchFlags{
					Pkg: model.PkgMatchTypeSpecificVersion,
				},
				CG: &model.CertifyGoodInputSpec{
					Justification: "test justification",
				},
			},

			Query: &model.CertifyGoodSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCG: &model.CertifyGood{
				Subject:       testdata.P1out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P4},
			Call: call{
				Sub: model.PackageSourceOrArtifactInput{
					Package: testdata.P4,
				},
				Match: &model.MatchFlags{
					Pkg: model.PkgMatchTypeSpecificVersion,
				},
				CG: &model.CertifyGoodInputSpec{
					Justification: "test justification",
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Type:      ptrfrom.String("conan"),
						Namespace: ptrfrom.String("openssl.org"),
						Name:      ptrfrom.String("openssl"),
						Version:   ptrfrom.String("3.0.3"),
					},
				},
			},
			ExpCG: &model.CertifyGood{
				Subject:       testdata.P4out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Source",
			InSrc: []*model.SourceInputSpec{testdata.S2},
			Call: call{
				Sub: model.PackageSourceOrArtifactInput{
					Source: testdata.S2,
				},
				CG: &model.CertifyGoodInputSpec{
					Justification: "test justification",
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpCG: &model.CertifyGood{
				Subject:       testdata.S2out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Artifact",
			InArt: []*model.ArtifactInputSpec{testdata.A2},
			Call: call{
				Sub: model.PackageSourceOrArtifactInput{
					Artifact: testdata.A2,
				},
				CG: &model.CertifyGoodInputSpec{
					Justification: "test justification",
				},
			},
			Query: &model.CertifyGoodSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpCG: &model.CertifyGood{
				Subject:       testdata.A2out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Source - no filter",
			InSrc: []*model.SourceInputSpec{testdata.S3},
			Call: call{
				Sub: model.PackageSourceOrArtifactInput{
					Source: testdata.S3,
				},
				CG: &model.CertifyGoodInputSpec{
					Justification: "test justification",
				},
			},
			Query: &model.CertifyGoodSpec{},
			ExpCG: &model.CertifyGood{
				Subject:       testdata.S3out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query on Artifact - no filter",
			InArt: []*model.ArtifactInputSpec{testdata.A3},
			Call: call{
				Sub: model.PackageSourceOrArtifactInput{
					Artifact: testdata.A3,
				},
				CG: &model.CertifyGoodInputSpec{
					Justification: "test justification",
				},
			},
			Query: &model.CertifyGoodSpec{},
			ExpCG: &model.CertifyGood{
				Subject:       testdata.A3out,
				Justification: "test justification",
			},
		},
		{
			Name:  "Query bad ID",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Call: call{
				Sub: model.PackageSourceOrArtifactInput{
					Source: testdata.S1,
				},
				CG: &model.CertifyGoodInputSpec{
					Justification: "test justification",
				},
			},
			Query: &model.CertifyGoodSpec{
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
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			found, err := b.IngestCertifyGood(ctx, test.Call.Sub, test.Call.Match, *test.Call.CG)
			if (err != nil) != test.ExpIngestErr {
				t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
			}
			if err != nil {
				return
			}

			got, err := b.(*arangoClient).buildCertifyGoodByID(ctx, found.ID, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpCG, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

// TODO (pxp928): add tests back in when implemented

// func TestCertifyGoodNeighbors(t *testing.T) {
// 	type call struct {
// 		Sub   model.PackageSourceOrArtifactInput
// 		Match *model.MatchFlags
// 		CG    *model.CertifyGoodInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InPkg        []*model.PkgInputSpec
// 		InSrc        []*model.SourceInputSpec
// 		InArt        []*model.ArtifactInputSpec
// 		Calls        []call
// 		ExpNeighbors map[string][]string
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageSourceOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					Match: &model.MatchFlags{
// 						Pkg: model.PkgMatchTypeSpecificVersion,
// 					},
// 					CG: &model.CertifyGoodInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"4": []string{"1", "5"}, // pkg version
// 				"5": []string{"1"},      // certify good
// 			},
// 		},
// 		{
// 			Name:  "Pkg Name Src and Artifact",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			InSrc: []*model.SourceInputSpec{testdata.S1},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageSourceOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					Match: &model.MatchFlags{
// 						Pkg: model.PkgMatchTypeAllVersions,
// 					},
// 					CG: &model.CertifyGoodInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 				{
// 					Sub: model.PackageSourceOrArtifactInput{
// 						Source: testdata.S1,
// 					},
// 					CG: &model.CertifyGoodInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 				{
// 					Sub: model.PackageSourceOrArtifactInput{
// 						Artifact: testdata.A1,
// 					},
// 					CG: &model.CertifyGoodInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"1":  []string{"1"},
// 				"2":  []string{"1", "1"},
// 				"3":  []string{"1", "1", "9"}, // pkg name
// 				"4":  []string{"1"},           // pkg version
// 				"5":  []string{"5"},
// 				"6":  []string{"5", "5"},
// 				"7":  []string{"5", "10"}, // src name
// 				"8":  []string{"11"},      // art
// 				"9":  []string{"1"},       // cb 1 -> pkg name
// 				"10": []string{"5"},       // cb 2 -> src name
// 				"11": []string{"8"},       // cb 3 -> art
// 			},
// 		},
// 	}
// 	ctx := context.Background()
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			b, err := inmem.getBackend(nil)
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
// 			for _, a := range test.InArt {
// 				if _, err := b.IngestArtifact(ctx, a); err != nil {
// 					t.Fatalf("Could not ingest artifact: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				if _, err := b.IngestCertifyGood(ctx, o.Sub, o.Match, *o.CG); err != nil {
// 					t.Fatalf("Could not ingest CertifyGood: %v", err)
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
