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

package backend

import (
	"strconv"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var (
	mAll      = model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}
	mSpecific = model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
)

func (s *Suite) TestIsDependency() {
	type call struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		MF model.MatchFlags
		ID *model.IsDependencyInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		Calls        []call
		Query        *model.IsDependencySpec
		ExpID        []*model.IsDependency
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Ingest same",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Ingest same, different version",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p1,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification one",
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Query on pkg",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					ID: ptrfrom.String("0"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p2outName,
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Query on dep pkg",
			InPkg: []*model.PkgInputSpec{p1, p2, p4},
			Calls: []call{
				{
					P1: p2,
					P2: p4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					Name: ptrfrom.String("openssl"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p2out,
					DependencyPackage: p4outName,
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Query on pkg multiple",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p3,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Type: ptrfrom.String("pypi"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p1outName,
					DependencyType:    model.DependencyTypeUnknown,
				},
				{
					Package:           p3out,
					DependencyPackage: p1outName,
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Query on both pkgs",
			InPkg: []*model.PkgInputSpec{p1, p2, p3, p4},
			Calls: []call{
				{
					P1: p2,
					P2: p1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p3,
					P2: p4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
				DependencyPackage: &model.PkgSpec{
					Name: ptrfrom.String("openssl"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p3out,
					DependencyPackage: p4outName,
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Query none",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Subpath: ptrfrom.String("asdf"),
				},
			},
			ExpID: nil,
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				ID: ptrfrom.String("1"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p2out,
					DependencyPackage: p1outName,
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Query on Range",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						VersionRange: "1-3",
					},
				},
				{
					P1: p2,
					P2: p1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						VersionRange: "4-5",
					},
				},
			},
			Query: &model.IsDependencySpec{
				VersionRange: ptrfrom.String("1-3"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p1outName,
					VersionRange:      "1-3",
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Query on DependencyType",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeDirect,
					},
				},
				{
					P1: p2,
					P2: p1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeIndirect,
					},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyType: (*model.DependencyType)(ptrfrom.String(string(model.DependencyTypeIndirect))),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p2out,
					DependencyPackage: p1outName,
					DependencyType:    model.DependencyTypeIndirect,
				},
			},
		},
		{
			Name:  "Ingest no P1",
			InPkg: []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no P2",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					P1: p1,
					P2: p4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
		{
			Name:  "IsDep from version to version",
			InPkg: []*model.PkgInputSpec{p2, p3},
			Calls: []call{
				{
					P1: p3,
					P2: p2,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p3out,
					DependencyPackage: p2out,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "IsDep from version to name",
			InPkg: []*model.PkgInputSpec{p2, p3},
			Calls: []call{
				{
					P1: p3,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p3out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "IsDep from version to name and version",
			InPkg: []*model.PkgInputSpec{p2, p3},
			Calls: []call{
				{
					P1: p3,
					P2: p2,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p3,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p3out,
					DependencyPackage: p2out,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
				},
				{
					Package:           p3out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "Ingest DependencyPackage with version and query without version",
			InPkg: []*model.PkgInputSpec{p2, p4},
			Calls: []call{
				{
					P1: p2,
					P2: p4,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
						VersionRange:  "v3.0.3",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Type: ptrfrom.String("pypi"),
					Name: ptrfrom.String("tensorflow"),
				},
				DependencyPackage: &model.PkgSpec{
					Type:      ptrfrom.String("conan"),
					Namespace: ptrfrom.String("openssl.org"),
					Name:      ptrfrom.String("openssl"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p2out,
					DependencyPackage: p4out,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
					VersionRange:      "v3.0.3",
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			b, err := GetBackend(s.Client)
			s.Require().NoError(err, "Could not instantiate testing backend")

			pksIDs := make([]string, len(test.InPkg))
			for i, a := range test.InPkg {
				if p, err := b.IngestPackage(ctx, *a); err != nil {
					s.Require().NoError(err, "Could not ingest pkg")
				} else {
					pksIDs[i] = p.Namespaces[0].Names[0].Versions[0].ID
				}
			}

			depIDs := make([]string, len(test.Calls))
			for i, o := range test.Calls {

				dep, err := b.IngestDependency(ctx, *o.P1, *o.P2, o.MF, *o.ID)
				if (err != nil) != test.ExpIngestErr {
					s.T().Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				depIDs[i] = dep.ID
			}

			if test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx < 0 || idIdx >= len(depIDs) {
						s.T().Logf("ID index out of range, want: %d, got: %d. So ID %d will be directly used to query.", len(depIDs), idIdx, idIdx)
					} else {
						test.Query.ID = &depIDs[idIdx]
					}
				}
			}

			if test.Query.Package != nil && test.Query.Package.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.Package.ID)
				if err == nil {
					if idIdx < 0 || idIdx >= len(pksIDs) {
						s.T().Logf("ID index out of range, want: %d, got: %d. So ID %d will be directly used to query.", len(pksIDs), idIdx, idIdx)
					} else {
						test.Query.Package.ID = &pksIDs[idIdx]
					}
				}
			}

			got, err := b.IsDependency(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				s.T().Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(test.ExpID, got, ignoreID, ignoreEmptySlices); diff != "" {
				s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestIngestDependencies() {
	type call struct {
		P1s []*model.PkgInputSpec
		P2s []*model.PkgInputSpec
		MF  model.MatchFlags
		IDs []*model.IsDependencyInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		Calls        []call
		Query        *model.IsDependencySpec
		ExpID        []*model.IsDependency
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1, p2, p3, p4},
			Calls: []call{{
				P1s: []*model.PkgInputSpec{p1, p2},
				P2s: []*model.PkgInputSpec{p2, p4},
				MF:  mAll,
				IDs: []*model.IsDependencyInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification",
					},
				},
			}},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
				},
				{
					Package:           p2out,
					DependencyPackage: p4outName,
					Justification:     "test justification",
					DependencyType:    model.DependencyTypeUnknown,
				},
			},
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			b, err := GetBackend(s.Client)
			s.Require().NoError(err, "Could not instantiate testing backend")
			t := s.T()
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, a := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *a); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestDependencies(ctx, o.P1s, o.P2s, o.MF, o.IDs)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}

			got, err := b.IsDependency(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpID, got, IngestPredicatesCmpOpts...); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
