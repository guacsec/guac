package backend

import (
	"strconv"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestIsDependency() {
	type call struct {
		P1    *model.PkgInputSpec
		P2    *model.PkgInputSpec
		Input *model.IsDependencyInputSpec
	}
	tests := []struct {
		Name              string
		IngestPkg         []*model.PkgInputSpec
		Calls             []call
		Query             *model.IsDependencySpec
		ExpectedDep       []*model.IsDependency
		ExpectedIngestErr bool
		ExpectedQueryErr  bool
		Only              bool
	}{
		{
			Name:      "HappyPath",
			IngestPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					Input: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p2outName,
					Justification:    "test justification",
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:      "Ingest same",
			IngestPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					Input: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p1,
					P2: p2,
					Input: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p2outName,
					Justification:    "test justification",
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:      "Ingest same, different version",
			IngestPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					Input: &model.IsDependencyInputSpec{
						Justification:  "test justification",
						DependencyType: model.DependencyTypeDirect,
					},
				},
				{
					P1: p1,
					P2: p3,
					Input: &model.IsDependencyInputSpec{
						Justification:  "test justification",
						DependencyType: model.DependencyTypeDirect,
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p2outName,
					Justification:    "test justification",
					DependencyType:   model.DependencyTypeDirect,
				},
			},
		},
		{
			Name:      "Query on Justification",
			IngestPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					Input: &model.IsDependencyInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: p1,
					P2: p2,
					Input: &model.IsDependencyInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p2outName,
					Justification:    "test justification one",
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:      "Query on pkg",
			IngestPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1:    p1,
					P2:    p2,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p2,
					P2:    p3,
					Input: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					ID: ptrfrom.String("0"), // index of p1
				},
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p2outName,
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:      "Query on dep pkg",
			IngestPkg: []*model.PkgInputSpec{p1, p2, p4},
			Calls: []call{
				{
					P1:    p2,
					P2:    p4,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p2,
					P2:    p1,
					Input: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependentPackage: &model.PkgNameSpec{
					Name: ptrfrom.String("openssl"),
				},
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p2out,
					DependentPackage: p4outName,
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:      "Query on pkg multiple",
			IngestPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1:    p1,
					P2:    p2,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p3,
					P2:    p2,
					Input: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Type: ptrfrom.String("pypi"),
				},
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p1outName,
					DependencyType:   model.DependencyTypeUnknown,
				},
				{
					Package:          p3out,
					DependentPackage: p1outName,
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:      "Query on both pkgs",
			IngestPkg: []*model.PkgInputSpec{p1, p2, p3, p4},
			Calls: []call{
				{
					P1:    p2,
					P2:    p1,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p3,
					P2:    p4,
					Input: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
				DependentPackage: &model.PkgNameSpec{
					Name: ptrfrom.String("openssl"),
				},
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p3out,
					DependentPackage: p4outName,
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:      "Query none",
			IngestPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1:    p1,
					P2:    p2,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p2,
					P2:    p3,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p1,
					P2:    p3,
					Input: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Subpath: ptrfrom.String("asdf"),
				},
			},
			ExpectedDep: nil,
		},
		{
			Name:      "Query on ID",
			IngestPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1:    p1,
					P2:    p2,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p2,
					P2:    p3,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p1,
					P2:    p3,
					Input: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				ID: ptrfrom.String("1"), // ID's are replaced with real IDs later on, this is the index in the array of calls
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p2out,
					DependentPackage: p1outName,
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:      "Query on Range",
			IngestPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p1,
					Input: &model.IsDependencyInputSpec{
						VersionRange: "1-3",
					},
				},
				{
					P1: p2,
					P2: p1,
					Input: &model.IsDependencyInputSpec{
						VersionRange: "4-5",
					},
				},
			},
			Query: &model.IsDependencySpec{
				VersionRange: ptrfrom.String("1-3"),
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p1outName,
					VersionRange:     "1-3",
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:      "Query on DependencyType",
			IngestPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p1,
					Input: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeDirect,
					},
				},
				{
					P1: p2,
					P2: p1,
					Input: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeIndirect,
					},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyType: (*model.DependencyType)(ptrfrom.String(string(model.DependencyTypeIndirect))),
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p2out,
					DependentPackage: p1outName,
					DependencyType:   model.DependencyTypeIndirect,
				},
			},
		},
		{
			Name:      "Ingest no P1",
			IngestPkg: []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					P1:    p1,
					P2:    p2,
					Input: &model.IsDependencyInputSpec{},
				},
			},
			ExpectedIngestErr: true,
		},
		{
			Name:      "Ingest no P2",
			IngestPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					P1:    p1,
					P2:    p4,
					Input: &model.IsDependencyInputSpec{},
				},
			},
			ExpectedIngestErr: true,
		},
		{
			Name:      "Query bad ID",
			IngestPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1:    p1,
					P2:    p2,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p2,
					P2:    p3,
					Input: &model.IsDependencyInputSpec{},
				},
				{
					P1:    p1,
					P2:    p3,
					Input: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpectedQueryErr: true,
		},
	}

	hasOnly := false
	for _, t := range tests {
		if t.Only {
			hasOnly = true
			break
		}
	}

	ctx := s.Ctx
	for _, test := range tests {
		if hasOnly && !test.Only {
			continue
		}

		s.Run(test.Name, func() {
			b, err := GetBackend(s.Client)
			s.Require().NoError(err, "Could not instantiate testing backend")

			for _, a := range test.IngestPkg {
				if _, err := b.IngestPackage(ctx, *a); err != nil {
					s.Require().NoError(err, "Could not ingest pkg")
				}
			}

			depIDs := make([]string, len(test.Calls))
			pksIDs := make([]string, 0)
			for i, o := range test.Calls {

				dep, err := b.IngestDependency(ctx, *o.P1, *o.P2, *o.Input)
				if (err != nil) != test.ExpectedIngestErr {
					s.T().Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpectedIngestErr, err)
				}
				if err != nil {
					return
				}
				depIDs[i] = dep.ID
				if dep.Package != nil && len(dep.Package.Namespaces) == 1 && len(dep.Package.Namespaces[0].Names) == 1 && len(dep.Package.Namespaces[0].Names[0].Versions) == 1 {
					pksIDs = append(pksIDs, dep.Package.Namespaces[0].Names[0].Versions[0].ID)
				}
			}

			if test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx >= len(depIDs) {
						s.T().Fatalf("ID index out of range, want: %d, got: %d", len(depIDs), idIdx)
					}

					realID := depIDs[idIdx]
					test.Query.ID = &realID
				}
			}

			if test.Query.Package != nil && test.Query.Package.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.Package.ID)
				if err == nil {
					if idIdx >= len(pksIDs) {
						s.T().Fatalf("ID index out of range, want: %d, got: %d", len(pksIDs), idIdx)
					}

					realID := pksIDs[idIdx]
					test.Query.Package.ID = &realID
				}
			}

			got, err := b.IsDependency(ctx, test.Query)
			if (err != nil) != test.ExpectedQueryErr {
				s.T().Fatalf("did not get expected query error, want: %v, got: %v", test.ExpectedQueryErr, err)
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(test.ExpectedDep, got, ignoreID, ignoreEmptySlices); diff != "" {
				s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestIngestDependencies() {
	type call struct {
		P1s []*model.PkgInputSpec
		P2s []*model.PkgInputSpec
		IDs []*model.IsDependencyInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		Calls        []call
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
				IDs: []*model.IsDependencyInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification",
					},
				},
			}},
			ExpID: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p2outName,
					Justification:    "test justification",
					DependencyType:   model.DependencyTypeUnknown,
				},
				{
					Package:          p2out,
					DependentPackage: p4outName,
					Justification:    "test justification",
					DependencyType:   model.DependencyTypeUnknown,
				},
			},
		},
		{
			Name:  "With uneven pkgs input",
			InPkg: []*model.PkgInputSpec{p1, p2, p3, p4},
			Calls: []call{{
				P1s: []*model.PkgInputSpec{p1, p2},
				P2s: []*model.PkgInputSpec{p2},
				IDs: []*model.IsDependencyInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification",
					},
				},
			}},
			ExpIngestErr: true,
		},
		{
			Name:  "With uneven deps input",
			InPkg: []*model.PkgInputSpec{p1, p2, p3, p4},
			Calls: []call{{
				P1s: []*model.PkgInputSpec{p1, p2},
				P2s: []*model.PkgInputSpec{p2, p4},
				IDs: []*model.IsDependencyInputSpec{
					{
						Justification: "test justification",
					},
				},
			}},
			ExpIngestErr: true,
		},
	}

	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()

			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, a := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *a); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				}
			}
			for _, o := range test.Calls {
				got, err := b.IngestDependencies(ctx, o.P1s, o.P2s, o.IDs)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpID, got, ignoreID, ignoreEmptySlices); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}

		})
	}
}
