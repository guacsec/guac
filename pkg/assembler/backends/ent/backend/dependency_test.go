package backend

import (
	"context"
	"reflect"

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
						Justification: "test justification",
					},
				},
				{
					P1: p1,
					P2: p3,
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
					// ID: ptrfrom.String("9"),
					Type: ptrfrom.String("pypi"),
					Name: ptrfrom.String("tensorflow"),
					// Version: ptrfrom.String("2.11.1"),
				},
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p2outName,
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
				},
				{
					Package:          p3out,
					DependentPackage: p1outName,
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
				ID: ptrfrom.String("9"),
			},
			ExpectedDep: []*model.IsDependency{
				{
					Package:          p2out,
					DependentPackage: p1outName,
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
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return p.Last().String() == ".ID"
	}, cmp.Ignore())

	ignoreEmptySlices := cmp.FilterValues(func(x, y interface{}) bool {
		xv, yv := reflect.ValueOf(x), reflect.ValueOf(y)
		if xv.Kind() == reflect.Slice && yv.Kind() == reflect.Slice {
			return xv.Len() == 0 && yv.Len() == 0
		}
		return false
	}, cmp.Ignore())

	hasOnly := false
	for _, t := range tests {
		if t.Only {
			hasOnly = true
			break
		}
	}

	ctx := context.Background()
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
			for _, o := range test.Calls {
				_, err := b.IngestDependency(ctx, *o.P1, *o.P2, *o.Input)
				if (err != nil) != test.ExpectedIngestErr {
					s.T().Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpectedIngestErr, err)
				}
				if err != nil {
					return
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
