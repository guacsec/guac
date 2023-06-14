package backend

import (
	"context"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestIsDependency() {
	type call struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
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
					Package:          p1out,
					DependentPackage: p2outName,
					Justification:    "test justification",
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
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p1,
					P2: p2,
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
					Package:          p1out,
					DependentPackage: p2outName,
					Justification:    "test justification",
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
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p1,
					P2: p3,
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
					Package:          p1out,
					DependentPackage: p2outName,
					Justification:    "test justification",
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
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: p1,
					P2: p2,
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
					Package:          p1out,
					DependentPackage: p2outName,
					Justification:    "test justification one",
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
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					ID: ptrfrom.String("5"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:          p1out,
					DependentPackage: p2outName,
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
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p1,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependentPackage: &model.PkgNameSpec{
					Name: ptrfrom.String("openssl"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:          p2out,
					DependentPackage: p4outName,
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
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p3,
					P2: p2,
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
			Name:  "Query on both pkgs",
			InPkg: []*model.PkgInputSpec{p1, p2, p3, p4},
			Calls: []call{
				{
					P1: p2,
					P2: p1,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p3,
					P2: p4,
					ID: &model.IsDependencyInputSpec{},
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
			ExpID: []*model.IsDependency{
				{
					Package:          p3out,
					DependentPackage: p4outName,
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
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
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
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				ID: ptrfrom.String("9"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:          p2out,
					DependentPackage: p1outName,
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
					ID: &model.IsDependencyInputSpec{
						VersionRange: "1-3",
					},
				},
				{
					P1: p2,
					P2: p1,
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
					Package:          p1out,
					DependentPackage: p1outName,
					VersionRange:     "1-3",
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
					ID: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeDirect,
					},
				},
				{
					P1: p2,
					P2: p1,
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
					Package:          p2out,
					DependentPackage: p1outName,
					DependencyType:   model.DependencyTypeIndirect,
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
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	for _, test := range tests {
		s.Run(test.Name, func() {
			b, err := GetBackend(s.Client)
			s.Require().NoError(err, "Could not instantiate testing backend")

			for _, a := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *a); err != nil {
					s.Require().NoError(err, "Could not ingest pkg")
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestDependency(ctx, *o.P1, *o.P2, *o.ID)
				if (err != nil) != test.ExpIngestErr {
					s.T().Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.IsDependency(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				s.T().Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(test.ExpID, got, ignoreID); diff != "" {
				s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
