package backend

import (
	"strconv"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

var g1 = &model.GHSAInputSpec{
	GhsaID: "GHSA-h45f-rjvw-2rv2",
}
var g1out = &model.Ghsa{
	GhsaID: "ghsa-h45f-rjvw-2rv2",
}

var g2 = &model.GHSAInputSpec{
	GhsaID: "GHSA-xrw3-wqph-3fxg",
}
var g2out = &model.Ghsa{
	GhsaID: "ghsa-xrw3-wqph-3fxg",
}

var g3 = &model.GHSAInputSpec{
	GhsaID: "GHSA-8v4j-7jgf-5rg9",
}
var g3out = &model.Ghsa{
	GhsaID: "ghsa-8v4j-7jgf-5rg9",
}

func lessGhsa(a, b *model.Ghsa) bool {
	return a.GhsaID < b.GhsaID
}

func (s *Suite) TestGHSA() {
	tests := []struct {
		Name         string
		Ingests      []*model.GHSAInputSpec
		ExpIngestErr bool
		Query        *model.GHSASpec
		Exp          []*model.Ghsa
		ExpQueryErr  bool
	}{
		{
			Name:    "HappyPath",
			Ingests: []*model.GHSAInputSpec{g1},
			Query:   &model.GHSASpec{},
			Exp:     []*model.Ghsa{g1out},
		},
		{
			Name:    "Multiple",
			Ingests: []*model.GHSAInputSpec{g1, g2},
			Query:   &model.GHSASpec{},
			Exp:     []*model.Ghsa{g1out, g2out},
		},
		{
			Name:    "Duplicates",
			Ingests: []*model.GHSAInputSpec{g1, g1, g1},
			Query:   &model.GHSASpec{},
			Exp:     []*model.Ghsa{g1out},
		},
		{
			Name:    "Query by GHSA ID",
			Ingests: []*model.GHSAInputSpec{g1, g2, g3},
			Query: &model.GHSASpec{
				GhsaID: ptrfrom.String("GHSA-8v4j-7jgf-5rg9"),
			},
			Exp: []*model.Ghsa{g3out},
		},
		{
			Name:    "Query by ID",
			Ingests: []*model.GHSAInputSpec{g1},
			Query: &model.GHSASpec{
				ID: ptrfrom.String("0"),
			},
			Exp: []*model.Ghsa{g1out},
		},
		{
			Name:    "Query None",
			Ingests: []*model.GHSAInputSpec{g1, g2, g3},
			Query: &model.GHSASpec{
				GhsaID: ptrfrom.String("asdf"),
			},
			Exp: nil,
		},
		{
			Name:    "Query none ID",
			Ingests: []*model.GHSAInputSpec{g1},
			Query: &model.GHSASpec{
				ID: ptrfrom.String("123456"),
			},
			Exp: nil,
		},
		{
			Name:    "Query invalid ID",
			Ingests: []*model.GHSAInputSpec{g1},
			Query: &model.GHSASpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
	}

	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			b, err := GetBackend(s.Client)
			if err != nil {
				s.T().Fatalf("Could not instantiate testing backend: %v", err)
			}

			ids := make([]string, len(test.Ingests))
			for idx, i := range test.Ingests {
				id, err := b.IngestGhsa(ctx, i)
				if (err != nil) != test.ExpIngestErr {
					s.T().Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}

				ids[idx] = id.ID
			}

			if test.Query.ID != nil {
				idIndex, err := strconv.Atoi(*test.Query.ID)
				if err == nil && idIndex < len(ids) {
					test.Query.ID = ptrfrom.String(ids[idIndex])
				}
			}

			got, err := b.Ghsa(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				s.T().Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, lessGhsa)
			if diff := cmp.Diff(test.Exp, got, ignoreID); diff != "" {
				s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
