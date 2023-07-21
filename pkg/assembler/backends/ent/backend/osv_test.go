package backend

import (
	"strconv"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

var o1 = &model.OSVInputSpec{
	OsvID: "CVE-2014-8140",
}
var o1out = &model.Osv{
	OsvID: "cve-2014-8140",
}

var o2 = &model.OSVInputSpec{
	OsvID: "CVE-2022-26499",
}
var o2out = &model.Osv{
	OsvID: "cve-2022-26499",
}

var o3 = &model.OSVInputSpec{
	OsvID: "GHSA-h45f-rjvw-2rv2",
}
var o3out = &model.Osv{
	OsvID: "ghsa-h45f-rjvw-2rv2",
}

func lessOsv(a, b *model.Osv) bool {
	return a.OsvID < b.OsvID
}

func (s *Suite) TestOSV() {
	tests := []struct {
		Name         string
		Ingests      []*model.OSVInputSpec
		ExpIngestErr bool
		Query        *model.OSVSpec
		Exp          []*model.Osv
		ExpQueryErr  bool
	}{
		{
			Name:    "HappyPath",
			Ingests: []*model.OSVInputSpec{o1},
			Query:   &model.OSVSpec{},
			Exp:     []*model.Osv{o1out},
		},
		{
			Name:    "Multiple",
			Ingests: []*model.OSVInputSpec{o1, o2},
			Query:   &model.OSVSpec{},
			Exp:     []*model.Osv{o1out, o2out},
		},
		{
			Name:    "Duplicates",
			Ingests: []*model.OSVInputSpec{o1, o1, o1},
			Query:   &model.OSVSpec{},
			Exp:     []*model.Osv{o1out},
		},
		{
			Name:    "Query by OSV ID",
			Ingests: []*model.OSVInputSpec{o1, o2, o3},
			Query: &model.OSVSpec{
				OsvID: ptrfrom.String("CVE-2022-26499"),
			},
			Exp: []*model.Osv{o2out},
		},
		{
			Name:    "Query by ID",
			Ingests: []*model.OSVInputSpec{o3},
			Query: &model.OSVSpec{
				ID: ptrfrom.String("0"),
			},
			Exp: []*model.Osv{o3out},
		},
		{
			Name:    "Query None",
			Ingests: []*model.OSVInputSpec{o1, o2, o3},
			Query: &model.OSVSpec{
				OsvID: ptrfrom.String("asdf"),
			},
			Exp: nil,
		},
		{
			Name:    "Query none ID",
			Ingests: []*model.OSVInputSpec{o1},
			Query: &model.OSVSpec{
				ID: ptrfrom.String("123456"),
			},
			Exp: nil,
		},
		{
			Name:    "Query invalid ID",
			Ingests: []*model.OSVInputSpec{o1},
			Query: &model.OSVSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
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
			ids := make([]string, len(test.Ingests))
			for i, v := range test.Ingests {
				record, err := b.IngestOsv(ctx, v)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				ids[i] = record.ID
			}
			if test.Query.ID != nil {
				idIndex, err := strconv.Atoi(*test.Query.ID)
				if err == nil && idIndex < len(ids) {
					test.Query.ID = ptrfrom.String(ids[idIndex])
				}
			}

			got, err := b.Osv(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, lessOsv)
			if diff := cmp.Diff(test.Exp, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
