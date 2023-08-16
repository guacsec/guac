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

package inmem_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
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

func TestGHSA(t *testing.T) {
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
				ID: ptrfrom.String("2"),
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
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, i := range test.Ingests {
				_, err := b.IngestGhsa(ctx, i)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.Ghsa(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, lessGhsa)
			if diff := cmp.Diff(test.Exp, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestGHSAs(t *testing.T) {
	tests := []struct {
		name    string
		ingests []*model.GHSAInputSpec
		exp     []*model.Ghsa
	}{{
		name:    "Multiple",
		ingests: []*model.GHSAInputSpec{g1, g2, g3},
		exp:     []*model.Ghsa{g1out, g2out, g3out},
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			got, err := b.IngestGHSAs(ctx, test.ingests)
			if err != nil {
				t.Fatalf("ingest error: %v", err)
				return
			}
			if diff := cmp.Diff(test.exp, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
