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

var c1 = &model.CVEInputSpec{
	Year:  2019,
	CveID: "CVE-2019-13110",
}
var c1out = &model.Cve{
	Year:  2019,
	CveID: "cve-2019-13110",
}

var c2 = &model.CVEInputSpec{
	Year:  2014,
	CveID: "CVE-2014-8139",
}
var c2out = &model.Cve{
	Year:  2014,
	CveID: "cve-2014-8139",
}

var c3 = &model.CVEInputSpec{
	Year:  2014,
	CveID: "cVe-2014-8140",
}
var c3out = &model.Cve{
	Year:  2014,
	CveID: "cve-2014-8140",
}

func lessCve(a, b *model.Cve) bool {
	return a.CveID < b.CveID
}

func TestCVE(t *testing.T) {
	tests := []struct {
		Name         string
		Ingests      []*model.CVEInputSpec
		ExpIngestErr bool
		Query        *model.CVESpec
		Exp          []*model.Cve
		ExpQueryErr  bool
	}{
		{
			Name:    "HappyPath",
			Ingests: []*model.CVEInputSpec{c1},
			Query:   &model.CVESpec{},
			Exp:     []*model.Cve{c1out},
		},
		{
			Name:    "Multiple",
			Ingests: []*model.CVEInputSpec{c1, c2},
			Query:   &model.CVESpec{},
			Exp:     []*model.Cve{c2out, c1out},
		},
		{
			Name:    "Duplicates",
			Ingests: []*model.CVEInputSpec{c1, c1, c1},
			Query:   &model.CVESpec{},
			Exp:     []*model.Cve{c1out},
		},
		{
			Name:    "Query by year",
			Ingests: []*model.CVEInputSpec{c1, c2, c3},
			Query: &model.CVESpec{
				Year: ptrfrom.Int(2014),
			},
			Exp: []*model.Cve{c2out, c3out},
		},
		{
			Name:    "Query by CveID",
			Ingests: []*model.CVEInputSpec{c1, c2, c3},
			Query: &model.CVESpec{
				CveID: ptrfrom.String("CVE-2014-8140"),
			},
			Exp: []*model.Cve{c3out},
		},
		{
			Name:    "Query by ID",
			Ingests: []*model.CVEInputSpec{c1},
			Query: &model.CVESpec{
				ID: ptrfrom.String("2"),
			},
			Exp: []*model.Cve{c1out},
		},
		{
			Name:    "Query none",
			Ingests: []*model.CVEInputSpec{c1, c2, c3},
			Query: &model.CVESpec{
				Year: ptrfrom.Int(2099),
			},
			Exp: nil,
		},
		{
			Name:    "Query none ID",
			Ingests: []*model.CVEInputSpec{c1, c2, c3},
			Query: &model.CVESpec{
				ID: ptrfrom.String("12345"),
			},
			Exp: nil,
		},
		{
			Name:    "Query invalid ID",
			Ingests: []*model.CVEInputSpec{c1, c2, c3},
			Query: &model.CVESpec{
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
				_, err := b.IngestCve(ctx, i)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.Cve(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, lessCve)
			if diff := cmp.Diff(test.Exp, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestCVEs(t *testing.T) {
	tests := []struct {
		name    string
		ingests []*model.CVEInputSpec
		exp     []*model.Cve
	}{{
		name:    "Multiple",
		ingests: []*model.CVEInputSpec{c1, c2, c3},
		exp:     []*model.Cve{c1out, c2out, c3out},
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
			got, err := b.IngestCVEs(ctx, test.ingests)
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
