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

func TestOSV(t *testing.T) {
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
				ID: ptrfrom.String("2"),
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
				_, err := b.IngestOsv(ctx, i)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
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
