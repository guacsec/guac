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
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestLicense() {
	tests := []struct {
		Name         string
		Ingests      []*model.LicenseInputSpec
		ExpIngestErr bool
		Query        *model.LicenseSpec
		Exp          []*model.License
		ExpQueryErr  bool
	}{
		{
			Name:    "HappyPath",
			Ingests: []*model.LicenseInputSpec{testdata.L1},
			Query:   &model.LicenseSpec{},
			Exp:     []*model.License{testdata.L1out},
		},
		{
			Name:    "Multiple",
			Ingests: []*model.LicenseInputSpec{testdata.L1, testdata.L2},
			Query:   &model.LicenseSpec{},
			Exp:     []*model.License{testdata.L1out, testdata.L2out},
		},
		{
			Name:    "Duplicates",
			Ingests: []*model.LicenseInputSpec{testdata.L1, testdata.L1, testdata.L1},
			Query:   &model.LicenseSpec{},
			Exp:     []*model.License{testdata.L1out},
		},
		{
			Name:    "Query by Name",
			Ingests: []*model.LicenseInputSpec{testdata.L1, testdata.L2, testdata.L3},
			Query: &model.LicenseSpec{
				Name: ptrfrom.String("BSD-3-Clause"),
			},
			Exp: []*model.License{testdata.L1out},
		},
		{
			Name:    "Query by Inline",
			Ingests: []*model.LicenseInputSpec{testdata.L2, testdata.L3, testdata.L4},
			Query: &model.LicenseSpec{
				Inline: &testdata.InlineLicense,
			},
			Exp: []*model.License{testdata.L4out},
		},
		{
			Name:    "Query by ListVersion",
			Ingests: []*model.LicenseInputSpec{testdata.L2, testdata.L3, testdata.L4},
			Query: &model.LicenseSpec{
				ListVersion: ptrfrom.String("1.23 2020"),
			},
			Exp: []*model.License{testdata.L3out},
		},
		{
			Name:    "Query by ID",
			Ingests: []*model.LicenseInputSpec{testdata.L2, testdata.L3, testdata.L4},
			Query: &model.LicenseSpec{
				ID: ptrfrom.String("1"),
			},
			Exp: []*model.License{testdata.L3out},
		},
		{
			Name:    "Query None",
			Ingests: []*model.LicenseInputSpec{testdata.L2, testdata.L3, testdata.L4},
			Query: &model.LicenseSpec{
				ListVersion: ptrfrom.String("foo"),
			},
			Exp: nil,
		},
		{
			Name:    "Query invalid ID",
			Ingests: []*model.LicenseInputSpec{testdata.L1, testdata.L2, testdata.L3},
			Query: &model.LicenseSpec{
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
			recordIDs := make([]string, len(test.Ingests))
			for x, i := range test.Ingests {
				lic, err := b.IngestLicense(ctx, i)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				recordIDs[x] = lic.ID
			}

			if test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx >= len(recordIDs) {
						s.T().Logf("ID index out of range, want: %d, got: %d. So ID %d will be directly used to query.", len(recordIDs), idIdx, idIdx)
					} else {
						realID := recordIDs[idIdx]
						test.Query.ID = &realID
					}
				}
			}

			got, err := b.Licenses(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, lessLic)
			if diff := cmp.Diff(test.Exp, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func lessLic(a, b *model.License) int {
	return strings.Compare(a.Name, b.Name)
}

func (s *Suite) TestIngestLicenses() {
	tests := []struct {
		name    string
		ingests []*model.LicenseInputSpec
		exp     []*model.License
	}{
		{
			name:    "Multiple",
			ingests: []*model.LicenseInputSpec{testdata.L1, testdata.L2, testdata.L3, testdata.L4},
			exp:     []*model.License{{}, {}, {}, {}},
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			got, err := b.IngestLicenses(ctx, test.ingests)
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
