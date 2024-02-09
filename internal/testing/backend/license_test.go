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

package backend_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestLicenses(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	tests := []struct {
		Name         string
		Ingests      []*model.LicenseInputSpec
		ExpIngestErr bool
		IDInFilter   int
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
			Name:    "Duplicates",
			Ingests: []*model.LicenseInputSpec{testdata.L1, testdata.L1, testdata.L1},
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
			Name:       "Query by ID",
			Ingests:    []*model.LicenseInputSpec{testdata.L2, testdata.L3, testdata.L4},
			IDInFilter: 2,
			Query:      &model.LicenseSpec{},
			Exp:        []*model.License{testdata.L3out},
		},
		{
			Name:    "Query by Name",
			Ingests: []*model.LicenseInputSpec{testdata.L1, testdata.L2, testdata.L3, testdata.L4},
			Query: &model.LicenseSpec{
				Name: ptrfrom.String("BSD-3-Clause"),
			},
			Exp: []*model.License{testdata.L1out},
		},
		{
			Name: "Query by Inline",
			Query: &model.LicenseSpec{
				Inline: &testdata.InlineLicense,
			},
			Exp: []*model.License{testdata.L4out},
		},
		{
			Name: "Query by ListVersion",
			Query: &model.LicenseSpec{
				ListVersion: ptrfrom.String("1.23 2020"),
			},
			Exp: []*model.License{testdata.L3out},
		},
		{
			Name: "Query None",
			Query: &model.LicenseSpec{
				ListVersion: ptrfrom.String("foo"),
			},
			Exp: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			for i, ingest := range tt.Ingests {
				ingestedLicenseID, err := b.IngestLicense(ctx, ingest)
				if (err != nil) != tt.ExpIngestErr {
					t.Errorf("arangoClient.IngestLicense() error = %v, wantErr %v", err, tt.ExpIngestErr)
					return
				}
				if err != nil {
					return
				}
				if (i + 1) == tt.IDInFilter {
					tt.Query.ID = ptrfrom.String(ingestedLicenseID)
				}
			}
			got, err := b.Licenses(ctx, tt.Query)
			if (err != nil) != tt.ExpQueryErr {
				t.Errorf("arangoClient.Licenses() error = %v, wantErr %v", err, tt.ExpQueryErr)
				return
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.Exp, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLicensesBulk(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	tests := []struct {
		Name         string
		Ingests      []*model.LicenseInputSpec
		ExpIngestErr bool
		Query        *model.LicenseSpec
		Exp          []*model.License
		ExpQueryErr  bool
	}{
		{
			Name:    "Query by Name",
			Ingests: []*model.LicenseInputSpec{testdata.L1, testdata.L1, testdata.L2, testdata.L3, testdata.L4},
			Query: &model.LicenseSpec{
				Name: ptrfrom.String("BSD-3-Clause"),
			},
			Exp: []*model.License{testdata.L1out},
		},
		{
			Name: "Query by Inline",
			Query: &model.LicenseSpec{
				Inline: &testdata.InlineLicense,
			},
			Exp: []*model.License{testdata.L4out},
		},
		{
			Name: "Query by ListVersion",
			Query: &model.LicenseSpec{
				ListVersion: ptrfrom.String("1.23 2020"),
			},
			Exp: []*model.License{testdata.L3out},
		},
		{
			Name: "Query None",
			Query: &model.LicenseSpec{
				ListVersion: ptrfrom.String("foo"),
			},
			Exp: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			_, err := b.IngestLicenses(ctx, tt.Ingests)
			if (err != nil) != tt.ExpIngestErr {
				t.Errorf("arangoClient.IngestLicenses() error = %v, wantErr %v", err, tt.ExpIngestErr)
				return
			}
			if err != nil {
				return
			}
			got, err := b.Licenses(ctx, tt.Query)
			if (err != nil) != tt.ExpQueryErr {
				t.Errorf("arangoClient.Licenses() error = %v, wantErr %v", err, tt.ExpQueryErr)
				return
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.Exp, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
