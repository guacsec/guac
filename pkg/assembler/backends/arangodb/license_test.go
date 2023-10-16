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

package arangodb

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func lessLicense(a, b *model.License) int {
	return strings.Compare(a.Name, b.Name)
}

func Test_Licenses(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
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
			Name:       "Query by ID",
			Ingests:    []*model.LicenseInputSpec{testdata.L2, testdata.L3, testdata.L4},
			IDInFilter: 2,
			Query:      &model.LicenseSpec{},
			Exp:        []*model.License{testdata.L3out},
		},
		{
			Name: "Query None",
			Query: &model.LicenseSpec{
				ListVersion: ptrfrom.String("foo"),
			},
			Exp: nil,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			c, err := getBackend(ctx, arangArg)
			if err != nil {
				t.Fatalf("error creating arango backend: %v", err)
			}
			for i, ingest := range tt.Ingests {
				ingestedLicense, err := c.IngestLicense(ctx, ingest)
				if (err != nil) != tt.ExpIngestErr {
					t.Errorf("demoClient.IngestLicense() error = %v, wantErr %v", err, tt.ExpIngestErr)
					return
				}
				if err != nil {
					return
				}
				if (i + 1) == tt.IDInFilter {
					tt.Query.ID = &ingestedLicense.ID
				}
			}
			got, err := c.Licenses(ctx, tt.Query)
			if (err != nil) != tt.ExpQueryErr {
				t.Errorf("demoClient.Licenses() error = %v, wantErr %v", err, tt.ExpQueryErr)
				return
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, lessLicense)
			if diff := cmp.Diff(tt.Exp, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_LicensesBulk(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
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
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			c, err := getBackend(ctx, arangArg)
			if err != nil {
				t.Fatalf("error creating arango backend: %v", err)
			}
			_, err = c.IngestLicenses(ctx, tt.Ingests)
			if (err != nil) != tt.ExpIngestErr {
				t.Errorf("demoClient.IngestLicense() error = %v, wantErr %v", err, tt.ExpIngestErr)
				return
			}
			if err != nil {
				return
			}
			got, err := c.Licenses(ctx, tt.Query)
			if (err != nil) != tt.ExpQueryErr {
				t.Errorf("demoClient.Licenses() error = %v, wantErr %v", err, tt.ExpQueryErr)
				return
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, lessLicense)
			if diff := cmp.Diff(tt.Exp, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_getLicenseByID(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	tests := []struct {
		Name         string
		Ingests      []*model.LicenseInputSpec
		ExpIngestErr bool
		IDInFilter   int
		Query        *model.LicenseSpec
		Exp          *model.License
		ExpQueryErr  bool
	}{
		{
			Name:    "HappyPath",
			Ingests: []*model.LicenseInputSpec{testdata.L1},
			Query:   &model.LicenseSpec{},
			Exp:     testdata.L1out,
		},
		{
			Name:       "Query by ID",
			Ingests:    []*model.LicenseInputSpec{testdata.L4},
			IDInFilter: 2,
			Query:      &model.LicenseSpec{},
			Exp:        testdata.L4out,
		},
		{
			Name: "Query bad ID",
			Query: &model.LicenseSpec{
				ID: ptrfrom.String("foo"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			c, err := getBackend(ctx, arangArg)
			if err != nil {
				t.Fatalf("error creating arango backend: %v", err)
			}
			for _, ingest := range tt.Ingests {
				ingestedLicense, err := c.IngestLicense(ctx, ingest)
				if (err != nil) != tt.ExpIngestErr {
					t.Errorf("demoClient.IngestLicense() error = %v, wantErr %v", err, tt.ExpIngestErr)
					return
				}
				if err != nil {
					return
				}
				got, err := c.(*arangoClient).getLicenseByID(ctx, ingestedLicense.ID)
				if (err != nil) != tt.ExpQueryErr {
					t.Errorf("demoClient.Licenses() error = %v, wantErr %v", err, tt.ExpQueryErr)
					return
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(tt.Exp, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}
