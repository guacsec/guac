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

func TestPackages(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	tests := []struct {
		name       string
		pkgInput   *model.PkgInputSpec
		pkgFilter  *model.PkgSpec
		idInFilter bool
		want       []*model.Package
		wantErr    bool
	}{{
		name:     "tensorflow empty version",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P1out},
		wantErr:    false,
	}, {
		name:     "tensorflow empty version, ID search",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: true,
		want:       []*model.Package{testdata.P1out},
		wantErr:    false,
	}, {
		name:     "tensorflow with version",
		pkgInput: testdata.P2,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Version: ptrfrom.String("2.11.1"),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P2out},
		wantErr:    false,
	}, {
		name:     "tensorflow with version and subpath",
		pkgInput: testdata.P3,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Subpath: ptrfrom.String("saved_model_cli.py"),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P3out},
		wantErr:    false,
	}, {
		name:     "openssl with version",
		pkgInput: testdata.P4,
		pkgFilter: &model.PkgSpec{
			Name:      ptrfrom.String("openssl"),
			Namespace: ptrfrom.String("openssl.org"),
			Version:   ptrfrom.String("3.0.3"),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P4out},
		wantErr:    false,
	}, {
		name:     "openssl with match empty qualifiers",
		pkgInput: testdata.P4,
		pkgFilter: &model.PkgSpec{
			Name:                     ptrfrom.String("openssl"),
			Namespace:                ptrfrom.String("openssl.org"),
			Version:                  ptrfrom.String("3.0.3"),
			MatchOnlyEmptyQualifiers: ptrfrom.Bool(true),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P4out},
		wantErr:    false,
	}, {
		name:     "openssl with qualifier",
		pkgInput: testdata.P5,
		pkgFilter: &model.PkgSpec{
			Name:      ptrfrom.String("openssl"),
			Namespace: ptrfrom.String("openssl.org"),
			Version:   ptrfrom.String("3.0.3"),
			Qualifiers: []*model.PackageQualifierSpec{{
				Key:   "test",
				Value: ptrfrom.String("test"),
			}},
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P5out},
		wantErr:    false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkgIDs, err := b.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.pkgFilter.ID = ptrfrom.String(ingestedPkgIDs.PackageVersionID)
			}
			got, err := b.Packages(ctx, tt.pkgFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("Packages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestPackages(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	tests := []struct {
		name      string
		pkgInputs []*model.PkgInputSpec
		wantErr   bool
	}{{
		name:      "tensorflow empty version",
		pkgInputs: []*model.PkgInputSpec{testdata.P3, testdata.P4},
		wantErr:   false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := b.IngestPackages(ctx, tt.pkgInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("IngestPackages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != len(tt.pkgInputs) {
				t.Errorf("Unexpected number of results. Wanted: %d, got %d", len(tt.pkgInputs), len(got))
			}
		})
	}
}
