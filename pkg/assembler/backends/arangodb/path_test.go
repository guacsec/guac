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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_Node(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	tests := []struct {
		name       string
		pkgInput   *model.PkgInputSpec
		pkgFilter  *model.PkgSpec
		idInFilter bool
		want       *model.Package
		wantErr    bool
	}{{
		name:     "tensorflow empty version, ID search",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: true,
		want:       testdata.P1out,
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
		idInFilter: true,
		want:       testdata.P4out,
		wantErr:    false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkg, err := b.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := b.Node(ctx, ingestedPkg.Namespaces[0].Names[0].Versions[0].ID)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.Packages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
