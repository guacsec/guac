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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO (pxp928): eventual consistency for search does not allow for the unit test to work

func Test_arangoClient_FindSoftware(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := GetBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	tests := []struct {
		name          string
		search        string
		pkgInput      model.PkgInputSpec
		srcInput      model.SourceInputSpec
		artInput      model.ArtifactInputSpec
		wantPkgSrcArt []model.PackageSourceOrArtifact
		wantErr       bool
	}{{
		// TODO add tests
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.IngestPackage(ctx, tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := b.FindSoftware(ctx, tt.search)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.FindSoftware() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.wantPkgSrcArt, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
