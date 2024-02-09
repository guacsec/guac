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

func TestIngestSources(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	tests := []struct {
		name      string
		srcInputs []*model.SourceInputSpec
		wantErr   bool
	}{{
		name:      "test batch source ingestion",
		srcInputs: []*model.SourceInputSpec{testdata.S3, testdata.S4},
		wantErr:   false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := b.IngestSources(ctx, tt.srcInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("IngestSources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != len(tt.srcInputs) {
				t.Errorf("Unexpected number of results. Wanted: %d, got %d", len(tt.srcInputs), len(got))
			}
		})
	}
}

func TestSources(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	tests := []struct {
		name       string
		srcInput   *model.SourceInputSpec
		srcFilter  *model.SourceSpec
		idInFilter bool
		want       []*model.Source
		wantErr    bool
	}{{
		name:     "myrepo with tag",
		srcInput: &model.IDorSourceInput{SourceInput: testdata.S1},
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: false,
		want:       []*model.Source{testdata.S1out},
		wantErr:    false,
	}, {
		name:     "myrepo with tag, ID search",
		srcInput: &model.IDorSourceInput{SourceInput: testdata.S1},
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: true,
		want:       []*model.Source{testdata.S1out},
		wantErr:    false,
	}, {
		name:     "bobsrepo with commit",
		srcInput: testdata.S4,
		srcFilter: &model.SourceSpec{
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want:       []*model.Source{testdata.S4out},
		wantErr:    false,
	}, {
		name:     "bobsrepo with commit, type search",
		srcInput: testdata.S4,
		srcFilter: &model.SourceSpec{
			Type:      ptrfrom.String("svn"),
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want:       []*model.Source{testdata.S4out},
		wantErr:    false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedSrcIDs, err := b.IngestSource(ctx, *tt.srcInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("IngestSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.srcFilter.ID = ptrfrom.String(ingestedSrcIDs.SourceNameID)
			}
			got, err := b.Sources(ctx, tt.srcFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
