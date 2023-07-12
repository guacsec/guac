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

package inmem

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var s1 = &model.SourceInputSpec{
	Type:      "git",
	Namespace: "github.com/jeff",
	Name:      "myrepo",
	Tag:       ptrfrom.String("v1.0"),
}
var s1out = &model.Source{
	Type: "git",
	Namespaces: []*model.SourceNamespace{{
		Namespace: "github.com/jeff",
		Names: []*model.SourceName{{
			Name:   "myrepo",
			Tag:    ptrfrom.String("v1.0"),
			Commit: ptrfrom.String(""),
		}},
	}},
}

var s2 = &model.SourceInputSpec{
	Type:      "git",
	Namespace: "github.com/bob",
	Name:      "bobsrepo",
	Commit:    ptrfrom.String("5e7c41f"),
}
var s2out = &model.Source{
	Type: "git",
	Namespaces: []*model.SourceNamespace{{
		Namespace: "github.com/bob",
		Names: []*model.SourceName{{
			Name:   "bobsrepo",
			Tag:    ptrfrom.String(""),
			Commit: ptrfrom.String("5e7c41f"),
		}},
	}},
}

func Test_demoClient_IngestSources(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		srcInputs []*model.SourceInputSpec
		want      []*model.Source
		wantErr   bool
	}{{
		name:      "test batch source intestion",
		srcInputs: []*model.SourceInputSpec{s1, s2},
		want:      []*model.Source{s1out, s2out},
		wantErr:   false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &demoClient{
				sources: srcTypeMap{},
				index:   indexType{},
			}
			got, err := c.IngestSources(ctx, tt.srcInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestSources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_demoClient_Sources(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		srcInput   *model.SourceInputSpec
		srcFilter  *model.SourceSpec
		idInFilter bool
		want       []*model.Source
		wantErr    bool
	}{{
		name:     "myrepo with tag",
		srcInput: s1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: false,
		want:       []*model.Source{s1out},
		wantErr:    false,
	}, {
		name:     "myrepo with tag, ID search",
		srcInput: s1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: true,
		want:       []*model.Source{s1out},
		wantErr:    false,
	}, {
		name:     "bobsrepo with commit",
		srcInput: s2,
		srcFilter: &model.SourceSpec{
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want:       []*model.Source{s2out},
		wantErr:    false,
	}, {
		name:     "bobsrepo with commit, type search",
		srcInput: s2,
		srcFilter: &model.SourceSpec{
			Type:      ptrfrom.String("git"),
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want:       []*model.Source{s2out},
		wantErr:    false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &demoClient{
				sources: srcTypeMap{},
				index:   indexType{},
			}
			ingestedPkg, err := c.IngestSource(ctx, *tt.srcInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.srcFilter.ID = &ingestedPkg.Namespaces[0].Names[0].ID
			}
			got, err := c.Sources(ctx, tt.srcFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.Sources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
