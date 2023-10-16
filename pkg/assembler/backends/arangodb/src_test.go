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

func lessSource(a, b *model.Source) int {
	return strings.Compare(a.Namespaces[0].Namespace,
		b.Namespaces[0].Namespace)
}

func Test_IngestSources(t *testing.T) {
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
		name      string
		srcInputs []*model.SourceInputSpec
		want      []*model.Source
		wantErr   bool
	}{{
		name:      "test batch source ingestion",
		srcInputs: []*model.SourceInputSpec{testdata.S3, testdata.S4},
		want:      []*model.Source{testdata.S4out, testdata.S3out},
		wantErr:   false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := b.IngestSources(ctx, tt.srcInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestSources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessSource)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_Sources(t *testing.T) {
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
		srcInput   *model.SourceInputSpec
		srcFilter  *model.SourceSpec
		idInFilter bool
		want       []*model.Source
		wantErr    bool
	}{{
		name:     "myrepo with tag",
		srcInput: testdata.S1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: false,
		want:       []*model.Source{testdata.S1out},
		wantErr:    false,
	}, {
		name:     "myrepo with tag, ID search",
		srcInput: testdata.S1,
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
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkg, err := b.IngestSource(ctx, *tt.srcInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.srcFilter.ID = &ingestedPkg.Namespaces[0].Names[0].ID
			}
			got, err := b.Sources(ctx, tt.srcFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.Sources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessSource)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_SourceTypes(t *testing.T) {
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
		srcInput   *model.SourceInputSpec
		srcFilter  *model.SourceSpec
		idInFilter bool
		want       []*model.Source
		wantErr    bool
	}{{
		name:     "myrepo with tag",
		srcInput: testdata.S1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: false,
		want: []*model.Source{{
			Type:       "git",
			Namespaces: []*model.SourceNamespace{},
		}},
		wantErr: false,
	}, {
		name:     "myrepo with tag, ID search",
		srcInput: testdata.S1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: true,
		want: []*model.Source{{
			Type:       "git",
			Namespaces: []*model.SourceNamespace{},
		}},
		wantErr: false,
	}, {
		name:     "bobsrepo with commit",
		srcInput: testdata.S4,
		srcFilter: &model.SourceSpec{
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want: []*model.Source{
			{
				Type:       "git",
				Namespaces: []*model.SourceNamespace{},
			}, {
				Type:       "svn",
				Namespaces: []*model.SourceNamespace{},
			},
		},
		wantErr: false,
	}, {
		name:     "bobsrepo with commit, type search",
		srcInput: testdata.S4,
		srcFilter: &model.SourceSpec{
			Type:      ptrfrom.String("svn"),
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want: []*model.Source{{
			Type:       "svn",
			Namespaces: []*model.SourceNamespace{},
		}},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkg, err := b.IngestSource(ctx, *tt.srcInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.srcFilter.ID = &ingestedPkg.Namespaces[0].Names[0].ID
			}
			got, err := b.(*arangoClient).sourcesType(ctx, tt.srcFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.Sources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_SourceNamespaces(t *testing.T) {
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
		srcInput   *model.SourceInputSpec
		srcFilter  *model.SourceSpec
		idInFilter bool
		want       []*model.Source
		wantErr    bool
	}{{
		name:     "myrepo with tag",
		srcInput: testdata.S1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: false,
		want: []*model.Source{{
			Type: "git",
			Namespaces: []*model.SourceNamespace{{
				ID:        "srcNamespaces/323102",
				Namespace: "github.com/jeff",
				Names:     []*model.SourceName{},
			}},
		}},
		wantErr: false,
	}, {
		name:     "myrepo with tag, ID search",
		srcInput: testdata.S1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: true,
		want: []*model.Source{{
			Type: "git",
			Namespaces: []*model.SourceNamespace{{
				Namespace: "github.com/jeff",
				Names:     []*model.SourceName{},
			}},
		}},
		wantErr: false,
	}, {
		name:     "bobsrepo with commit",
		srcInput: testdata.S4,
		srcFilter: &model.SourceSpec{
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want: []*model.Source{
			{
				Type: "svn",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/bob",
					Names:     []*model.SourceName{},
				}},
			},
		},
		wantErr: false,
	}, {
		name:     "bobsrepo with commit, type search",
		srcInput: testdata.S4,
		srcFilter: &model.SourceSpec{
			Type:      ptrfrom.String("svn"),
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want: []*model.Source{{
			Type: "svn",
			Namespaces: []*model.SourceNamespace{{
				Namespace: "github.com/bob",
				Names:     []*model.SourceName{},
			}},
		}},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkg, err := b.IngestSource(ctx, *tt.srcInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.srcFilter.ID = &ingestedPkg.Namespaces[0].Names[0].ID
			}
			got, err := b.(*arangoClient).sourcesNamespace(ctx, tt.srcFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.Sources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessSource)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildSourceResponseFromID(t *testing.T) {
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
		srcInput   *model.SourceInputSpec
		srcFilter  *model.SourceSpec
		idInFilter bool
		want       *model.Source
		wantErr    bool
	}{{
		name:     "myrepo with tag",
		srcInput: testdata.S1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: false,
		want:       testdata.S1out,
		wantErr:    false,
	}, {
		name:     "myrepo with tag, ID search",
		srcInput: testdata.S1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: true,
		want:       testdata.S1out,
		wantErr:    false,
	}, {
		name:     "bobsrepo with commit",
		srcInput: testdata.S4,
		srcFilter: &model.SourceSpec{
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want:       testdata.S4out,
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
		want:       testdata.S4out,
		wantErr:    false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedSrc, err := b.IngestSource(ctx, *tt.srcInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.srcFilter.ID = &ingestedSrc.Namespaces[0].Names[0].ID
			}
			got, err := b.(*arangoClient).buildSourceResponseFromID(ctx, ingestedSrc.Namespaces[0].Names[0].ID, tt.srcFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.buildSourceResponseFromID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
