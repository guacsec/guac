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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_IngestBuilder(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	c, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	tests := []struct {
		name         string
		builderInput *model.BuilderInputSpec
		want         *model.Builder
		wantErr      bool
	}{{
		name: "HubHostedActions",
		builderInput: &model.BuilderInputSpec{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		},
		want: &model.Builder{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		},
		wantErr: false,
	}, {
		name: "chains",
		builderInput: &model.BuilderInputSpec{
			URI: "https://tekton.dev/chains/v2",
		},
		want: &model.Builder{
			URI: "https://tekton.dev/chains/v2",
		},
		wantErr: false,
	}}

	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.IngestBuilder(ctx, tt.builderInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestBuilder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func lessBuilder(a, b *model.Builder) int {
	return strings.Compare(a.URI, b.URI)
}

func Test_IngestBuilders(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	c, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	tests := []struct {
		name          string
		builderInputs []*model.BuilderInputSpec
		want          []*model.Builder
		wantErr       bool
	}{{
		name: "HubHostedActions",
		builderInputs: []*model.BuilderInputSpec{
			{
				URI: "https://github.com/CreateFork/HubHostedActions@v1",
			},
			{
				URI: "https://tekton.dev/chains/v2",
			},
		},
		want: []*model.Builder{
			{
				URI: "https://github.com/CreateFork/HubHostedActions@v1",
			},
			{
				URI: "https://tekton.dev/chains/v2",
			},
		},
		wantErr: false,
	}}

	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.IngestBuilders(ctx, tt.builderInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestBuilder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessBuilder)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_Builders(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	tests := []struct {
		name         string
		builderInput *model.BuilderInputSpec
		builderSpec  *model.BuilderSpec
		idInFilter   bool
		want         []*model.Builder
		wantErr      bool
	}{{
		name: "HubHostedActions",
		builderInput: &model.BuilderInputSpec{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		},
		builderSpec: &model.BuilderSpec{
			URI: ptrfrom.String("https://github.com/CreateFork/HubHostedActions@v1"),
		},
		want: []*model.Builder{{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		}},
		wantErr: false,
	}, {
		name: "chains",
		builderInput: &model.BuilderInputSpec{
			URI: "https://tekton.dev/chains/v2",
		},
		builderSpec: &model.BuilderSpec{
			URI: ptrfrom.String("https://tekton.dev/chains/v2"),
		},
		idInFilter: true,
		want: []*model.Builder{{
			URI: "https://tekton.dev/chains/v2",
		}},
		wantErr: false,
	}, {
		name: "query all",
		builderInput: &model.BuilderInputSpec{
			URI: "https://tekton.dev/chains/v2",
		},
		builderSpec: &model.BuilderSpec{},
		want: []*model.Builder{{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		}, {
			URI: "https://tekton.dev/chains/v2",
		}},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := getBackend(ctx, arangArg)
			if err != nil {
				t.Fatalf("error creating arango backend: %v", err)
			}
			ingestedBuilder, err := c.IngestBuilder(ctx, tt.builderInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestBuilder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.builderSpec.ID = &ingestedBuilder.ID
			}
			got, err := c.Builders(ctx, tt.builderSpec)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.Builders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessBuilder)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildBuilderResponseByID(t *testing.T) {
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
		name         string
		builderInput *model.BuilderInputSpec
		want         *model.Builder
		wantErr      bool
	}{{
		name: "HubHostedActions",
		builderInput: &model.BuilderInputSpec{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		},
		want: &model.Builder{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		},
		wantErr: false,
	}, {
		name: "chains",
		builderInput: &model.BuilderInputSpec{
			URI: "https://tekton.dev/chains/v2",
		},
		want: &model.Builder{
			URI: "https://tekton.dev/chains/v2",
		},
		wantErr: false,
	}}

	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedBuilder, err := b.IngestBuilder(ctx, tt.builderInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestBuilder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := b.(*arangoClient).buildBuilderResponseByID(ctx, ingestedBuilder.ID, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.buildPackageResponseFromID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
