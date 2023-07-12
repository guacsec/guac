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
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_builderStruct_ID(t *testing.T) {
	tests := []struct {
		name string
		id   uint32
		want uint32
	}{{
		name: "getID",
		id:   643,
		want: 643,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &builderStruct{
				id: tt.id,
			}
			if got := b.ID(); got != tt.want {
				t.Errorf("builderStruct.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_builderStruct_Neighbors(t *testing.T) {
	type fields struct {
		id       uint32
		uri      string
		hasSLSAs []uint32
	}
	tests := []struct {
		name         string
		fields       fields
		allowedEdges edgeMap
		want         []uint32
	}{{
		name: "hasSLSAs",
		fields: fields{
			hasSLSAs: []uint32{445, 1232244},
		},
		allowedEdges: edgeMap{model.EdgeBuilderHasSlsa: true},
		want:         []uint32{445, 1232244},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &builderStruct{
				id:       tt.fields.id,
				uri:      tt.fields.uri,
				hasSLSAs: tt.fields.hasSLSAs,
			}
			if got := b.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("builderStruct.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_builderStruct_BuildModelNode(t *testing.T) {
	type fields struct {
		id  uint32
		uri string
	}
	tests := []struct {
		name    string
		fields  fields
		want    model.Node
		wantErr bool
	}{{
		name: "HubHostedActions",
		fields: fields{
			id:  uint32(43),
			uri: "https://github.com/CreateFork/HubHostedActions@v1",
		},
		want: &model.Builder{
			ID:  nodeID(uint32(43)),
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		},
		wantErr: false,
	}, {
		name: "chains",
		fields: fields{
			id:  uint32(53),
			uri: "https://tekton.dev/chains/v2",
		},
		want: &model.Builder{
			ID:  nodeID(uint32(53)),
			URI: "https://tekton.dev/chains/v2",
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &demoClient{
				builders: builderMap{},
				index:    indexType{},
			}
			b := &builderStruct{
				id:  tt.fields.id,
				uri: tt.fields.uri,
			}
			got, err := b.BuildModelNode(c)
			if (err != nil) != tt.wantErr {
				t.Errorf("builderStruct.BuildModelNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_demoClient_IngestBuilder(t *testing.T) {
	ctx := context.Background()
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
			c := &demoClient{
				builders: builderMap{},
				index:    indexType{},
			}
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

func Test_demoClient_IngestBuilders(t *testing.T) {
	ctx := context.Background()
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
			}},
		want: []*model.Builder{
			{
				URI: "https://github.com/CreateFork/HubHostedActions@v1",
			},
			{
				URI: "https://tekton.dev/chains/v2",
			}},
		wantErr: false,
	}}

	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &demoClient{
				builders: builderMap{},
				index:    indexType{},
			}
			got, err := c.IngestBuilders(ctx, tt.builderInputs)
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

func Test_demoClient_Builders(t *testing.T) {
	ctx := context.Background()
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
		name: "chains",
		builderInput: &model.BuilderInputSpec{
			URI: "https://tekton.dev/chains/v2",
		},
		builderSpec: &model.BuilderSpec{},
		want: []*model.Builder{{
			URI: "https://tekton.dev/chains/v2",
		}},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &demoClient{
				builders: builderMap{},
				index:    indexType{},
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
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_demoClient_exactBuilder(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name         string
		builderInput *model.BuilderInputSpec
		builderSpec  *model.BuilderSpec
		idInFilter   bool
		want         *builderStruct
		wantErr      bool
	}{{
		name: "HubHostedActions",
		builderInput: &model.BuilderInputSpec{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		},
		builderSpec: &model.BuilderSpec{
			URI: ptrfrom.String("https://github.com/CreateFork/HubHostedActions@v1"),
		},
		want: &builderStruct{
			uri: "https://github.com/CreateFork/HubHostedActions@v1",
		},
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
		want: &builderStruct{
			uri: "https://tekton.dev/chains/v2",
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &demoClient{
				builders: builderMap{},
				index:    indexType{},
			}
			ingestedBuilder, err := c.IngestBuilder(ctx, tt.builderInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestBuilder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.builderSpec.ID = &ingestedBuilder.ID
			}
			got, err := c.exactBuilder(tt.builderSpec)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.exactBuilder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			id64, err := strconv.ParseUint(ingestedBuilder.ID, 10, 32)
			if err != nil {
				t.Errorf("failed to convert string to uint32: %v", err)
				return
			}
			id := uint32(id64)
			tt.want.id = id
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("demoClient.exactBuilder() = %v, want %v", got, tt.want)
			}
		})
	}
}
