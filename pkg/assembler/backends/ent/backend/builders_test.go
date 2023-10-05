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

package backend

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestIngestBuilder() {
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
	ctx := s.Ctx
	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("GetBackend() error = %v", err)
			}
			got, err := b.IngestBuilder(ctx, tt.builderInput)
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

func (s *Suite) TestIngestBuilders() {
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
	ctx := s.Ctx
	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			got, err := b.IngestBuilders(ctx, tt.builderInputs)
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

func (s *Suite) TestBuilders() {
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
	ctx := s.Ctx
	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			ingestedBuilder, err := b.IngestBuilder(ctx, tt.builderInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestBuilder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.builderSpec.ID = &ingestedBuilder.ID
			}
			got, err := b.Builders(ctx, tt.builderSpec)
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

func (s *Suite) TestExactBuilder() {
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
		want: []*model.Builder{
			{
				URI: "https://github.com/CreateFork/HubHostedActions@v1",
			},
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
		want: []*model.Builder{
			{
				URI: "https://tekton.dev/chains/v2",
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			ingestedBuilder, err := b.IngestBuilder(ctx, tt.builderInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestBuilder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.builderSpec.ID = &ingestedBuilder.ID
			}
			got, err := b.Builders(ctx, tt.builderSpec)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.exactBuilder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
