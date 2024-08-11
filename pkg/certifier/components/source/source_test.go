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

package source

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/certifier"
)

func TestNewCertifier(t *testing.T) {
	httpClient := http.Client{}
	gqlclient := graphql.NewClient("inmemeory", &httpClient)

	type args struct {
		client            graphql.Client
		daysSinceLastScan int
		batchSize         int
		addedLatency      *time.Duration
	}
	tests := []struct {
		name    string
		args    args
		want    certifier.QueryComponents
		wantErr bool
	}{{
		name: "newSourceQuery",
		args: args{
			client:            gqlclient,
			daysSinceLastScan: 0,
			batchSize:         60000,
			addedLatency:      nil,
		},
		want: &sourceQuery{
			client:            gqlclient,
			daysSinceLastScan: 0,
			batchSize:         60000,
			addedLatency:      nil,
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCertifier(tt.args.client, tt.args.daysSinceLastScan, tt.args.batchSize, tt.args.addedLatency)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCertifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_sourceArtifacts_GetComponents(t *testing.T) {
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")

	testSourceDjangoTag := generated.SourcesListSourcesListSourceConnectionEdgesSourceEdgeNodeSource{}
	testSourceDjangoTag.Type = "git"
	testSourceDjangoTag.Namespaces = append(testSourceDjangoTag.Namespaces, generated.AllSourceTreeNamespacesSourceNamespace{
		Id:        "",
		Namespace: "github.com/django",
		Names: []generated.AllSourceTreeNamespacesSourceNamespaceNamesSourceName{
			{
				Name:   "django",
				Commit: ptrfrom.String(""),
				Tag:    ptrfrom.String("1.11.1"),
			},
		},
	})

	testSourceDjangoCommit := generated.SourcesListSourcesListSourceConnectionEdgesSourceEdgeNodeSource{}
	testSourceDjangoCommit.Type = "git"
	testSourceDjangoCommit.Namespaces = append(testSourceDjangoCommit.Namespaces, generated.AllSourceTreeNamespacesSourceNamespace{
		Id:        "",
		Namespace: "github.com/django",
		Names: []generated.AllSourceTreeNamespacesSourceNamespaceNamesSourceName{
			{
				Name:   "django",
				Commit: ptrfrom.String("e829b0a239cffdeab5781df450a6b0e0026faa2d"),
				Tag:    ptrfrom.String(""),
			},
		},
	})

	testSourceDjangoCommitWithAlgo := generated.SourcesListSourcesListSourceConnectionEdgesSourceEdgeNodeSource{}
	testSourceDjangoCommitWithAlgo.Type = "git"
	testSourceDjangoCommitWithAlgo.Namespaces = append(testSourceDjangoCommitWithAlgo.Namespaces, generated.AllSourceTreeNamespacesSourceNamespace{
		Id:        "",
		Namespace: "github.com/django",
		Names: []generated.AllSourceTreeNamespacesSourceNamespaceNamesSourceName{
			{
				Name:   "django",
				Commit: ptrfrom.String("sha1:e829b0a239cffdeab5781df450a6b0e0026faa2d"),
				Tag:    ptrfrom.String(""),
			},
		},
	})

	testSourceKubeTestTag := generated.SourcesListSourcesListSourceConnectionEdgesSourceEdgeNodeSource{}
	testSourceKubeTestTag.Type = "git"
	testSourceKubeTestTag.Namespaces = append(testSourceKubeTestTag.Namespaces, generated.AllSourceTreeNamespacesSourceNamespace{
		Id:        "",
		Namespace: "github.com/vapor-ware",
		Names: []generated.AllSourceTreeNamespacesSourceNamespaceNamesSourceName{
			{
				Name:   "kubetest",
				Commit: ptrfrom.String(""),
				Tag:    ptrfrom.String("0.9.5"),
			},
		},
	})

	neighborCertifyScorecardTimeStamp := generated.NeighborsNeighborsCertifyScorecard{}
	neighborCertifyScorecardTimeStamp.Scorecard = generated.AllCertifyScorecardScorecard{
		TimeScanned: tm.UTC(),
	}

	neighborCertifyScorecardTimeNow := generated.NeighborsNeighborsCertifyScorecard{}
	neighborCertifyScorecardTimeNow.Scorecard = generated.AllCertifyScorecardScorecard{
		TimeScanned: time.Now().UTC(),
	}

	tests := []struct {
		name              string
		daysSinceLastScan int
		getSources        func(ctx context.Context, client graphql.Client, filter generated.SourceSpec, after *string, first *int) (*generated.SourcesListResponse, error)
		getNeighbors      func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error)
		wantSourceNode    []*SourceNode
		wantErr           bool
	}{
		{
			name:              "django: daysSinceLastScan=0, tag specified",
			daysSinceLastScan: 0,
			getSources: func(ctx context.Context, client graphql.Client, filter generated.SourceSpec, after *string, first *int) (*generated.SourcesListResponse, error) {
				return &generated.SourcesListResponse{
					SourcesList: &generated.SourcesListSourcesListSourceConnection{
						TotalCount: 1,
						Edges: []generated.SourcesListSourcesListSourceConnectionEdgesSourceEdge{
							{
								Node:   testSourceDjangoTag,
								Cursor: "",
							},
						},
						PageInfo: generated.SourcesListSourcesListSourceConnectionPageInfo{
							HasNextPage: false,
						},
					},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{},
				}, nil
			},
			wantSourceNode: []*SourceNode{
				{
					Repo:   "github.com/django/django",
					Commit: "",
					Tag:    "1.11.1",
				},
			},
			wantErr: false,
		}, {
			name:              "django: daysSinceLastScan=0, commit specified",
			daysSinceLastScan: 0,
			getSources: func(ctx context.Context, client graphql.Client, filter generated.SourceSpec, after *string, first *int) (*generated.SourcesListResponse, error) {
				return &generated.SourcesListResponse{
					SourcesList: &generated.SourcesListSourcesListSourceConnection{
						TotalCount: 1,
						Edges: []generated.SourcesListSourcesListSourceConnectionEdgesSourceEdge{
							{
								Node:   testSourceDjangoCommit,
								Cursor: "",
							},
						},
						PageInfo: generated.SourcesListSourcesListSourceConnectionPageInfo{
							HasNextPage: false,
						},
					},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{},
				}, nil
			},
			wantSourceNode: []*SourceNode{
				{
					Repo:   "github.com/django/django",
					Commit: "e829b0a239cffdeab5781df450a6b0e0026faa2d",
					Tag:    "",
				},
			},
			wantErr: false,
		}, {
			name:              "django: daysSinceLastScan=0, commit with algorithm specified",
			daysSinceLastScan: 0,
			getSources: func(ctx context.Context, client graphql.Client, filter generated.SourceSpec, after *string, first *int) (*generated.SourcesListResponse, error) {
				return &generated.SourcesListResponse{
					SourcesList: &generated.SourcesListSourcesListSourceConnection{
						TotalCount: 1,
						Edges: []generated.SourcesListSourcesListSourceConnectionEdgesSourceEdge{
							{
								Node:   testSourceDjangoCommitWithAlgo,
								Cursor: "",
							},
						},
						PageInfo: generated.SourcesListSourcesListSourceConnectionPageInfo{
							HasNextPage: false,
						},
					},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{},
				}, nil
			},
			wantSourceNode: []*SourceNode{
				{
					Repo:   "github.com/django/django",
					Commit: "e829b0a239cffdeab5781df450a6b0e0026faa2d",
					Tag:    "",
				},
			},
			wantErr: false,
		}, {
			name:              "django with scorecard, daysSinceLastScan=0",
			daysSinceLastScan: 0,
			getSources: func(ctx context.Context, client graphql.Client, filter generated.SourceSpec, after *string, first *int) (*generated.SourcesListResponse, error) {
				return &generated.SourcesListResponse{
					SourcesList: &generated.SourcesListSourcesListSourceConnection{
						TotalCount: 1,
						Edges: []generated.SourcesListSourcesListSourceConnectionEdgesSourceEdge{
							{
								Node:   testSourceDjangoTag,
								Cursor: "",
							},
						},
						PageInfo: generated.SourcesListSourcesListSourceConnectionPageInfo{
							HasNextPage: false,
						},
					},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{&neighborCertifyScorecardTimeStamp},
				}, nil
			},
			wantSourceNode: []*SourceNode{},
			wantErr:        false,
		}, {
			name:              "django with scorecard, timestamp: time past, daysSinceLastScan=30",
			daysSinceLastScan: 30,
			getSources: func(ctx context.Context, client graphql.Client, filter generated.SourceSpec, after *string, first *int) (*generated.SourcesListResponse, error) {
				return &generated.SourcesListResponse{
					SourcesList: &generated.SourcesListSourcesListSourceConnection{
						TotalCount: 1,
						Edges: []generated.SourcesListSourcesListSourceConnectionEdgesSourceEdge{
							{
								Node:   testSourceDjangoTag,
								Cursor: "",
							},
						},
						PageInfo: generated.SourcesListSourcesListSourceConnectionPageInfo{
							HasNextPage: false,
						},
					},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{&neighborCertifyScorecardTimeStamp},
				}, nil
			},
			wantSourceNode: []*SourceNode{
				{
					Repo:   "github.com/django/django",
					Commit: "",
					Tag:    "1.11.1",
				},
			},
			wantErr: false,
		}, {
			name:              "django with scorecard, timestamp: time now, daysSinceLastScan=30",
			daysSinceLastScan: 30,
			getSources: func(ctx context.Context, client graphql.Client, filter generated.SourceSpec, after *string, first *int) (*generated.SourcesListResponse, error) {
				return &generated.SourcesListResponse{
					SourcesList: &generated.SourcesListSourcesListSourceConnection{
						TotalCount: 1,
						Edges: []generated.SourcesListSourcesListSourceConnectionEdgesSourceEdge{
							{
								Node:   testSourceDjangoTag,
								Cursor: "",
							},
						},
						PageInfo: generated.SourcesListSourcesListSourceConnectionPageInfo{
							HasNextPage: false,
						},
					},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{&neighborCertifyScorecardTimeNow},
				}, nil
			},
			wantSourceNode: []*SourceNode{},
			wantErr:        false,
		}, {
			name:              "multiple packages",
			daysSinceLastScan: 0,
			getSources: func(ctx context.Context, client graphql.Client, filter generated.SourceSpec, after *string, first *int) (*generated.SourcesListResponse, error) {
				return &generated.SourcesListResponse{
					SourcesList: &generated.SourcesListSourcesListSourceConnection{
						TotalCount: 1,
						Edges: []generated.SourcesListSourcesListSourceConnectionEdgesSourceEdge{
							{
								Node:   testSourceDjangoTag,
								Cursor: "",
							},
							{
								Node:   testSourceDjangoCommit,
								Cursor: "",
							},
							{
								Node:   testSourceKubeTestTag,
								Cursor: "",
							},
						},
						PageInfo: generated.SourcesListSourcesListSourceConnectionPageInfo{
							HasNextPage: false,
						},
					},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{},
				}, nil
			},
			wantSourceNode: []*SourceNode{
				{
					Repo:   "github.com/django/django",
					Commit: "",
					Tag:    "1.11.1",
				}, {
					Repo:   "github.com/django/django",
					Commit: "e829b0a239cffdeab5781df450a6b0e0026faa2d",
					Tag:    "",
				}, {
					Repo:   "github.com/vapor-ware/kubetest",
					Commit: "",
					Tag:    "0.9.5",
				},
			},
			wantErr: false,
		}}

	addedLatency, err := time.ParseDuration("3ms")
	if err != nil {
		t.Errorf("failed to parser duration with error: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			p := &sourceQuery{
				client:            nil,
				daysSinceLastScan: tt.daysSinceLastScan,
				addedLatency:      &addedLatency,
			}
			getSources = tt.getSources
			getNeighbors = tt.getNeighbors

			// compChan to collect query components
			compChan := make(chan interface{}, 1)
			// errChan to receive error from collectors
			errChan := make(chan error, 1)

			go func() {
				errChan <- p.GetComponents(ctx, compChan)
			}()

			snList := []*SourceNode{}
			componentsCaptured := false
			for !componentsCaptured {
				select {
				case d := <-compChan:
					if component, ok := d.(*SourceNode); ok {
						snList = append(snList, component)
					}
				case err := <-errChan:
					if err != nil {
						t.Error(err)
					}
					componentsCaptured = true
				}
			}
			for len(compChan) > 0 {
				d := <-compChan
				if component, ok := d.(*SourceNode); ok {
					snList = append(snList, component)
				}
			}
			if !reflect.DeepEqual(snList, tt.wantSourceNode) {
				t.Errorf("sourceQuery.GetComponents() got = %v, want %v", snList, tt.wantSourceNode)
			}
		})
	}
}
