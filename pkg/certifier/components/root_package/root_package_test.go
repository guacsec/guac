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

package root_package

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

func TestNewPackageQuery(t *testing.T) {
	httpClient := http.Client{}
	gqlclient := graphql.NewClient("inmemeory", &httpClient)

	type args struct {
		client           graphql.Client
		batchSize        int
		serviceBatchSize int
		addedLatency     *time.Duration
		lastScan         *int
		queryType        generated.QueryType
	}
	tests := []struct {
		name string
		args args
		want certifier.QueryComponents
	}{{
		name: "newPackageQuery",
		args: args{
			client:           gqlclient,
			batchSize:        60000,
			serviceBatchSize: 1000,
			addedLatency:     nil,
			lastScan:         ptrfrom.Int(1),
			queryType:        generated.QueryTypeVulnerability,
		},
		want: &packageQuery{
			client:           gqlclient,
			batchSize:        60000,
			serviceBatchSize: 1000,
			addedLatency:     nil,
			lastScan:         ptrfrom.Int(1),
			queryType:        generated.QueryTypeVulnerability,
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewPackageQuery(tt.args.client, tt.args.queryType, tt.args.batchSize, tt.args.serviceBatchSize, tt.args.addedLatency, tt.args.lastScan); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPackageQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_packageQuery_GetComponents(t *testing.T) {
	testPypiPackage := generated.QueryPackagesListForScanQueryPackagesListForScanPackageConnectionEdgesPackageEdgeNodePackage{}

	testPypiPackage.Type = "pypi"
	testPypiPackage.Namespaces = append(testPypiPackage.Namespaces, generated.AllPkgTreeNamespacesPackageNamespace{
		Id:        "",
		Namespace: "",
		Names: []generated.AllPkgTreeNamespacesPackageNamespaceNamesPackageName{
			{
				Name: "django",
				Versions: []generated.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{
					{
						Version: "1.11.1",
						Purl:    "pkg:pypi/django@1.11.1",
					},
				},
			},
		},
	})

	testOpenSSLPackage := generated.QueryPackagesListForScanQueryPackagesListForScanPackageConnectionEdgesPackageEdgeNodePackage{}
	testOpenSSLPackage.Type = "conan"
	testOpenSSLPackage.Namespaces = append(testOpenSSLPackage.Namespaces, generated.AllPkgTreeNamespacesPackageNamespace{
		Id:        "",
		Namespace: "openssl.org",
		Names: []generated.AllPkgTreeNamespacesPackageNamespaceNamesPackageName{
			{
				Name: "openssl",
				Versions: []generated.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{
					{
						Version: "3.0.3",
						Purl:    "pkg:conan/openssl.org/openssl@3.0.3",
					},
				},
			},
		},
	})

	tests := []struct {
		name                         string
		lastScan                     int
		getPackages                  func(ctx_ context.Context, client_ graphql.Client, pkgIDs []string, after *string, first *int) (*generated.QueryPackagesListForScanResponse, error)
		findPackagesThatNeedScanning func(ctx_ context.Context, client_ graphql.Client, queryType generated.QueryType, lastScan *int) (*generated.FindPackagesThatNeedScanningResponse, error)
		wantPackNode                 []*PackageNode
		wantErr                      bool
	}{
		{
			name:     "django:",
			lastScan: 0,
			findPackagesThatNeedScanning: func(ctx_ context.Context, client_ graphql.Client, queryType generated.QueryType, lastScan *int) (*generated.FindPackagesThatNeedScanningResponse, error) {
				return &generated.FindPackagesThatNeedScanningResponse{
					FindPackagesThatNeedScanning: []string{},
				}, nil
			},
			getPackages: func(ctx_ context.Context, client_ graphql.Client, pkgIDs []string, after *string, first *int) (*generated.QueryPackagesListForScanResponse, error) {
				return &generated.QueryPackagesListForScanResponse{
					QueryPackagesListForScan: &generated.QueryPackagesListForScanQueryPackagesListForScanPackageConnection{
						TotalCount: 1,
						Edges: []generated.QueryPackagesListForScanQueryPackagesListForScanPackageConnectionEdgesPackageEdge{
							{
								Node:   testPypiPackage,
								Cursor: "",
							},
						},
						PageInfo: generated.QueryPackagesListForScanQueryPackagesListForScanPackageConnectionPageInfo{
							HasNextPage: false,
						},
					},
				}, nil
			},
			wantPackNode: []*PackageNode{
				{
					Purl: "pkg:pypi/django@1.11.1",
				},
			},
			wantErr: false,
		}, {
			name:     "multiple packages",
			lastScan: 0,
			findPackagesThatNeedScanning: func(ctx_ context.Context, client_ graphql.Client, queryType generated.QueryType, lastScan *int) (*generated.FindPackagesThatNeedScanningResponse, error) {
				return &generated.FindPackagesThatNeedScanningResponse{
					FindPackagesThatNeedScanning: []string{},
				}, nil
			},
			getPackages: func(ctx_ context.Context, client_ graphql.Client, pkgIDs []string, after *string, first *int) (*generated.QueryPackagesListForScanResponse, error) {
				return &generated.QueryPackagesListForScanResponse{
					QueryPackagesListForScan: &generated.QueryPackagesListForScanQueryPackagesListForScanPackageConnection{
						TotalCount: 2,
						Edges: []generated.QueryPackagesListForScanQueryPackagesListForScanPackageConnectionEdgesPackageEdge{
							{
								Node:   testPypiPackage,
								Cursor: "",
							},
							{
								Node:   testOpenSSLPackage,
								Cursor: "",
							},
						},
						PageInfo: generated.QueryPackagesListForScanQueryPackagesListForScanPackageConnectionPageInfo{
							HasNextPage: false,
						},
					},
				}, nil
			},
			wantPackNode: []*PackageNode{{
				Purl: "pkg:pypi/django@1.11.1",
			}, {
				Purl: "pkg:conan/openssl.org/openssl@3.0.3",
			}},
			wantErr: false,
		}}
	addedLatency, err := time.ParseDuration("3ms")
	if err != nil {
		t.Errorf("failed to parser duration with error: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			p := &packageQuery{
				client:       nil,
				batchSize:    1,
				addedLatency: &addedLatency,
				queryType:    generated.QueryTypeVulnerability,
			}
			getPackages = tt.getPackages
			findPackagesThatNeedScanning = tt.findPackagesThatNeedScanning

			// compChan to collect query components
			compChan := make(chan interface{}, 1)
			// errChan to receive error from collectors
			errChan := make(chan error, 1)

			go func() {
				errChan <- p.GetComponents(ctx, compChan)
			}()

			pnList := []*PackageNode{}
			componentsCaptured := false
			for !componentsCaptured {
				select {
				case d := <-compChan:
					if component, ok := d.([]*PackageNode); ok {
						pnList = append(pnList, component...)
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
				if component, ok := d.([]*PackageNode); ok {
					pnList = append(pnList, component...)
				}
			}
			if !reflect.DeepEqual(pnList, tt.wantPackNode) {
				t.Errorf("packageQuery.GetComponents() got = %v, want %v", pnList, tt.wantPackNode)
			}
		})
	}
}
