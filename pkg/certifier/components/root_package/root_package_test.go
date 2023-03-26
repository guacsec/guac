//
// Copyright 2022 The GUAC Authors.
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
	"reflect"
	"testing"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func Test_packageQuery_GetComponents(t *testing.T) {
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	testPackage := generated.PackagesPackagesPackage{}

	testPackage.Type = "pypi"
	testPackage.Namespaces = append(testPackage.Namespaces, generated.AllPkgTreeNamespacesPackageNamespace{
		Id:        "",
		Namespace: "",
		Names: []generated.AllPkgTreeNamespacesPackageNamespaceNamesPackageName{
			{
				Name: "django",
				Versions: []generated.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{
					{
						Version: "1.11.1",
					},
				},
			},
		},
	})

	neighborCertifyVulnTimeStamp := generated.NeighborsNeighborsCertifyVuln{}
	neighborCertifyVulnTimeStamp.Metadata = generated.AllCertifyVulnMetadataVulnerabilityMetaData{
		TimeScanned: tm,
	}

	tests := []struct {
		name              string
		daysSinceLastScan int
		getPackages       func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error)
		getNeighbors      func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error)
		wantPackNode      []*PackageNode
		wantErr           bool
	}{
		{
			name:              "django",
			daysSinceLastScan: 0,
			getPackages: func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error) {
				return &generated.PackagesResponse{
					Packages: []generated.PackagesPackagesPackage{testPackage},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{},
				}, nil
			},
			wantPackNode: []*PackageNode{
				{
					Purl:      "pkg:pypi/django@1.11.1",
					Algorithm: "",
					Digest:    "",
				},
			},
			wantErr: false,
		},
		{
			name:              "django with certifyVuln",
			daysSinceLastScan: 0,
			getPackages: func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error) {
				return &generated.PackagesResponse{
					Packages: []generated.PackagesPackagesPackage{testPackage},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{&neighborCertifyVulnTimeStamp},
				}, nil
			},
			wantPackNode: []*PackageNode{},
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			p := &packageQuery{
				client:            nil,
				daysSinceLastScan: tt.daysSinceLastScan,
			}
			getPackages = tt.getPackages
			getNeighbors = tt.getNeighbors

			// docChan to collect artifacts
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
						pnList = component
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
					pnList = component
				}
			}
			if !reflect.DeepEqual(pnList, tt.wantPackNode) {
				t.Errorf("packageQuery.GetComponents() got = %v, want %v", pnList, tt.wantPackNode)
			}
		})
	}
}

func Test_packageQuery_getPackageNodes(t *testing.T) {
	type fields struct {
		client            graphql.Client
		daysSinceLastScan int
	}
	type args struct {
		ctx      context.Context
		response *generated.PackagesResponse
		nodeChan chan<- *PackageNode
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &packageQuery{
				client:            tt.fields.client,
				daysSinceLastScan: tt.fields.daysSinceLastScan,
			}
			if err := p.getPackageNodes(tt.args.ctx, tt.args.response, tt.args.nodeChan); (err != nil) != tt.wantErr {
				t.Errorf("packageQuery.getPackageNodes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
