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
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/certifier"
)

func TestNewPackageQuery(t *testing.T) {
	httpClient := http.Client{}
	gqlclient := graphql.NewClient("inmemeory", &httpClient)

	type args struct {
		client            graphql.Client
		daysSinceLastScan int
	}
	tests := []struct {
		name string
		args args
		want certifier.QueryComponents
	}{{
		name: "newPackageQuery",
		args: args{
			client:            gqlclient,
			daysSinceLastScan: 0,
		},
		want: &packageQuery{
			client:            gqlclient,
			daysSinceLastScan: 0,
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewPackageQuery(tt.args.client, tt.args.daysSinceLastScan); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPackageQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_packageQuery_GetComponents(t *testing.T) {
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	testPypiPackage := generated.PackagesPackagesPackage{}

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
					},
				},
			},
		},
	})

	testOpenSSLPackage := generated.PackagesPackagesPackage{}
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
					},
				},
			},
		},
	})

	neighborCertifyVulnTimeStamp := generated.NeighborsNeighborsCertifyVuln{}
	neighborCertifyVulnTimeStamp.Metadata = generated.AllCertifyVulnMetadataVulnerabilityMetaData{
		TimeScanned: tm.UTC(),
	}

	neighborCertifyVulnTimeNow := generated.NeighborsNeighborsCertifyVuln{}
	neighborCertifyVulnTimeNow.Metadata = generated.AllCertifyVulnMetadataVulnerabilityMetaData{
		TimeScanned: time.Now().UTC(),
	}

	neighborIsOccurrence := generated.NeighborsNeighborsIsOccurrence{}
	neighborIsOccurrence.Artifact.Algorithm = "sha256"
	neighborIsOccurrence.Artifact.Digest = "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"

	tests := []struct {
		name              string
		daysSinceLastScan int
		getPackages       func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error)
		getNeighbors      func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error)
		wantPackNode      []*PackageNode
		wantErr           bool
	}{
		{
			name:              "django: daysSinceLastScan=0",
			daysSinceLastScan: 0,
			getPackages: func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error) {
				return &generated.PackagesResponse{
					Packages: []generated.PackagesPackagesPackage{testPypiPackage},
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
		}, {
			name:              "django with certifyVuln",
			daysSinceLastScan: 0,
			getPackages: func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error) {
				return &generated.PackagesResponse{
					Packages: []generated.PackagesPackagesPackage{testPypiPackage},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{&neighborCertifyVulnTimeStamp},
				}, nil
			},
			wantPackNode: []*PackageNode{},
			wantErr:      false,
		}, {
			name:              "django with certifyVuln, daysSinceLastScan=30",
			daysSinceLastScan: 30,
			getPackages: func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error) {
				return &generated.PackagesResponse{
					Packages: []generated.PackagesPackagesPackage{testPypiPackage},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{&neighborCertifyVulnTimeStamp},
				}, nil
			},
			wantPackNode: []*PackageNode{{
				Purl:      "pkg:pypi/django@1.11.1",
				Algorithm: "",
				Digest:    "",
			}},
			wantErr: false,
		}, {
			name:              "django with certifyVuln, timestamp: time now, daysSinceLastScan=30",
			daysSinceLastScan: 30,
			getPackages: func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error) {
				return &generated.PackagesResponse{
					Packages: []generated.PackagesPackagesPackage{testPypiPackage},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{&neighborCertifyVulnTimeNow},
				}, nil
			},
			wantPackNode: []*PackageNode{},
			wantErr:      false,
		}, {
			name:              "django with certifyVuln, daysSinceLastScan=0, IsOccurrence",
			daysSinceLastScan: 0,
			getPackages: func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error) {
				return &generated.PackagesResponse{
					Packages: []generated.PackagesPackagesPackage{testPypiPackage},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{&neighborCertifyVulnTimeStamp, &neighborIsOccurrence},
				}, nil
			},
			wantPackNode: []*PackageNode{},
			wantErr:      false,
		}, {
			name:              "django, daysSinceLastScan=0, IsOccurrence",
			daysSinceLastScan: 0,
			getPackages: func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error) {
				return &generated.PackagesResponse{
					Packages: []generated.PackagesPackagesPackage{testPypiPackage},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{&neighborIsOccurrence},
				}, nil
			},
			wantPackNode: []*PackageNode{{
				Purl:      "pkg:pypi/django@1.11.1",
				Algorithm: "sha256",
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
			}},
			wantErr: false,
		}, {
			name:              "multiple packages",
			daysSinceLastScan: 0,
			getPackages: func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error) {
				return &generated.PackagesResponse{
					Packages: []generated.PackagesPackagesPackage{testPypiPackage, testOpenSSLPackage},
				}, nil
			},
			getNeighbors: func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error) {
				return &generated.NeighborsResponse{
					Neighbors: []generated.NeighborsNeighborsNode{},
				}, nil
			},
			wantPackNode: []*PackageNode{{
				Purl:      "pkg:pypi/django@1.11.1",
				Algorithm: "",
				Digest:    "",
			}, {
				Purl:      "pkg:conan/openssl.org/openssl@3.0.3",
				Algorithm: "",
				Digest:    "",
			}},
			wantErr: false,
		}}
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
