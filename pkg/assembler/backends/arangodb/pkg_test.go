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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

// func Test_pkgNamespaceStruct_Neighbors(t *testing.T) {
// 	type fields struct {
// 		id         uint32
// 		namespaces pkgNamespaceMap
// 	}
// 	tests := []struct {
// 		name   string
// 		fields fields
// 		want   []uint32
// 	}{{
// 		name: "pkgNamespaceStruct Neighbors",
// 		fields: fields{
// 			id:         uint32(23),
// 			namespaces: pkgNamespaceMap{"test": &pkgNameStruct{id: uint32(24)}},
// 		},
// 		want: []uint32{uint32(24)},
// 	}}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			n := &pkgNamespaceStruct{
// 				id:         tt.fields.id,
// 				namespaces: tt.fields.namespaces,
// 			}
// 			if got := n.Neighbors(nil); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("pkgNamespaceStruct.Neighbors() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_pkgNameStruct_Neighbors(t *testing.T) {
// 	type fields struct {
// 		id        uint32
// 		parent    uint32
// 		namespace string
// 		names     pkgNameMap
// 	}
// 	tests := []struct {
// 		name   string
// 		fields fields
// 		want   []uint32
// 	}{{
// 		name: "pkgNameStruct Neighbors",
// 		fields: fields{
// 			id:        uint32(23),
// 			parent:    uint32(22),
// 			namespace: "test",
// 			names:     pkgNameMap{"test": &pkgVersionStruct{id: uint32(24)}},
// 		},
// 		want: []uint32{uint32(24), uint32(22)},
// 	}}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			n := &pkgNameStruct{
// 				id:        tt.fields.id,
// 				parent:    tt.fields.parent,
// 				namespace: tt.fields.namespace,
// 				names:     tt.fields.names,
// 			}
// 			if got := n.Neighbors(nil); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("pkgNameStruct.Neighbors() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_pkgVersionStruct_Neighbors(t *testing.T) {
// 	type fields struct {
// 		id                uint32
// 		parent            uint32
// 		versions          pkgVersionList
// 		srcMapLinks       []uint32
// 		isDependencyLinks []uint32
// 		badLinks          []uint32
// 		goodLinks         []uint32
// 	}
// 	tests := []struct {
// 		name         string
// 		allowedEdges edgeMap
// 		fields       fields
// 		want         []uint32
// 	}{{
// 		name: "srcMapLinks",
// 		fields: fields{
// 			id:          uint32(23),
// 			parent:      uint32(22),
// 			versions:    pkgVersionList{&pkgVersionNode{id: uint32(24)}},
// 			srcMapLinks: []uint32{343, 546},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageHasSourceAt: true},
// 		want:         []uint32{22, 24, 343, 546},
// 	}, {
// 		name: "isDependencyLinks",
// 		fields: fields{
// 			id:                uint32(23),
// 			parent:            uint32(22),
// 			versions:          pkgVersionList{&pkgVersionNode{id: uint32(24)}},
// 			isDependencyLinks: []uint32{2324, 1234},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageIsDependency: true},
// 		want:         []uint32{22, 24, 2324, 1234},
// 	}, {
// 		name: "badLinks",
// 		fields: fields{
// 			id:       uint32(23),
// 			parent:   uint32(22),
// 			versions: pkgVersionList{&pkgVersionNode{id: uint32(24)}},
// 			badLinks: []uint32{445, 1232244},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageCertifyBad: true},
// 		want:         []uint32{22, 24, 445, 1232244},
// 	}, {
// 		name: "goodLinks",
// 		fields: fields{
// 			id:        uint32(23),
// 			parent:    uint32(22),
// 			versions:  pkgVersionList{&pkgVersionNode{id: uint32(24)}},
// 			goodLinks: []uint32{987, 9876},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageCertifyGood: true},
// 		want:         []uint32{22, 24, 987, 9876},
// 	}}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			n := &pkgVersionStruct{
// 				id:                tt.fields.id,
// 				parent:            tt.fields.parent,
// 				versions:          tt.fields.versions,
// 				srcMapLinks:       tt.fields.srcMapLinks,
// 				isDependencyLinks: tt.fields.isDependencyLinks,
// 				badLinks:          tt.fields.badLinks,
// 				goodLinks:         tt.fields.goodLinks,
// 			}
// 			if got := n.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("pkgVersionStruct.Neighbors() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_pkgVersionNode_Neighbors(t *testing.T) {
// 	type fields struct {
// 		id                uint32
// 		parent            uint32
// 		srcMapLinks       []uint32
// 		isDependencyLinks []uint32
// 		occurrences       []uint32
// 		certifyVulnLinks  []uint32
// 		hasSBOMs          []uint32
// 		vexLinks          []uint32
// 		badLinks          []uint32
// 		goodLinks         []uint32
// 		pkgEquals         []uint32
// 	}
// 	tests := []struct {
// 		name         string
// 		allowedEdges edgeMap
// 		fields       fields
// 		want         []uint32
// 	}{{
// 		name: "srcMapLinks",
// 		fields: fields{
// 			id:          uint32(23),
// 			parent:      uint32(22),
// 			srcMapLinks: []uint32{343, 546},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageHasSourceAt: true},
// 		want:         []uint32{22, 343, 546},
// 	}, {
// 		name: "isDependencyLinks",
// 		fields: fields{
// 			id:                uint32(23),
// 			parent:            uint32(22),
// 			isDependencyLinks: []uint32{2324, 1234},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageIsDependency: true},
// 		want:         []uint32{22, 2324, 1234},
// 	}, {
// 		name: "occurrences",
// 		fields: fields{
// 			id:          uint32(23),
// 			parent:      uint32(22),
// 			occurrences: []uint32{2324, 1234},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageIsOccurrence: true},
// 		want:         []uint32{22, 2324, 1234},
// 	}, {
// 		name: "certifyVulnLinks",
// 		fields: fields{
// 			id:               uint32(23),
// 			parent:           uint32(22),
// 			certifyVulnLinks: []uint32{2324, 1234},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageCertifyVuln: true},
// 		want:         []uint32{22, 2324, 1234},
// 	}, {
// 		name: "hasSBOMs",
// 		fields: fields{
// 			id:       uint32(23),
// 			parent:   uint32(22),
// 			hasSBOMs: []uint32{2324, 1234},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageHasSbom: true},
// 		want:         []uint32{22, 2324, 1234},
// 	}, {
// 		name: "vexLinks",
// 		fields: fields{
// 			id:       uint32(23),
// 			parent:   uint32(22),
// 			vexLinks: []uint32{2324, 1234},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageCertifyVexStatement: true},
// 		want:         []uint32{22, 2324, 1234},
// 	}, {
// 		name: "badLinks",
// 		fields: fields{
// 			id:       uint32(23),
// 			parent:   uint32(22),
// 			badLinks: []uint32{445, 1232244},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageCertifyBad: true},
// 		want:         []uint32{22, 445, 1232244},
// 	}, {
// 		name: "goodLinks",
// 		fields: fields{
// 			id:        uint32(23),
// 			parent:    uint32(22),
// 			goodLinks: []uint32{987, 9876},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackageCertifyGood: true},
// 		want:         []uint32{22, 987, 9876},
// 	}, {
// 		name: "pkgEquals",
// 		fields: fields{
// 			id:        uint32(23),
// 			parent:    uint32(22),
// 			pkgEquals: []uint32{987, 9876},
// 		},
// 		allowedEdges: edgeMap{model.EdgePackagePkgEqual: true},
// 		want:         []uint32{22, 987, 9876},
// 	}}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			n := &pkgVersionNode{
// 				id:                tt.fields.id,
// 				parent:            tt.fields.parent,
// 				srcMapLinks:       tt.fields.srcMapLinks,
// 				isDependencyLinks: tt.fields.isDependencyLinks,
// 				occurrences:       tt.fields.occurrences,
// 				certifyVulnLinks:  tt.fields.certifyVulnLinks,
// 				hasSBOMs:          tt.fields.hasSBOMs,
// 				vexLinks:          tt.fields.vexLinks,
// 				badLinks:          tt.fields.badLinks,
// 				goodLinks:         tt.fields.goodLinks,
// 				pkgEquals:         tt.fields.pkgEquals,
// 			}
// 			if got := n.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("pkgVersionNode.Neighbors() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

func Test_Packages(t *testing.T) {
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
		pkgInput   *model.PkgInputSpec
		pkgFilter  *model.PkgSpec
		idInFilter bool
		want       []*model.Package
		wantErr    bool
	}{{
		name:     "tensorflow empty version",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P1out},
		wantErr:    false,
	}, {
		name:     "tensorflow empty version, ID search",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: true,
		want:       []*model.Package{testdata.P1out},
		wantErr:    false,
	}, {
		name:     "tensorflow with version",
		pkgInput: testdata.P2,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Version: ptrfrom.String("2.11.1"),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P2out},
		wantErr:    false,
	}, {
		name:     "tensorflow with version and subpath",
		pkgInput: testdata.P3,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Subpath: ptrfrom.String("saved_model_cli.py"),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P3out},
		wantErr:    false,
	}, {
		name:     "openssl with version",
		pkgInput: testdata.P4,
		pkgFilter: &model.PkgSpec{
			Name:      ptrfrom.String("openssl"),
			Namespace: ptrfrom.String("openssl.org"),
			Version:   ptrfrom.String("3.0.3"),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P4out},
		wantErr:    false,
	}, {
		name:     "openssl with match empty qualifiers",
		pkgInput: testdata.P4,
		pkgFilter: &model.PkgSpec{
			Name:                     ptrfrom.String("openssl"),
			Namespace:                ptrfrom.String("openssl.org"),
			Version:                  ptrfrom.String("3.0.3"),
			MatchOnlyEmptyQualifiers: ptrfrom.Bool(true),
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P4out},
		wantErr:    false,
	}, {
		name:     "openssl with qualifier",
		pkgInput: testdata.P5,
		pkgFilter: &model.PkgSpec{
			Name:      ptrfrom.String("openssl"),
			Namespace: ptrfrom.String("openssl.org"),
			Version:   ptrfrom.String("3.0.3"),
			Qualifiers: []*model.PackageQualifierSpec{{
				Key:   "test",
				Value: ptrfrom.String("test"),
			}},
		},
		idInFilter: false,
		want:       []*model.Package{testdata.P5out},
		wantErr:    false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkg, err := b.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.pkgFilter.ID = &ingestedPkg.Namespaces[0].Names[0].Versions[0].ID
			}
			got, err := b.Packages(ctx, tt.pkgFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.Packages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessPkg)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_PackageTypes(t *testing.T) {
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
		pkgInput   *model.PkgInputSpec
		pkgFilter  *model.PkgSpec
		idInFilter bool
		want       []*model.Package
		wantErr    bool
	}{{
		name:     "tensorflow empty version",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type:       "pypi",
			Namespaces: []*model.PackageNamespace{},
		}},
		wantErr: false,
	}, {
		name:     "tensorflow empty version, ID search",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: true,
		want: []*model.Package{{
			Type:       "pypi",
			Namespaces: []*model.PackageNamespace{},
		}},
		wantErr: false,
	}, {
		name:     "tensorflow with version",
		pkgInput: testdata.P2,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Version: ptrfrom.String("2.11.1"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type:       "pypi",
			Namespaces: []*model.PackageNamespace{},
		}},
		wantErr: false,
	}, {
		name:     "tensorflow with version and subpath",
		pkgInput: testdata.P3,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Subpath: ptrfrom.String("saved_model_cli.py"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type:       "pypi",
			Namespaces: []*model.PackageNamespace{},
		}},
		wantErr: false,
	}, {
		name:     "openssl with version",
		pkgInput: testdata.P4,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("conan"),
			Name:    ptrfrom.String("openssl"),
			Version: ptrfrom.String("3.0.3"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type:       "conan",
			Namespaces: []*model.PackageNamespace{},
		}},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkg, err := b.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.pkgFilter.ID = &ingestedPkg.Namespaces[0].Names[0].Versions[0].ID
			}
			got, err := b.(*arangoClient).packagesType(ctx, tt.pkgFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.packagesType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_PackagesNamespace(t *testing.T) {
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
		pkgInput   *model.PkgInputSpec
		pkgFilter  *model.PkgSpec
		idInFilter bool
		want       []*model.Package
		wantErr    bool
	}{{
		name:     "tensorflow empty version",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type:       "pypi",
			Namespaces: []*model.PackageNamespace{{Names: []*model.PackageName{}}},
		}},
		wantErr: false,
	}, {
		name:     "tensorflow empty version, ID search",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: true,
		want: []*model.Package{{
			Type:       "pypi",
			Namespaces: []*model.PackageNamespace{{Names: []*model.PackageName{}}},
		}},
		wantErr: false,
	}, {
		name:     "tensorflow with version",
		pkgInput: testdata.P2,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Version: ptrfrom.String("2.11.1"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type:       "pypi",
			Namespaces: []*model.PackageNamespace{{Names: []*model.PackageName{}}},
		}},
		wantErr: false,
	}, {
		name:     "tensorflow with version and subpath",
		pkgInput: testdata.P3,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Subpath: ptrfrom.String("saved_model_cli.py"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type:       "pypi",
			Namespaces: []*model.PackageNamespace{{Names: []*model.PackageName{}}},
		}},
		wantErr: false,
	}, {
		name:     "openssl with version",
		pkgInput: testdata.P4,
		pkgFilter: &model.PkgSpec{
			Type:      ptrfrom.String("conan"),
			Name:      ptrfrom.String("openssl"),
			Namespace: ptrfrom.String("openssl.org"),
			Version:   ptrfrom.String("3.0.3"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type: "conan",
			Namespaces: []*model.PackageNamespace{{
				Namespace: "openssl.org",
				Names:     []*model.PackageName{},
			}},
		}},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkg, err := b.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.pkgFilter.ID = &ingestedPkg.Namespaces[0].Names[0].Versions[0].ID
			}
			got, err := b.(*arangoClient).packagesNamespace(ctx, tt.pkgFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.packagesNamespace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_PackagesName(t *testing.T) {
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
		pkgInput   *model.PkgInputSpec
		pkgFilter  *model.PkgSpec
		idInFilter bool
		want       []*model.Package
		wantErr    bool
	}{{
		name:     "tensorflow empty version",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type: "pypi",
			Namespaces: []*model.PackageNamespace{{
				Names: []*model.PackageName{
					{Name: "tensorflow", Versions: []*model.PackageVersion{}},
				},
			}},
		}},
		wantErr: false,
	}, {
		name:     "tensorflow empty version, ID search",
		pkgInput: testdata.P1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: true,
		want: []*model.Package{{
			Type: "pypi",
			Namespaces: []*model.PackageNamespace{{
				Names: []*model.PackageName{
					{Name: "tensorflow", Versions: []*model.PackageVersion{}},
				},
			}},
		}},
		wantErr: false,
	}, {
		name:     "tensorflow with version",
		pkgInput: testdata.P2,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Version: ptrfrom.String("2.11.1"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type: "pypi",
			Namespaces: []*model.PackageNamespace{{
				Names: []*model.PackageName{
					{Name: "tensorflow", Versions: []*model.PackageVersion{}},
				},
			}},
		}},
		wantErr: false,
	}, {
		name:     "tensorflow with version and subpath",
		pkgInput: testdata.P3,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Subpath: ptrfrom.String("saved_model_cli.py"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type: "pypi",
			Namespaces: []*model.PackageNamespace{{
				Names: []*model.PackageName{
					{Name: "tensorflow", Versions: []*model.PackageVersion{}},
				},
			}},
		}},
		wantErr: false,
	}, {
		name:     "openssl with version",
		pkgInput: testdata.P4,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("conan"),
			Name:    ptrfrom.String("openssl"),
			Version: ptrfrom.String("3.0.3"),
		},
		idInFilter: false,
		want: []*model.Package{{
			Type: "conan",
			Namespaces: []*model.PackageNamespace{{
				Namespace: "openssl.org",
				Names: []*model.PackageName{
					{Name: "openssl", Versions: []*model.PackageVersion{}},
				},
			}},
		}},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkg, err := b.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.pkgFilter.ID = &ingestedPkg.Namespaces[0].Names[0].Versions[0].ID
			}
			got, err := b.(*arangoClient).packagesName(ctx, tt.pkgFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.packagesName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessPkg)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func lessPkg(a, b *model.Package) bool {
	return a.Namespaces[0].Names[0].Name < b.Namespaces[0].Names[0].Name
}

func Test_IngestPackages(t *testing.T) {
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
		pkgInputs []*model.PkgInputSpec
		want      []*model.Package
		wantErr   bool
	}{{
		name:      "tensorflow empty version",
		pkgInputs: []*model.PkgInputSpec{testdata.P3, testdata.P4},
		want:      []*model.Package{testdata.P4out, testdata.P3out},
		wantErr:   false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := b.IngestPackages(ctx, tt.pkgInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestPackages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessPkg)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildPackageResponseFromID(t *testing.T) {
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
		pkgInput   *model.PkgInputSpec
		pkgFilter  *model.PkgSpec
		idInFilter bool
		want       *model.Package
		wantErr    bool
	}{{
		name:     "tensorflow empty version, ID search",
		pkgInput: testdata.P3,
		pkgFilter: &model.PkgSpec{
			Name:    ptrfrom.String("tensorflow"),
			Subpath: ptrfrom.String("saved_model_cli.py"),
		},
		idInFilter: true,
		want:       testdata.P3out,
		wantErr:    false,
	}, {
		name:     "openssl with match empty qualifiers",
		pkgInput: testdata.P4,
		pkgFilter: &model.PkgSpec{
			Name:                     ptrfrom.String("openssl"),
			Namespace:                ptrfrom.String("openssl.org"),
			Version:                  ptrfrom.String("3.0.3"),
			MatchOnlyEmptyQualifiers: ptrfrom.Bool(true),
		},
		idInFilter: true,
		want:       testdata.P4out,
		wantErr:    false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingestedPkg, err := b.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := b.(*arangoClient).buildPackageResponseFromID(ctx, ingestedPkg.Namespaces[0].Names[0].Versions[0].ID, tt.pkgFilter)
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
