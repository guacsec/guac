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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_pkgNamespaceStruct_ID(t *testing.T) {
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
			n := &pkgNamespaceStruct{
				id: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgNamespaceStruct.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgNameStruct_ID(t *testing.T) {
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
			n := &pkgNameStruct{
				id: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgNameStruct.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersionStruct_ID(t *testing.T) {
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
			n := &pkgVersionStruct{
				id: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgVersionStruct.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersionNode_ID(t *testing.T) {
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
			n := &pkgVersionNode{
				id: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgVersionNode.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgNamespaceStruct_Neighbors(t *testing.T) {
	type fields struct {
		id         uint32
		namespaces pkgNamespaceMap
	}
	tests := []struct {
		name   string
		fields fields
		want   []uint32
	}{{
		name: "pkgNamespaceStruct Neighbors",
		fields: fields{
			id:         uint32(23),
			namespaces: pkgNamespaceMap{"test": &pkgNameStruct{id: uint32(24)}},
		},
		want: []uint32{uint32(24)},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgNamespaceStruct{
				id:         tt.fields.id,
				namespaces: tt.fields.namespaces,
			}
			if got := n.Neighbors(edgeMap{
				model.EdgePackageTypePackageNamespace: true,
			}); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgNamespaceStruct.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgNameStruct_Neighbors(t *testing.T) {
	type fields struct {
		id        uint32
		parent    uint32
		namespace string
		names     pkgNameMap
	}
	tests := []struct {
		name   string
		fields fields
		want   []uint32
	}{{
		name: "pkgNameStruct Neighbors",
		fields: fields{
			id:        uint32(23),
			parent:    uint32(22),
			namespace: "test",
			names:     pkgNameMap{"test": &pkgVersionStruct{id: uint32(24)}},
		},
		want: []uint32{uint32(24), uint32(22)},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgNameStruct{
				id:        tt.fields.id,
				parent:    tt.fields.parent,
				namespace: tt.fields.namespace,
				names:     tt.fields.names,
			}
			if got := n.Neighbors(edgeMap{
				model.EdgePackageNamespacePackageType: true,
				model.EdgePackageNamespacePackageName: true,
			}); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgNameStruct.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersionStruct_Neighbors(t *testing.T) {
	type fields struct {
		id                uint32
		parent            uint32
		versions          pkgVersionMap
		srcMapLinks       []uint32
		isDependencyLinks []uint32
		badLinks          []uint32
		goodLinks         []uint32
	}
	tests := []struct {
		name         string
		allowedEdges edgeMap
		fields       fields
		want         []uint32
	}{{
		name: "packageNamespace",
		fields: fields{
			id:          uint32(23),
			parent:      uint32(22),
			versions:    pkgVersionMap{"digest-a": &pkgVersionNode{id: uint32(24)}},
			srcMapLinks: []uint32{343, 546},
		},
		allowedEdges: edgeMap{model.EdgePackageNamePackageNamespace: true},
		want:         []uint32{22},
	}, {
		name: "packageVersion",
		fields: fields{
			id:          uint32(23),
			parent:      uint32(22),
			versions:    pkgVersionMap{"digest-a": &pkgVersionNode{id: uint32(24)}},
			srcMapLinks: []uint32{343, 546},
		},
		allowedEdges: edgeMap{model.EdgePackageNamePackageVersion: true},
		want:         []uint32{24},
	}, {
		name: "srcMapLinks",
		fields: fields{
			id:          uint32(23),
			parent:      uint32(22),
			versions:    pkgVersionMap{"digest-a": &pkgVersionNode{id: uint32(24)}},
			srcMapLinks: []uint32{343, 546},
		},
		allowedEdges: edgeMap{model.EdgePackageHasSourceAt: true},
		want:         []uint32{343, 546},
	}, {
		name: "isDependencyLinks",
		fields: fields{
			id:                uint32(23),
			parent:            uint32(22),
			versions:          pkgVersionMap{"digest-a": &pkgVersionNode{id: uint32(24)}},
			isDependencyLinks: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageIsDependency: true},
		want:         []uint32{2324, 1234},
	}, {
		name: "badLinks",
		fields: fields{
			id:       uint32(23),
			parent:   uint32(22),
			versions: pkgVersionMap{"digest-a": &pkgVersionNode{id: uint32(24)}},
			badLinks: []uint32{445, 1232244},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyBad: true},
		want:         []uint32{445, 1232244},
	}, {
		name: "goodLinks",
		fields: fields{
			id:        uint32(23),
			parent:    uint32(22),
			versions:  pkgVersionMap{"digest-a": &pkgVersionNode{id: uint32(24)}},
			goodLinks: []uint32{987, 9876},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyGood: true},
		want:         []uint32{987, 9876},
	}, {
		name: "goodLinks",
		fields: fields{
			id:        uint32(23),
			parent:    uint32(22),
			versions:  pkgVersionMap{"digest-a": &pkgVersionNode{id: uint32(24)}},
			goodLinks: []uint32{987, 9876},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyGood: true},
		want:         []uint32{987, 9876},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgVersionStruct{
				id:                tt.fields.id,
				parent:            tt.fields.parent,
				versions:          tt.fields.versions,
				srcMapLinks:       tt.fields.srcMapLinks,
				isDependencyLinks: tt.fields.isDependencyLinks,
				badLinks:          tt.fields.badLinks,
				goodLinks:         tt.fields.goodLinks,
			}
			if got := n.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgVersionStruct.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersionNode_Neighbors(t *testing.T) {
	type fields struct {
		id                uint32
		parent            uint32
		srcMapLinks       []uint32
		isDependencyLinks []uint32
		occurrences       []uint32
		certifyVulnLinks  []uint32
		hasSBOMs          []uint32
		vexLinks          []uint32
		badLinks          []uint32
		goodLinks         []uint32
		pkgEquals         []uint32
	}
	tests := []struct {
		name         string
		allowedEdges edgeMap
		fields       fields
		want         []uint32
	}{{
		name: "packageName",
		fields: fields{
			id:          uint32(23),
			parent:      uint32(22),
			srcMapLinks: []uint32{343, 546},
		},
		allowedEdges: edgeMap{model.EdgePackageVersionPackageName: true},
		want:         []uint32{22},
	}, {
		name: "srcMapLinks",
		fields: fields{
			id:          uint32(23),
			parent:      uint32(22),
			srcMapLinks: []uint32{343, 546},
		},
		allowedEdges: edgeMap{model.EdgePackageHasSourceAt: true},
		want:         []uint32{343, 546},
	}, {
		name: "isDependencyLinks",
		fields: fields{
			id:                uint32(23),
			parent:            uint32(22),
			isDependencyLinks: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageIsDependency: true},
		want:         []uint32{2324, 1234},
	}, {
		name: "occurrences",
		fields: fields{
			id:          uint32(23),
			parent:      uint32(22),
			occurrences: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageIsOccurrence: true},
		want:         []uint32{2324, 1234},
	}, {
		name: "certifyVulnLinks",
		fields: fields{
			id:               uint32(23),
			parent:           uint32(22),
			certifyVulnLinks: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyVuln: true},
		want:         []uint32{2324, 1234},
	}, {
		name: "hasSBOMs",
		fields: fields{
			id:       uint32(23),
			parent:   uint32(22),
			hasSBOMs: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageHasSbom: true},
		want:         []uint32{2324, 1234},
	}, {
		name: "vexLinks",
		fields: fields{
			id:       uint32(23),
			parent:   uint32(22),
			vexLinks: []uint32{2324, 1234},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyVexStatement: true},
		want:         []uint32{2324, 1234},
	}, {
		name: "badLinks",
		fields: fields{
			id:       uint32(23),
			parent:   uint32(22),
			badLinks: []uint32{445, 1232244},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyBad: true},
		want:         []uint32{445, 1232244},
	}, {
		name: "goodLinks",
		fields: fields{
			id:        uint32(23),
			parent:    uint32(22),
			goodLinks: []uint32{987, 9876},
		},
		allowedEdges: edgeMap{model.EdgePackageCertifyGood: true},
		want:         []uint32{987, 9876},
	}, {
		name: "pkgEquals",
		fields: fields{
			id:        uint32(23),
			parent:    uint32(22),
			pkgEquals: []uint32{987, 9876},
		},
		allowedEdges: edgeMap{model.EdgePackagePkgEqual: true},
		want:         []uint32{987, 9876},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgVersionNode{
				id:                tt.fields.id,
				parent:            tt.fields.parent,
				srcMapLinks:       tt.fields.srcMapLinks,
				isDependencyLinks: tt.fields.isDependencyLinks,
				occurrences:       tt.fields.occurrences,
				certifyVulnLinks:  tt.fields.certifyVulnLinks,
				hasSBOMs:          tt.fields.hasSBOMs,
				vexLinks:          tt.fields.vexLinks,
				badLinks:          tt.fields.badLinks,
				goodLinks:         tt.fields.goodLinks,
				pkgEquals:         tt.fields.pkgEquals,
			}
			if got := n.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgVersionNode.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

var p1 = &model.PkgInputSpec{
	Type: "pypi",
	Name: "tensorflow",
}
var p1out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{{
				Version:    "",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var p2 = &model.PkgInputSpec{
	Type:    "pypi",
	Name:    "tensorflow",
	Version: ptrfrom.String("2.11.1"),
}
var p2out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{{
				Version:    "2.11.1",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var p3 = &model.PkgInputSpec{
	Type:    "pypi",
	Name:    "tensorflow",
	Version: ptrfrom.String("2.11.1"),
	Subpath: ptrfrom.String("saved_model_cli.py"),
}
var p3out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{{
				Version:    "2.11.1",
				Subpath:    "saved_model_cli.py",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var p4 = &model.PkgInputSpec{
	Type:      "conan",
	Namespace: ptrfrom.String("openssl.org"),
	Name:      "openssl",
	Version:   ptrfrom.String("3.0.3"),
}
var p4out = &model.Package{
	Type: "conan",
	Namespaces: []*model.PackageNamespace{{
		Namespace: "openssl.org",
		Names: []*model.PackageName{{
			Name: "openssl",
			Versions: []*model.PackageVersion{{
				Version:    "3.0.3",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

func Test_demoClient_Packages(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		pkgInput   *model.PkgInputSpec
		pkgFilter  *model.PkgSpec
		idInFilter bool
		want       []*model.Package
		wantErr    bool
	}{{
		name:     "tensorflow empty version",
		pkgInput: p1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: false,
		want:       []*model.Package{p1out},
		wantErr:    false,
	}, {
		name:     "tensorflow empty version, ID search",
		pkgInput: p1,
		pkgFilter: &model.PkgSpec{
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: true,
		want:       []*model.Package{p1out},
		wantErr:    false,
	}, {
		name:     "tensorflow with version",
		pkgInput: p2,
		pkgFilter: &model.PkgSpec{
			Type: ptrfrom.String("pypi"),
			Name: ptrfrom.String("tensorflow"),
		},
		idInFilter: false,
		want:       []*model.Package{p2out},
		wantErr:    false,
	}, {
		name:     "tensorflow with version and subpath",
		pkgInput: p3,
		pkgFilter: &model.PkgSpec{
			Type:    ptrfrom.String("pypi"),
			Name:    ptrfrom.String("tensorflow"),
			Subpath: ptrfrom.String("saved_model_cli.py"),
		},
		idInFilter: false,
		want:       []*model.Package{p3out},
		wantErr:    false,
	}, {
		name:     "openssl with version",
		pkgInput: p4,
		pkgFilter: &model.PkgSpec{
			Name:    ptrfrom.String("openssl"),
			Version: ptrfrom.String("3.0.3"),
		},
		idInFilter: false,
		want:       []*model.Package{p4out},
		wantErr:    false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &demoClient{
				packages: pkgTypeMap{},
				index:    indexType{},
			}
			ingestedPkg, err := c.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.pkgFilter.ID = &ingestedPkg.Namespaces[0].Names[0].Versions[0].ID
			}
			got, err := c.Packages(ctx, tt.pkgFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.Packages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_demoClient_IngestPackages(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		pkgInputs []*model.PkgInputSpec
		want      []*model.Package
		wantErr   bool
	}{{
		name:      "tensorflow empty version",
		pkgInputs: []*model.PkgInputSpec{p1, p2, p3, p4},
		want:      []*model.Package{p1out, p2out, p3out, p4out},
		wantErr:   false,
	},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &demoClient{
				packages: pkgTypeMap{},
				index:    indexType{},
			}
			got, err := c.IngestPackages(ctx, tt.pkgInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestPackages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

var pp5out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{
				{
					Version:    "2.11.1",
					Qualifiers: []*model.PackageQualifier{},
				},
				{
					Version:    "2.11.3",
					Qualifiers: []*model.PackageQualifier{},
				},
			},
		}},
	}},
}
var pp6out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{
				{
					Version:    "2.11.1",
					Qualifiers: []*model.PackageQualifier{},
					Subpath:    "a",
				},
				{
					Version:    "2.11.1",
					Qualifiers: []*model.PackageQualifier{},
					Subpath:    "b",
				},
			},
		}},
	}},
}
var pp7out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{
				{
					Version:    "2.11.1",
					Qualifiers: []*model.PackageQualifier{{Key: "1", Value: "2"}},
				},
				{
					Version:    "2.11.1",
					Qualifiers: []*model.PackageQualifier{{Key: "a", Value: "b"}, {Key: "c", Value: "d"}},
				},
			},
		}},
	}},
}
var pp8out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{
				{
					Version:    "2.11.1",
					Qualifiers: []*model.PackageQualifier{{Key: "a", Value: "b"}},
				},
			},
		}},
	}},
}

var p9out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{
				{
					Version:    "",
					Qualifiers: []*model.PackageQualifier{},
				},
			},
		}},
	}},
}

var p10out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{
				{
					Version:    "2.11.1",
					Qualifiers: []*model.PackageQualifier{},
				},
				{
					Version:    "",
					Qualifiers: []*model.PackageQualifier{},
				},
			},
		}},
	}},
}

func Test_IngestingVersions(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		pkgInputs []*model.PkgInputSpec
		want      []*model.Package
	}{
		{
			name: "package name without version",
			pkgInputs: []*model.PkgInputSpec{
				{
					Type: "pypi",
					Name: "tensorflow",
				},
			},
			want: []*model.Package{p9out},
		},
		{
			name: "package names with and without version",
			pkgInputs: []*model.PkgInputSpec{
				{
					Type:    "pypi",
					Name:    "tensorflow",
					Version: ptrfrom.String("2.11.1"),
				},
				{
					Type: "pypi",
					Name: "tensorflow",
				},
			},
			want: []*model.Package{p10out},
		},
		{
			name: "different versions are not considered duplicates ",
			pkgInputs: []*model.PkgInputSpec{
				{
					Type:    "pypi",
					Name:    "tensorflow",
					Version: ptrfrom.String("2.11.1"),
				},
				{
					Type:    "pypi",
					Name:    "tensorflow",
					Version: ptrfrom.String("2.11.3"),
				},
			},
			want: []*model.Package{pp5out},
		},
		{
			name: "version nodes with different subpaths are not considered duplicates ",
			pkgInputs: []*model.PkgInputSpec{
				{
					Type:    "pypi",
					Name:    "tensorflow",
					Version: ptrfrom.String("2.11.1"),
					Subpath: ptrfrom.String("a"),
				},
				{
					Type:    "pypi",
					Name:    "tensorflow",
					Version: ptrfrom.String("2.11.1"),
					Subpath: ptrfrom.String("b"),
				},
			},
			want: []*model.Package{pp6out},
		},
		{
			name: "version nodes with different qualifiers are not considered duplicates ",
			pkgInputs: []*model.PkgInputSpec{
				{
					Type:       "pypi",
					Name:       "tensorflow",
					Version:    ptrfrom.String("2.11.1"),
					Qualifiers: []*model.PackageQualifierInputSpec{{Key: "1", Value: "2"}},
				},
				{
					Type:       "pypi",
					Name:       "tensorflow",
					Version:    ptrfrom.String("2.11.1"),
					Qualifiers: []*model.PackageQualifierInputSpec{{Key: "a", Value: "b"}, {Key: "c", Value: "d"}},
				},
			},
			want: []*model.Package{pp7out},
		},
		{
			name:      "a single package is created from duplicate version nodes (just with versions)",
			pkgInputs: []*model.PkgInputSpec{p2, p2},
			want:      []*model.Package{p2out},
		},
		{
			name:      "a single package is created from duplicate version nodes with (versions and subpaths)",
			pkgInputs: []*model.PkgInputSpec{p3, p3},
			want:      []*model.Package{p3out},
		},
		{
			name: "a single package is created from duplicate version nodes (with versions, subpaths, and qualifiers)",
			pkgInputs: []*model.PkgInputSpec{
				{
					Type:       "pypi",
					Name:       "tensorflow",
					Version:    ptrfrom.String("2.11.1"),
					Qualifiers: []*model.PackageQualifierInputSpec{{Key: "a", Value: "b"}},
				},
				{
					Type:       "pypi",
					Name:       "tensorflow",
					Version:    ptrfrom.String("2.11.1"),
					Qualifiers: []*model.PackageQualifierInputSpec{{Key: "a", Value: "b"}},
				},
			},
			want: []*model.Package{pp8out},
		},
	}

	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &demoClient{
				packages: pkgTypeMap{},
				index:    indexType{},
			}
			_, err := c.IngestPackages(ctx, tt.pkgInputs)
			if err != nil {
				t.Errorf("Unexpected demoClient.IngestPackages() error = %v, ", err)
				return
			}
			packages, err := c.Packages(ctx, nil)
			if err != nil {
				t.Errorf("Unexpected demoClient.Packages() error = %v, ", err)
				return
			}

			MakeCanonicalPackageSlice(packages)
			MakeCanonicalPackageSlice(tt.want)

			if diff := cmp.Diff(tt.want, packages, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}

}
