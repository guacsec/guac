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

package keyvalue

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_pkgType_ID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{{
		name: "getID",
		id:   "643",
		want: "643",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgType{
				ThisID: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgType.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgNamespace_ID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{{
		name: "getID",
		id:   "643",
		want: "643",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgNamespace{
				ThisID: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgNamespace.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgName_ID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{{
		name: "getID",
		id:   "643",
		want: "643",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgName{
				ThisID: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgName.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersion_ID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{{
		name: "getID",
		id:   "643",
		want: "643",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgVersion{
				ThisID: tt.id,
			}
			if got := n.ID(); got != tt.want {
				t.Errorf("pkgVersion.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_PkgType_Neighbors(t *testing.T) {
	type fields struct {
		id         string
		namespaces []string
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{{
		name: "PkgType Neighbors",
		fields: fields{
			id:         "23",
			namespaces: []string{"24"},
		},
		want: []string{"24"},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgType{
				ThisID:     tt.fields.id,
				Namespaces: tt.fields.namespaces,
			}
			if got := n.Neighbors(edgeMap{
				model.EdgePackageTypePackageNamespace: true,
			}); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PkgType.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgNamespace_Neighbors(t *testing.T) {
	type fields struct {
		id        string
		parent    string
		namespace string
		names     []string
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{{
		name: "pkgNamespace Neighbors",
		fields: fields{
			id:        "23",
			parent:    "22",
			namespace: "test",
			names:     []string{"24"},
		},
		want: []string{"24", "22"},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgNamespace{
				ThisID:    tt.fields.id,
				Parent:    tt.fields.parent,
				Namespace: tt.fields.namespace,
				Names:     tt.fields.names,
			}
			if got := n.Neighbors(edgeMap{
				model.EdgePackageNamespacePackageType: true,
				model.EdgePackageNamespacePackageName: true,
			}); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgNamespace.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgName_Neighbors(t *testing.T) {
	type fields struct {
		id                string
		parent            string
		versions          []string
		srcMapLinks       []string
		isDependencyLinks []string
		badLinks          []string
		goodLinks         []string
	}
	tests := []struct {
		name         string
		allowedEdges edgeMap
		fields       fields
		want         []string
	}{
		{
			name: "packageNamespace",
			fields: fields{
				id:          "23",
				parent:      "22",
				versions:    []string{"24"},
				srcMapLinks: []string{"343", "546"},
			},
			allowedEdges: edgeMap{model.EdgePackageNamePackageNamespace: true},
			want:         []string{"22"},
		},
		{
			name: "packageVersion",
			fields: fields{
				id:          "23",
				parent:      "22",
				versions:    []string{"24"},
				srcMapLinks: []string{"343", "546"},
			},
			allowedEdges: edgeMap{model.EdgePackageNamePackageVersion: true},
			want:         []string{"24"},
		},
		{
			name: "srcMapLinks",
			fields: fields{
				id:          "23",
				parent:      "22",
				versions:    []string{"24"},
				srcMapLinks: []string{"343", "546"},
			},
			allowedEdges: edgeMap{model.EdgePackageHasSourceAt: true},
			want:         []string{"343", "546"},
		},
		{
			name: "isDependencyLinks",
			fields: fields{
				id:                "23",
				parent:            "22",
				versions:          []string{"24"},
				isDependencyLinks: []string{"2324", "1234"},
			},
			allowedEdges: edgeMap{model.EdgePackageIsDependency: true},
			want:         []string{"2324", "1234"},
		},
		{
			name: "badLinks",
			fields: fields{
				id:       "23",
				parent:   "22",
				versions: []string{"24"},
				badLinks: []string{"445", "1232244"},
			},
			allowedEdges: edgeMap{model.EdgePackageCertifyBad: true},
			want:         []string{"445", "1232244"},
		},
		{
			name: "goodLinks",
			fields: fields{
				id:        "23",
				parent:    "22",
				versions:  []string{"24"},
				goodLinks: []string{"987", "9876"},
			},
			allowedEdges: edgeMap{model.EdgePackageCertifyGood: true},
			want:         []string{"987", "9876"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgName{
				ThisID:            tt.fields.id,
				Parent:            tt.fields.parent,
				Versions:          tt.fields.versions,
				SrcMapLinks:       tt.fields.srcMapLinks,
				IsDependencyLinks: tt.fields.isDependencyLinks,
				BadLinks:          tt.fields.badLinks,
				GoodLinks:         tt.fields.goodLinks,
			}
			if got := n.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgName.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkgVersion_Neighbors(t *testing.T) {
	type fields struct {
		id                string
		parent            string
		srcMapLinks       []string
		isDependencyLinks []string
		occurrences       []string
		certifyVulnLinks  []string
		hasSBOMs          []string
		vexLinks          []string
		badLinks          []string
		goodLinks         []string
		pkgEquals         []string
	}
	tests := []struct {
		name         string
		allowedEdges edgeMap
		fields       fields
		want         []string
	}{
		{
			name: "packageName",
			fields: fields{
				id:          "23",
				parent:      "22",
				srcMapLinks: []string{"343", "546"},
			},
			allowedEdges: edgeMap{model.EdgePackageVersionPackageName: true},
			want:         []string{"22"},
		},
		{
			name: "srcMapLinks",
			fields: fields{
				id:          "23",
				parent:      "22",
				srcMapLinks: []string{"343", "546"},
			},
			allowedEdges: edgeMap{model.EdgePackageHasSourceAt: true},
			want:         []string{"343", "546"},
		},
		{
			name: "isDependencyLinks",
			fields: fields{
				id:                "23",
				parent:            "22",
				isDependencyLinks: []string{"2324", "1234"},
			},
			allowedEdges: edgeMap{model.EdgePackageIsDependency: true},
			want:         []string{"2324", "1234"},
		},
		{
			name: "occurrences",
			fields: fields{
				id:          "23",
				parent:      "22",
				occurrences: []string{"2324", "1234"},
			},
			allowedEdges: edgeMap{model.EdgePackageIsOccurrence: true},
			want:         []string{"2324", "1234"},
		},
		{
			name: "certifyVulnLinks",
			fields: fields{
				id:               "23",
				parent:           "22",
				certifyVulnLinks: []string{"2324", "1234"},
			},
			allowedEdges: edgeMap{model.EdgePackageCertifyVuln: true},
			want:         []string{"2324", "1234"},
		},
		{
			name: "hasSBOMs",
			fields: fields{
				id:       "23",
				parent:   "22",
				hasSBOMs: []string{"2324", "1234"},
			},
			allowedEdges: edgeMap{model.EdgePackageHasSbom: true},
			want:         []string{"2324", "1234"},
		},
		{
			name: "vexLinks",
			fields: fields{
				id:       "23",
				parent:   "22",
				vexLinks: []string{"2324", "1234"},
			},
			allowedEdges: edgeMap{model.EdgePackageCertifyVexStatement: true},
			want:         []string{"2324", "1234"},
		},
		{
			name: "badLinks",
			fields: fields{
				id:       "23",
				parent:   "22",
				badLinks: []string{"445", "1232244"},
			},
			allowedEdges: edgeMap{model.EdgePackageCertifyBad: true},
			want:         []string{"445", "1232244"},
		},
		{
			name: "goodLinks",
			fields: fields{
				id:        "23",
				parent:    "22",
				goodLinks: []string{"987", "9876"},
			},
			allowedEdges: edgeMap{model.EdgePackageCertifyGood: true},
			want:         []string{"987", "9876"},
		},
		{
			name: "pkgEquals",
			fields: fields{
				id:        "23",
				parent:    "22",
				pkgEquals: []string{"987", "9876"},
			},
			allowedEdges: edgeMap{model.EdgePackagePkgEqual: true},
			want:         []string{"987", "9876"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &pkgVersion{
				ThisID:            tt.fields.id,
				Parent:            tt.fields.parent,
				SrcMapLinks:       tt.fields.srcMapLinks,
				IsDependencyLinks: tt.fields.isDependencyLinks,
				Occurrences:       tt.fields.occurrences,
				CertifyVulnLinks:  tt.fields.certifyVulnLinks,
				HasSBOMs:          tt.fields.hasSBOMs,
				VexLinks:          tt.fields.vexLinks,
				BadLinks:          tt.fields.badLinks,
				GoodLinks:         tt.fields.goodLinks,
				PkgEquals:         tt.fields.pkgEquals,
			}
			if got := n.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkgVersion.Neighbors() = %v, want %v", got, tt.want)
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
			c, _ := getBackend(ctx, nil)
			ingestedPkg, err := c.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.pkgFilter.ID = &ingestedPkg.PackageVersionID
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
		wantErr   bool
	}{
		{
			name:      "tensorflow empty version",
			pkgInputs: []*model.PkgInputSpec{p1, p2, p3, p4},
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := getBackend(ctx, nil)
			_, err := c.IngestPackages(ctx, tt.pkgInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestPackages() error = %v, wantErr %v", err, tt.wantErr)
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
			c, _ := getBackend(ctx, nil)
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
