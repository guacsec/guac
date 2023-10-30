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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/stretchr/testify/assert"
)

func TestHashPackageVersions(t *testing.T) {
	tests := []struct {
		name     string
		pkg      model.PkgInputSpec
		expected string
	}{
		{
			name:     "With empty qualifiers",
			pkg:      model.PkgInputSpec{Version: ptr("1.0.0"), Subpath: ptr("subpath"), Qualifiers: []*model.PackageQualifierInputSpec{}},
			expected: "2f2b07de87ca7c566f419c7dd81afbc7be0d1bfe",
		},
		{
			name:     "With nil qualifiers",
			pkg:      model.PkgInputSpec{Version: ptr("1.0.0"), Subpath: ptr("subpath"), Qualifiers: nil},
			expected: "2f2b07de87ca7c566f419c7dd81afbc7be0d1bfe",
		},
		{
			name: "With qualifiers",
			pkg: model.PkgInputSpec{Version: ptr("1.0.0"), Subpath: ptr("subpath"), Qualifiers: []*model.PackageQualifierInputSpec{
				{Key: "arch", Value: "arm64"},
				{Key: "tag", Value: "foo"},
			}},
			expected: "38315cfad2f3b9a267ad75a564dda639f1e1c768",
		},
		{
			name: "With qualifiers reverse order",
			pkg: model.PkgInputSpec{Version: ptr("1.0.0"), Subpath: ptr("subpath"), Qualifiers: []*model.PackageQualifierInputSpec{
				{Key: "tag", Value: "foo"},
				{Key: "arch", Value: "arm64"},
			}},
			expected: "38315cfad2f3b9a267ad75a564dda639f1e1c768",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := versionHashFromInputSpec(test.pkg)
			assert.Equal(t, test.expected, result)
		})
	}
}

func (s *Suite) Test_get_package_helpers() {
	p1Spec := model.PkgInputSpec{
		Type:      "apk",
		Namespace: ptr("test"),
		Name:      "alpine",
		Version:   ptr("1.0.0"),
		Subpath:   ptr("subpath"),
		Qualifiers: []*model.PackageQualifierInputSpec{
			{Key: "arch", Value: "arm64"},
			{Key: "a", Value: "b"},
		},
	}
	p2Spec := model.PkgInputSpec{
		Type:      "apk",
		Namespace: ptr("test"),
		Name:      "alpine",
		Version:   ptr("1.0.0"),
		Subpath:   ptr("subpath"),
	}

	_, err := WithinTX(s.Ctx, s.Client, func(ctx context.Context) (*ent.PackageVersion, error) {
		return upsertPackage(s.Ctx, ent.TxFromContext(ctx), p2Spec)
	})
	s.Require().NoError(err)
	pkgVersionID, err := WithinTX(s.Ctx, s.Client, func(ctx context.Context) (*ent.PackageVersion, error) {
		return upsertPackage(s.Ctx, ent.TxFromContext(ctx), p1Spec)
	})
	s.Require().NoError(err)
	s.Require().NotNil(pkgVersionID)

	s.Run("getPkgName", func() {
		pkgName, err := getPkgName(s.Ctx, s.Client, model.PkgInputSpec{
			Type:      "apk",
			Namespace: ptr("test"),
			Name:      "alpine",
		})
		s.Require().NoError(err)
		s.Require().NotNil(pkgName)
		s.Equal("alpine", pkgName.Name)
	})

	s.Run("getPkgVersion", func() {
		pkgVersion, err := getPkgVersion(s.Ctx, s.Client, p1Spec)
		s.Require().NoError(err)
		s.Require().NotNil(pkgVersion)
	})

	s.Run("pkgTreeFromVersion", func() {
		pkgVersion, err := getPkgVersion(s.Ctx, s.Client, p1Spec)
		s.Require().NoError(err)
		pkgTree, err := pkgTreeFromVersion(s.Ctx, pkgVersion)
		s.Require().NoError(err)
		s.Require().NotNil(pkgTree)
		if s.Len(pkgTree.Edges.Namespaces, 1) {
			if s.Len(pkgTree.Edges.Namespaces[0].Edges.Names, 1) {
				if s.Len(pkgTree.Edges.Namespaces[0].Edges.Names[0].Edges.Versions, 1) {
					s.Equal("1.0.0", pkgTree.Edges.Namespaces[0].Edges.Names[0].Edges.Versions[0].Version)
				}
			}
		}
	})
}

func (s *Suite) TestEmptyQualifiersPredicate() {
	spec := model.PkgInputSpec{
		Type:      "apk",
		Namespace: ptr("test"),
		Name:      "alpine",
		Version:   ptr("1.0.0"),
		Subpath:   ptr("subpath"),
		Qualifiers: []*model.PackageQualifierInputSpec{
			{Key: "arch", Value: "arm64"},
			{Key: "a", Value: "b"},
		},
	}

	pkg, err := WithinTX(s.Ctx, s.Client, func(ctx context.Context) (*ent.PackageVersion, error) {
		return upsertPackage(s.Ctx, ent.TxFromContext(ctx), spec)
	})
	s.Require().NoError(err)
	s.Require().NotNil(pkg)

	// Ingest twice to ensure upserts are working
	pkg, err = WithinTX(s.Ctx, s.Client, func(ctx context.Context) (*ent.PackageVersion, error) {
		return upsertPackage(s.Ctx, ent.TxFromContext(ctx), spec)
	})
	s.Require().NoError(err)
	s.Require().NotNil(pkg)

	s.Run("Empty keys", func() {
		s.Empty(s.Client.PackageVersion.Query().Where(packageversion.QualifiersIsEmpty()).AllX(s.Ctx))
	})

	s.Run("No Qualifiers", func() {
		spec.Qualifiers = nil
		pkg, err := WithinTX(s.Ctx, s.Client, func(ctx context.Context) (*ent.PackageVersion, error) {
			return upsertPackage(s.Ctx, ent.TxFromContext(ctx), spec)
		})
		s.Require().NoError(err)
		s.Require().NotNil(pkg)

		s.Len(s.Client.PackageVersion.Query().Where(packageversion.QualifiersIsEmpty()).AllX(s.Ctx), 1)
	})

	s.Run("Single key", func() {
		versions := s.Client.PackageVersion.Query().Where(packageversion.QualifiersWithKeys("arch", "a")).AllX(s.Ctx)
		s.NotEmpty(versions)
	})

	s.Run("Multiple keys", func() {
		versions := s.Client.PackageVersion.Query().Where(packageversion.QualifiersContains("arch", "arm64")).AllX(s.Ctx)
		s.NotEmpty(versions)
	})

	s.Run("Using spec - Null value", func() {
		versions := s.Client.PackageVersion.Query().Where(
			packageversion.QualifiersMatch([]*model.PackageQualifierSpec{{Key: "arch"}}, false),
		).AllX(s.Ctx)
		s.NotEmpty(versions)
	})

	s.Run("Using spec - Multiple", func() {
		versions := s.Client.PackageVersion.Query().Where(
			packageversion.QualifiersMatch([]*model.PackageQualifierSpec{
				{Key: "arch"},
				{Key: "a", Value: ptr("b")},
			}, false),
		).AllX(s.Ctx)
		s.NotEmpty(versions)
	})

}

func (s *Suite) Test_IngestPackages() {
	ctx := s.Ctx
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
	}}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			c, err := GetBackend(s.Client)
			s.NoError(err)

			got, err := c.IngestPackages(ctx, tt.pkgInputs)
			if (err != nil) != tt.wantErr {
				s.T().Errorf("demoClient.IngestPackages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, IngestPredicatesCmpOpts...); diff != "" {
				s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) Test_Packages() {
	ctx := s.Ctx
	tests := []struct {
		name       string
		pkgInput   *model.PkgInputSpec
		pkgFilter  *model.PkgSpec
		idInFilter bool
		want       []*model.Package
		wantErr    bool
	}{
		{
			name:     "tensorflow empty version",
			pkgInput: p1,
			pkgFilter: &model.PkgSpec{
				Name: ptrfrom.String("tensorflow"),
			},
			want: []*model.Package{p1out},
		},
		{
			name:     "tensorflow empty version, ID search",
			pkgInput: p1,
			pkgFilter: &model.PkgSpec{
				Name: ptrfrom.String("tensorflow"),
			},
			idInFilter: true,
			want:       []*model.Package{p1out},
		},
		{
			name:     "tensorflow with version",
			pkgInput: p2,
			pkgFilter: &model.PkgSpec{
				Type: ptrfrom.String("pypi"),
				Name: ptrfrom.String("tensorflow"),
			},
			want: []*model.Package{p2out},
		},
		{
			name:     "tensorflow with version and subpath",
			pkgInput: p3,
			pkgFilter: &model.PkgSpec{
				Type:    ptrfrom.String("pypi"),
				Name:    ptrfrom.String("tensorflow"),
				Subpath: ptrfrom.String("saved_model_cli.py"),
			},
			want: []*model.Package{p3out},
		},
		{
			name:     "tensorflow with version and subpath but query without subpath",
			pkgInput: p3,
			pkgFilter: &model.PkgSpec{
				Type: ptrfrom.String("pypi"),
				Name: ptrfrom.String("tensorflow"),
			},
			want: []*model.Package{p3out},
		},
		{
			name:     "tensorflow without subpath",
			pkgInput: p2,
			pkgFilter: &model.PkgSpec{
				Type:    ptrfrom.String("pypi"),
				Name:    ptrfrom.String("tensorflow"),
				Subpath: ptrfrom.String(""),
			},
			want: []*model.Package{p2out},
		},
		{
			name:     "openssl with version",
			pkgInput: p4,
			pkgFilter: &model.PkgSpec{
				Name:    ptrfrom.String("openssl"),
				Version: ptrfrom.String("3.0.3"),
			},
			want: []*model.Package{p4out},
		}}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			be, err := GetBackend(s.Client)
			s.NoError(err)
			ingestedPkg, err := be.IngestPackage(ctx, *tt.pkgInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter && ingestedPkg != nil {
				tt.pkgFilter.ID = &ingestedPkg.Namespaces[0].Names[0].Versions[0].ID
			}
			got, err := be.Packages(ctx, tt.pkgFilter)
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
