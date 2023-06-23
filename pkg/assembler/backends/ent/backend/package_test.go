package backend

import (
	"testing"

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

func (s *Suite) Test_getPkgName() {
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

	pkgVersionID, err := upsertPackage(s.Ctx, s.Client, spec)
	s.Require().NoError(err)
	s.Require().NotNil(pkgVersionID)

	pkgName, err := getPkgName(s.Ctx, s.Client, &model.PkgInputSpec{
		Type:      "apk",
		Namespace: ptr("test"),
		Name:      "alpine",
	})
	s.Require().NoError(err)
	s.Require().NotNil(pkgName)
	s.Equal("alpine", pkgName.Name)

	s.Require().Equal(1, s.Client.PackageVersion.Query().Where(packageversion.ID(pkgVersionID)).CountX(s.Ctx))

	pkgVersion, err := getPkgVersion(s.Ctx, s.Client.Debug(), &spec)
	s.Require().NoError(err)
	s.Require().NotNil(pkgVersion)
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

	pkg, err := upsertPackage(s.Ctx, s.Client, spec)
	s.Require().NoError(err)
	s.Require().NotNil(pkg)

	// Ingest twice to ensure upserts are working
	pkg, err = upsertPackage(s.Ctx, s.Client, spec)
	s.Require().NoError(err)
	s.Require().NotNil(pkg)

	s.Run("Empty keys", func() {
		s.Empty(s.Client.PackageVersion.Query().Where(packageversion.QualifiersIsEmpty()).AllX(s.Ctx))
	})

	s.Run("No Qualifiers", func() {
		spec.Qualifiers = nil
		pkg, err = upsertPackage(s.Ctx, s.Client, spec)
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
			packageversion.QualifiersMatchSpec([]*model.PackageQualifierSpec{{Key: "arch"}}),
		).AllX(s.Ctx)
		s.NotEmpty(versions)
	})

	s.Run("Using spec - Multiple", func() {
		versions := s.Client.PackageVersion.Query().Where(
			packageversion.QualifiersMatchSpec([]*model.PackageQualifierSpec{
				{Key: "arch"},
				{Key: "a", Value: ptr("b")},
			}),
		).AllX(s.Ctx)
		s.NotEmpty(versions)
	})

}
