package backend

// Usually this would be part of ent, but the import cycle doesn't allow for it.

import (
	"testing"

	"github.com/guacsec/guac/pkg/assembler/backends/ent/testutils"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/stretchr/testify/suite"
)

type Suite struct {
	testutils.Suite
}

func TestEntBackendSuite(t *testing.T) {
	suite.Run(t, new(Suite))
}

func (s *Suite) TestCreateSoftwareTree() {
	be, err := GetBackend(s.Client)
	s.NoError(err)

	// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
	pkg, err := be.IngestPackage(s.Ctx, model.PkgInputSpec{
		Type:      "apk",
		Namespace: ptr("alpine"),
		Name:      "apk",
		Version:   ptr("2.12.9-r3"),
		Subpath:   nil,
		Qualifiers: []*model.PackageQualifierInputSpec{
			{Key: "arch", Value: "x86"},
		},
	})
	s.NoError(err)
	s.NotNil(pkg)
	s.Equal("apk", pkg.Type)

	if s.Len(pkg.Namespaces, 1) {
		s.Equal("alpine", pkg.Namespaces[0].Namespace)

		if s.Len(pkg.Namespaces[0].Names, 1) {
			s.Equal("apk", pkg.Namespaces[0].Names[0].Name)

			if s.Len(pkg.Namespaces[0].Names[0].Versions, 1) {
				s.Equal("2.12.9-r3", pkg.Namespaces[0].Names[0].Versions[0].Version)
			}
		}
	}

	// Ingest a second time should only create a new version
	pkg, err = be.IngestPackage(s.Ctx, model.PkgInputSpec{
		Type:      "apk",
		Namespace: ptr("alpine"),
		Name:      "apk",
		Version:   ptr("2.12.10"),
		Subpath:   nil,
		Qualifiers: []*model.PackageQualifierInputSpec{
			{Key: "arch", Value: "x86"},
		},
	})
	// Ensure that we don't get a duplicate row error
	s.NoError(err)
	s.NotNil(pkg)

	if s.Len(pkg.Namespaces, 1) {
		s.Equal("alpine", pkg.Namespaces[0].Namespace)

		if s.Len(pkg.Namespaces[0].Names, 1) {
			s.Equal("apk", pkg.Namespaces[0].Names[0].Name)

			if s.Len(pkg.Namespaces[0].Names[0].Versions, 1) {
				s.Equal("2.12.10", pkg.Namespaces[0].Names[0].Versions[0].Version)
			}
		}
	}
}

func (s *Suite) TestVersionUpsertsWithQualifiers() {
	be, err := GetBackend(s.Client)
	s.NoError(err)

	// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
	pkg1, err := be.IngestPackage(s.Ctx, model.PkgInputSpec{
		Type:       "apk",
		Namespace:  ptr("alpine"),
		Name:       "apk",
		Version:    ptr("2.12.9-r3"),
		Subpath:    nil,
		Qualifiers: []*model.PackageQualifierInputSpec{{Key: "arch", Value: "x86"}},
	})
	s.NoError(err)
	s.NotNil(pkg1)

	// pkg:apk/alpine/apk@2.12.9-r3?arch=arm64
	spec2 := model.PkgInputSpec{
		Type:       "apk",
		Namespace:  ptr("alpine"),
		Name:       "apk",
		Version:    ptr("2.12.9-r3"),
		Subpath:    nil,
		Qualifiers: []*model.PackageQualifierInputSpec{{Key: "arch", Value: "arm64"}},
	}

	pkg2, err := be.IngestPackage(s.Ctx, spec2)
	s.NoError(err)
	s.NotNil(pkg2)
}

func (s *Suite) TestIngestOccurrence_Package() {
	be, err := GetBackend(s.Client)
	s.NoError(err)

	_, err = be.IngestPackage(s.Ctx, *p1)
	s.NoError(err)

	_, err = be.IngestArtifact(s.Ctx, &model.ArtifactInputSpec{
		Algorithm: "sha256", Digest: "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
	})
	s.NoError(err)

	// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
	oc, err := be.IngestOccurrence(s.Ctx,
		model.PackageOrSourceInput{
			Package: p1,
		},
		model.ArtifactInputSpec{
			Algorithm: "sha256", Digest: "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		},
		model.IsOccurrenceInputSpec{
			Justification: "this artifact is an occurrence of this openssl",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	)
	s.NoError(err)
	s.NotNil(oc)
}
