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
	s.Run("HappyPath", func() {
		be, err := GetBackend(s.Client)
		s.NoError(err)

		// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
		id, err2 := be.IngestPackage(s.Ctx, model.PkgInputSpec{
			Type:      "apk",
			Namespace: ptr("alpine"),
			Name:      "apk",
			Version:   ptr("2.12.9-r3"),
			Subpath:   nil,
			Qualifiers: []*model.PackageQualifierInputSpec{
				{Key: "arch", Value: "x86"},
			},
		})
		s.NoError(err2)
		pkgs, err3 := be.Packages(s.Ctx, &model.PkgSpec{ID: &id.PackageVersionID})
		s.NoError(err3)
		pkg := pkgs[0]
		s.NoError(err3)
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
		id, err2 = be.IngestPackage(s.Ctx, model.PkgInputSpec{
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
		s.NoError(err2)

		pkgs, err = be.Packages(s.Ctx, &model.PkgSpec{ID: &id.PackageVersionID})
		s.NoError(err)
		pkg = pkgs[0]
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
	})
}

func (s *Suite) TestVersionUpsertsWithQualifiers() {
	s.Run("HappyPath", func() {
		be, err := GetBackend(s.Client)
		s.NoError(err)

		// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
		id, err2 := be.IngestPackage(s.Ctx, model.PkgInputSpec{
			Type:       "apk",
			Namespace:  ptr("alpine"),
			Name:       "apk",
			Version:    ptr("2.12.9-r3"),
			Subpath:    nil,
			Qualifiers: []*model.PackageQualifierInputSpec{{Key: "arch", Value: "x86"}},
		})
		s.NoError(err2)
		pkgs, err3 := be.Packages(s.Ctx, &model.PkgSpec{ID: &id.PackageVersionID})
		pkg1 := pkgs[0]
		s.NoError(err3)
		s.NotNil(pkg1)
		s.Equal("", pkg1.Namespaces[0].Names[0].Versions[0].Subpath)

		// pkg:apk/alpine/apk@2.12.9-r3?arch=arm64
		spec2 := model.PkgInputSpec{
			Type:       "apk",
			Namespace:  ptr("alpine"),
			Name:       "apk",
			Version:    ptr("2.12.9-r3"),
			Subpath:    nil,
			Qualifiers: []*model.PackageQualifierInputSpec{{Key: "arch", Value: "arm64"}},
		}

		id2, err4 := be.IngestPackage(s.Ctx, spec2)
		s.NoError(err4)
		pkgs, err3 = be.Packages(s.Ctx, &model.PkgSpec{ID: &id2.PackageVersionID})
		s.NoError(err3)
		pkg2 := pkgs[0]
		s.NotNil(pkg2)
	})
}

func (s *Suite) TestIngestOccurrence_Package() {
	s.Run("HappyPath", func() {
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
	})
}
