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

package backend

import (
	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) Test_FindSoftware() {
	b, err := GetBackend(s.Client)
	s.NoError(err)

	for _, p := range []*model.PkgInputSpec{p1, p2, p3} {
		if _, err := b.IngestPackage(s.Ctx, *p); err != nil {
			s.NoError(err)
		}
	}

	for _, src := range []*model.SourceInputSpec{s1, s2} {
		if _, err := b.IngestSource(s.Ctx, *src); err != nil {
			s.NoError(err)
		}
	}

	for _, art := range []*model.ArtifactInputSpec{a1} {
		if _, err := b.IngestArtifact(s.Ctx, art); err != nil {
			s.NoError(err)
		}
	}

	// Find a package
	results, err := b.FindSoftware(s.Ctx, "tensor")
	s.NoError(err)

	if diff := cmp.Diff([]model.PackageSourceOrArtifact{p1out, p2out, p3out}, results, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}

	// Find a source
	results, err = b.FindSoftware(s.Ctx, "bobs")
	s.NoError(err)

	if diff := cmp.Diff([]model.PackageSourceOrArtifact{s2out}, results, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}

	// Find an artifact
	results, err = b.FindSoftware(s.Ctx, "6bbb0da")
	s.NoError(err)

	if diff := cmp.Diff([]model.PackageSourceOrArtifact{a1out}, results, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}

	// Find with empty query
	results, err = b.FindSoftware(s.Ctx, "")
	s.NoError(err)

	if diff := cmp.Diff([]model.PackageSourceOrArtifact{}, results, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}
}
