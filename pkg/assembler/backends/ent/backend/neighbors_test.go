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
	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestNode() {
	ctx := s.Ctx
	tests := []struct {
		Name     string
		InArt    []*model.ArtifactInputSpec
		InPkg    []*model.PkgInputSpec
		InSrc    []*model.SourceInputSpec
		InBld    []*model.BuilderInputSpec
		Expected []interface{}
		Only     bool
	}{
		{
			Name:  "Ingest Artifact",
			InArt: []*model.ArtifactInputSpec{a1},
			InPkg: []*model.PkgInputSpec{p4},
			InSrc: []*model.SourceInputSpec{s1},
			InBld: []*model.BuilderInputSpec{b1},
			Expected: []interface{}{
				a1out,
				p4out,
				s1out,
				b1out,
			},
		},
	}
	hasOnly := false
	for _, t := range tests {
		if t.Only {
			hasOnly = true
			break
		}
	}

	for _, test := range tests {
		if hasOnly && !test.Only {
			continue
		}

		s.Run(test.Name, func() {
			b, err := GetBackend(s.Client)
			s.Require().NoError(err, "Could not instantiate testing backend")

			ids := make([]string, 0, len(test.Expected))
			for _, inA := range test.InArt {
				if a, err := b.IngestArtifactID(ctx, inA); err != nil {
					s.T().Fatalf("Could not ingest artifact: %v", err)
				} else {
					ids = append(ids, a)
				}
			}

			for _, inP := range test.InPkg {
				if id, err := b.IngestPackageID(ctx, *inP); err != nil {
					s.T().Fatalf("Could not ingest package: %v", err)
				} else {
					ids = append(ids, id)
				}
			}

			for _, inSrc := range test.InSrc {
				if id, err := b.IngestSourceID(ctx, *inSrc); err != nil {
					s.T().Fatalf("Could not ingest source: %v", err)
				} else {
					ids = append(ids, id)
				}
			}

			for _, inBLD := range test.InBld {
				if id, err := b.IngestBuilderID(ctx, inBLD); err != nil {
					s.T().Fatalf("Could not ingest builder: %v", err)
				} else {
					ids = append(ids, id)
				}
			}

			for i, id := range ids {
				n, err := b.Node(s.Ctx, id)
				s.Require().NoError(err)
				if diff := cmp.Diff(test.Expected[i], n, ignoreID, ignoreEmptySlices); diff != "" {
					s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func (s *Suite) TestNodes() {
	s.Run("HappyPath", func() {
		be, err := GetBackend(s.Client)
		s.Require().NoError(err)

		v, err := be.IngestArtifactID(s.Ctx, a1)
		s.Require().NoError(err)

		id, err := be.IngestPackageID(s.Ctx, *p4)
		s.Require().NoError(err)

		pkgs, err := be.Packages(s.Ctx, &model.PkgSpec{ID: &id})
		s.Require().NoError(err)
		p := pkgs[0]

		nodes, err := be.Nodes(s.Ctx, []string{v, p.ID, p.Namespaces[0].Names[0].Versions[0].ID})
		s.Require().NoError(err)
		if diff := cmp.Diff(a1out, nodes[0], ignoreID, ignoreEmptySlices); diff != "" {
			s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(p4outNamespace, nodes[1], ignoreID, ignoreEmptySlices); diff != "" {
			s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(p4out, nodes[2], ignoreID, ignoreEmptySlices); diff != "" {
			s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
		}
	})
}
