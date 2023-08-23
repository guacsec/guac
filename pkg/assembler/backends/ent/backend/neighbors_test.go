package backend

import (
	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestNode() {
	be, err := GetBackend(s.Client)
	s.Require().NoError(err)

	v, err := be.IngestArtifact(s.Ctx, a1)
	check(s, be, v.ID, err, a1out)

	p, err := be.IngestPackage(s.Ctx, *p4)
	check(s, be, p.ID, err, p4outNamespace)
	check(s, be, p.Namespaces[0].ID, err, p4out)
	check(s, be, p.Namespaces[0].Names[0].ID, err, p4out)
	check(s, be, p.Namespaces[0].Names[0].Versions[0].ID, err, p4out)

	sc, err := be.IngestSource(s.Ctx, *s1)
	check(s, be, sc.ID, err, s1outNamespace)

	bu, err := be.IngestBuilder(s.Ctx, b1)
	check(s, be, bu.ID, err, b1out)

	osv, err := be.IngestOsv(s.Ctx, o1)
	check(s, be, osv.ID, err, o1out)

	c, err := be.IngestCve(s.Ctx, c1)
	check(s, be, c.ID, err, c1out)

	g, err := be.IngestGhsa(s.Ctx, g1)
	check(s, be, g.ID, err, g1out)
}

func (s *Suite) TestNodeNew() {
	ctx := s.Ctx
	tests := []struct {
		Name     string
		InArt    []*model.ArtifactInputSpec
		InPkg    []*model.PkgInputSpec
		InSrc    []*model.SourceInputSpec
		Expected []interface{}
		Only     bool
	}{
		{
			Name:  "Ingest Artifact",
			InArt: []*model.ArtifactInputSpec{a1},
			InPkg: []*model.PkgInputSpec{p4},
			InSrc: []*model.SourceInputSpec{s1},
			Expected: []interface{}{
				a1out,
				p4outNamespace,
				s1outNamespace,
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
				if a, err := b.IngestArtifact(ctx, inA); err != nil {
					s.T().Fatalf("Could not ingest artifact: %v", err)
				} else {
					ids = append(ids, a.ID)
				}
			}

			for _, inP := range test.InPkg {
				if p, err := b.IngestPackage(ctx, *inP); err != nil {
					s.T().Fatalf("Could not ingest package: %v", err)
				} else {
					ids = append(ids, p.ID)
				}
			}

			for _, inSrc := range test.InSrc {
				if src, err := b.IngestSource(ctx, *inSrc); err != nil {
					s.T().Fatalf("Could not ingest source: %v", err)
				} else {
					ids = append(ids, src.ID)
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
	be, err := GetBackend(s.Client)
	s.Require().NoError(err)

	v, err := be.IngestArtifact(s.Ctx, a1)
	s.Require().NoError(err)

	p, err := be.IngestPackage(s.Ctx, *p4)
	s.Require().NoError(err)

	nodes, err := be.Nodes(s.Ctx, []string{v.ID, p.ID, p.Namespaces[0].Names[0].Versions[0].ID})
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
}

func check(s *Suite, be backends.Backend, id string, err error, expected interface{}) {
	s.Require().NoError(err)
	n, err := be.Node(s.Ctx, id)
	s.Require().NoError(err)
	if diff := cmp.Diff(expected, n, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}
}
