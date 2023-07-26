package backend

import (
	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/pkg/assembler/backends"
)

func (s *Suite) TestNode() {
	be, err := GetBackend(s.Client)
	s.Require().NoError(err)

	v, err := be.IngestArtifact(s.Ctx, a1)
	check(s, be, v.ID, err, a1out)

	p, err := be.IngestPackage(s.Ctx, *p1)
	check(s, be, p.ID, err, p1out)
	check(s, be, p.Namespaces[0].ID, err, p1out)
	check(s, be, p.Namespaces[0].Names[0].ID, err, p1out)
	check(s, be, p.Namespaces[0].Names[0].Versions[0].ID, err, p1out)

	sc, err := be.IngestSource(s.Ctx, *s1)
	check(s, be, sc.ID, err, s1out)

	bu, err := be.IngestBuilder(s.Ctx, b1)
	check(s, be, bu.ID, err, b1out)

	osv, err := be.IngestOsv(s.Ctx, o1)
	check(s, be, osv.ID, err, o1out)

	c, err := be.IngestCve(s.Ctx, c1)
	check(s, be, c.ID, err, c1out)

	g, err := be.IngestGhsa(s.Ctx, g1)
	check(s, be, g.ID, err, g1out)
}

func (s *Suite) TestNodes() {
	be, err := GetBackend(s.Client)
	s.Require().NoError(err)

	v, err := be.IngestArtifact(s.Ctx, a1)
	s.Require().NoError(err)

	p, err := be.IngestPackage(s.Ctx, *p1)
	s.Require().NoError(err)

	nodes, err := be.Nodes(s.Ctx, []string{v.ID, p.ID, p.Namespaces[0].Names[0].Versions[0].ID})
	s.Require().NoError(err)
	if diff := cmp.Diff(a1out, nodes[0], ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(p1out, nodes[1], ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(p1out, nodes[2], ignoreID, ignoreEmptySlices); diff != "" {
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
