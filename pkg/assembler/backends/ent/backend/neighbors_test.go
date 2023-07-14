package backend

import "github.com/google/go-cmp/cmp"

func (s *Suite) TestNode() {
	be, err := GetBackend(s.Client)
	s.Require().NoError(err)

	v, err := be.IngestArtifact(s.Ctx, a1)
	s.Require().NoError(err)

	p, err := be.IngestPackage(s.Ctx, *p1)
	s.Require().NoError(err)

	n, err := be.Node(s.Ctx, v.ID)
	s.Require().NoError(err)

	if diff := cmp.Diff(a1out, n, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}

	n, err = be.Node(s.Ctx, p.ID)
	s.Require().NoError(err)

	if diff := cmp.Diff(p1out, n, ignoreID, ignoreEmptySlices); diff != "" {
		s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
	}
}
