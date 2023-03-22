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

package testing

import (
	"context"
	"errors"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal data: link that a package/source/artifact is bad
type badList []*badLink
type badLink struct {
	id            uint32
	packageID     uint32
	artifactID    uint32
	sourceID      uint32
	justification string
	origin        string
	collector     string
}

func (n *badLink) getID() uint32 { return n.id }

func (n *badLink) neighbors() []uint32 {
	out := make([]uint32, 0, 1)
	if n.packageID != 0 {
		out = append(out, n.packageID)
	}
	if n.artifactID != 0 {
		out = append(out, n.artifactID)
	}
	if n.sourceID != 0 {
		out = append(out, n.sourceID)
	}
	return out
}

func (n *badLink) buildModelNode(c *demoClient) (model.Node, error) {
	return c.buildCertifyBad(n, nil, true)
}

// Ingest CertifyBad
func (c *demoClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {
	err := helper.ValidatePackageSourceOrArtifactInput(&subject, "bad subject")
	if err != nil {
		return nil, err
	}

	var packageID uint32
	var artifactID uint32
	var sourceID uint32
	searchIDs := []uint32{}
	if subject.Package != nil {
		packageID, err = getPackageIDFromInput(c, *subject.Package, *pkgMatchType)
		if err != nil {
			return nil, err
		}
		foundPkgNameorVersionNode, ok := c.index[packageID].(pkgNameOrVersion)
		if ok {
			searchIDs = append(searchIDs, foundPkgNameorVersionNode.getCertifyBadLinks()...)
		}
	} else if subject.Artifact != nil {
		artifactID, err = getArtifactIDFromInput(c, *subject.Artifact)
		if err != nil {
			return nil, err
		}
		foundArtStrct, ok := c.index[artifactID].(*artStruct)
		if ok {
			searchIDs = append(searchIDs, foundArtStrct.badLinks...)
		}
	} else {
		sourceID, err = getSourceIDFromInput(c, *subject.Source)
		if err != nil {
			return nil, err
		}
		srcName, ok := c.index[sourceID].(*srcNameNode)
		if ok {
			searchIDs = append(searchIDs, srcName.badLinks...)
		}
	}

	// Don't insert duplicates
	duplicate := false
	collectedCertifyBadLink := badLink{}
	for _, id := range searchIDs {
		v, _ := c.badLinkByID(id)
		subjectMatch := false
		if packageID != 0 && packageID == v.packageID {
			subjectMatch = true
		}
		if artifactID != 0 && artifactID == v.artifactID {
			subjectMatch = true
		}
		if sourceID != 0 && sourceID == v.sourceID {
			subjectMatch = true
		}
		if subjectMatch && certifyBad.Justification == v.justification &&
			certifyBad.Origin == v.origin && certifyBad.Collector == v.collector {

			collectedCertifyBadLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		// store the link
		collectedCertifyBadLink = badLink{
			id:            c.getNextID(),
			packageID:     packageID,
			artifactID:    artifactID,
			sourceID:      sourceID,
			justification: certifyBad.Justification,
			origin:        certifyBad.Origin,
			collector:     certifyBad.Collector,
		}
		c.index[collectedCertifyBadLink.id] = &collectedCertifyBadLink
		c.certifyBads = append(c.certifyBads, &collectedCertifyBadLink)
		// set the backlinks
		if packageID != 0 {
			c.index[packageID].(pkgNameOrVersion).setCertifyBadLinks(collectedCertifyBadLink.id)
		}
		if artifactID != 0 {
			c.index[artifactID].(*artStruct).setCertifyBadLinks(collectedCertifyBadLink.id)
		}
		if sourceID != 0 {
			c.index[sourceID].(*srcNameNode).setCertifyBadLinks(collectedCertifyBadLink.id)
		}

	}

	// build return GraphQL type
	builtCertifyBad, err := c.buildCertifyBad(&collectedCertifyBadLink, nil, true)
	if err != nil {
		return nil, err
	}
	return builtCertifyBad, nil
}

// Query CertifyBad
func (c *demoClient) CertifyBad(ctx context.Context, filter *model.CertifyBadSpec) ([]*model.CertifyBad, error) {

	err := helper.ValidatePackageSourceOrArtifactQueryFilter(filter.Subject)
	if err != nil {
		return nil, err
	}
	out := []*model.CertifyBad{}

	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		node, ok := c.index[uint32(id)]
		if !ok {
			return nil, gqlerror.Errorf("ID does not match existing node")
		}
		if link, ok := node.(*badLink); ok {
			foundCertifyBad, err := c.buildCertifyBad(link, filter, true)
			if err != nil {
				return nil, err
			}
			return []*model.CertifyBad{foundCertifyBad}, nil
		} else {
			return nil, gqlerror.Errorf("ID does not match expected node type for certifyBad")
		}
	}

	// TODO if any of the pkg/source/artifact are specified, ony search those backedges
	for _, link := range c.certifyBads {
		if filter != nil && noMatch(filter.Justification, link.justification) {
			continue
		}
		if filter != nil && noMatch(filter.Collector, link.collector) {
			continue
		}
		if filter != nil && noMatch(filter.Origin, link.origin) {
			continue
		}

		foundCertifyBad, err := c.buildCertifyBad(link, filter, false)
		if err != nil {
			return nil, err
		}
		if foundCertifyBad == nil {
			continue
		}
		out = append(out, foundCertifyBad)
	}

	return out, nil
}

func (c *demoClient) buildCertifyBad(link *badLink, filter *model.CertifyBadSpec, ingestOrIDProvided bool) (*model.CertifyBad, error) {
	var p *model.Package
	var a *model.Artifact
	var s *model.Source
	var err error
	if filter != nil && filter.Subject != nil {
		if filter.Subject.Package != nil && link.packageID != 0 {
			p, err = c.buildPackageResponse(link.packageID, filter.Subject.Package)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Artifact != nil && link.artifactID != 0 {
			a, err = c.buildArtifactResponse(link.artifactID, filter.Subject.Artifact)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Source != nil && link.sourceID != 0 {
			s, err = c.buildSourceResponse(link.sourceID, filter.Subject.Source)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.packageID != 0 {
			p, err = c.buildPackageResponse(link.packageID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.artifactID != 0 {
			a, err = c.buildArtifactResponse(link.artifactID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.sourceID != 0 {
			s, err = c.buildSourceResponse(link.sourceID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	var subj model.PackageSourceOrArtifact
	if link.packageID != 0 {
		if p == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve package via packageID")
		} else if p == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = p
	}
	if link.artifactID != 0 {
		if a == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve artifact via artifactID")
		} else if a == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = a
	}
	if link.sourceID != 0 {
		if s == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve source via sourceID")
		} else if s == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = s
	}

	certifyBad := model.CertifyBad{
		ID:            nodeID(link.id),
		Subject:       subj,
		Justification: link.justification,
		Origin:        link.origin,
		Collector:     link.collector,
	}
	return &certifyBad, nil
}

func (c *demoClient) badLinkByID(id uint32) (*badLink, error) {
	node, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find badLink")
	}
	link, ok := node.(*badLink)
	if !ok {
		return nil, errors.New("not an badLink")
	}
	return link, nil
}
