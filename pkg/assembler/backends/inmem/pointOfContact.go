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

package inmem

import (
	"context"
	"strconv"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: link that a package/source/artifact is good
type pointOfContactList []*pointOfContactLink
type pointOfContactLink struct {
	id            uint32
	packageID     uint32
	artifactID    uint32
	sourceID      uint32
	email         string
	info          string
	since         time.Time
	justification string
	origin        string
	collector     string
}

func (n *pointOfContactLink) ID() uint32 { return n.id }

func (n *pointOfContactLink) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 1)
	if n.packageID != 0 && allowedEdges[model.EdgePointOfContactPackage] {
		out = append(out, n.packageID)
	}
	if n.artifactID != 0 && allowedEdges[model.EdgePointOfContactArtifact] {
		out = append(out, n.artifactID)
	}
	if n.sourceID != 0 && allowedEdges[model.EdgePointOfContactSource] {
		out = append(out, n.sourceID)
	}
	return out
}

func (n *pointOfContactLink) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildPointOfContact(n, nil, true)
}

// Ingest PointOfContact

func (c *demoClient) IngestPointOfContacts(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, pointOfContacts []*model.PointOfContactInputSpec) ([]string, error) {
	var modelPointOfContactIDs []string

	for i := range pointOfContacts {
		var pointOfContact *model.PointOfContact
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageSourceOrArtifactInput{Package: subjects.Packages[i]}
			pointOfContact, err = c.IngestPointOfContact(ctx, subject, pkgMatchType, *pointOfContacts[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestPointOfContact failed with err: %v", err)
			}
		} else if len(subjects.Sources) > 0 {
			subject := model.PackageSourceOrArtifactInput{Source: subjects.Sources[i]}
			pointOfContact, err = c.IngestPointOfContact(ctx, subject, pkgMatchType, *pointOfContacts[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestPointOfContact failed with err: %v", err)
			}
		} else {
			subject := model.PackageSourceOrArtifactInput{Artifact: subjects.Artifacts[i]}
			pointOfContact, err = c.IngestPointOfContact(ctx, subject, pkgMatchType, *pointOfContacts[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestPointOfContact failed with err: %v", err)
			}
		}
		modelPointOfContactIDs = append(modelPointOfContactIDs, pointOfContact.ID)
	}
	return modelPointOfContactIDs, nil
}

func (c *demoClient) IngestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec) (*model.PointOfContact, error) {
	return c.ingestPointOfContact(ctx, subject, pkgMatchType, pointOfContact, true)
}

func (c *demoClient) ingestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec, readOnly bool) (*model.PointOfContact, error) {
	funcName := "IngestPointOfContact"

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var packageID uint32
	var foundPkgNameorVersionNode pkgNameOrVersion
	var artifactID uint32
	var foundArtStrct *artStruct
	var sourceID uint32
	var srcName *srcNameNode
	searchIDs := []uint32{}
	if subject.Package != nil {
		var err error
		packageID, err = getPackageIDFromInput(c, *subject.Package, *pkgMatchType)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundPkgNameorVersionNode, err = byID[pkgNameOrVersion](packageID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		searchIDs = append(searchIDs, foundPkgNameorVersionNode.getPointOfContactLinks()...)
	} else if subject.Artifact != nil {
		var err error
		artifactID, err = getArtifactIDFromInput(c, *subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundArtStrct, err = byID[*artStruct](artifactID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		searchIDs = append(searchIDs, foundArtStrct.pointOfContactLinks...)
	} else {
		var err error
		sourceID, err = getSourceIDFromInput(c, *subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		srcName, err = byID[*srcNameNode](sourceID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		searchIDs = append(searchIDs, srcName.pointOfContactLinks...)
	}

	// Don't insert duplicates
	duplicate := false
	collectedLink := pointOfContactLink{}
	for _, id := range searchIDs {
		v, err := byID[*pointOfContactLink](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
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
		if subjectMatch && pointOfContact.Justification == v.justification &&
			pointOfContact.Email == v.email && pointOfContact.Info == v.info &&
			pointOfContact.Since.Equal(v.since) &&
			pointOfContact.Origin == v.origin && pointOfContact.Collector == v.collector {

			collectedLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			b, err := c.ingestPointOfContact(ctx, subject, pkgMatchType, pointOfContact, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return b, err
		}
		// store the link
		collectedLink = pointOfContactLink{
			id:            c.getNextID(),
			packageID:     packageID,
			artifactID:    artifactID,
			sourceID:      sourceID,
			email:         pointOfContact.Email,
			info:          pointOfContact.Info,
			since:         pointOfContact.Since,
			justification: pointOfContact.Justification,
			origin:        pointOfContact.Origin,
			collector:     pointOfContact.Collector,
		}
		c.index[collectedLink.id] = &collectedLink
		c.pointOfContacts = append(c.pointOfContacts, &collectedLink)
		// set the backlinks
		if packageID != 0 {
			foundPkgNameorVersionNode.setPointOfContactLinks(collectedLink.id)
		}
		if artifactID != 0 {
			foundArtStrct.setPointOfContactLinks(collectedLink.id)
		}
		if sourceID != 0 {
			srcName.setPointOfContactLinks(collectedLink.id)
		}

	}

	// build return GraphQL type
	builtPointOfContact, err := c.buildPointOfContact(&collectedLink, nil, true)
	if err != nil {
		return nil, err
	}
	return builtPointOfContact, nil
}

// Query PointOfContact
func (c *demoClient) PointOfContact(ctx context.Context, filter *model.PointOfContactSpec) ([]*model.PointOfContact, error) {
	funcName := "PointOfContact"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*pointOfContactLink](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		found, err := c.buildPointOfContact(link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.PointOfContact{found}, nil
	}

	// Cant really search for an exact Pkg, as these can be linked to either
	// names or versions, and version could be empty.
	var search []uint32
	foundOne := false
	if filter != nil && filter.Subject != nil && filter.Subject.Artifact != nil {
		exactArtifact, err := c.artifactExact(filter.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.pointOfContactLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.pointOfContactLinks...)
			foundOne = true
		}
	}

	var out []*model.PointOfContact
	if foundOne {
		for _, id := range search {
			link, err := byID[*pointOfContactLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addPOCIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.pointOfContacts {
			var err error
			out, err = c.addPOCIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addPOCIfMatch(out []*model.PointOfContact, filter *model.PointOfContactSpec, link *pointOfContactLink) (
	[]*model.PointOfContact, error) {

	if filter != nil && noMatch(filter.Justification, link.justification) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.origin) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Email, link.email) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Info, link.info) {
		return out, nil
	}
	// no match if filter time since is after the timestamp
	if filter != nil && filter.Since != nil && filter.Since.After(link.since) {
		return out, nil
	}

	found, err := c.buildPointOfContact(link, filter, false)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return out, nil
	}
	return append(out, found), nil
}

func (c *demoClient) buildPointOfContact(link *pointOfContactLink, filter *model.PointOfContactSpec, ingestOrIDProvided bool) (*model.PointOfContact, error) {
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

	pointOfContact := model.PointOfContact{
		ID:            nodeID(link.id),
		Subject:       subj,
		Email:         link.email,
		Info:          link.info,
		Since:         link.since,
		Justification: link.justification,
		Origin:        link.origin,
		Collector:     link.collector,
	}
	return &pointOfContact, nil
}
