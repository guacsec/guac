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

package keyvalue

import (
	"context"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: link that a package/source/artifact is good
type pointOfContactList []*pointOfContactLink
type pointOfContactLink struct {
	id            string
	packageID     string
	artifactID    string
	sourceID      string
	email         string
	info          string
	since         time.Time
	justification string
	origin        string
	collector     string
}

func (n *pointOfContactLink) ID() string { return n.id }

func (n *pointOfContactLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 1)
	if n.packageID != "" && allowedEdges[model.EdgePointOfContactPackage] {
		out = append(out, n.packageID)
	}
	if n.artifactID != "" && allowedEdges[model.EdgePointOfContactArtifact] {
		out = append(out, n.artifactID)
	}
	if n.sourceID != "" && allowedEdges[model.EdgePointOfContactSource] {
		out = append(out, n.sourceID)
	}
	return out
}

func (n *pointOfContactLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildPointOfContact(ctx, n, nil, true)
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

	var packageID string
	var foundPkgNameorVersionNode pkgNameOrVersion
	var artifactID string
	var foundArtStrct *artStruct
	var sourceID string
	var srcName *srcNameNode
	searchIDs := []string{}
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
		artifactID, err = c.artifactIDByInput(ctx, subject.Artifact)
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
		if packageID != "" && packageID == v.packageID {
			subjectMatch = true
		}
		if artifactID != "" && artifactID == v.artifactID {
			subjectMatch = true
		}
		if sourceID != "" && sourceID == v.sourceID {
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
		if packageID != "" {
			foundPkgNameorVersionNode.setPointOfContactLinks(collectedLink.id)
		}
		if artifactID != "" {
			foundArtStrct.setPointOfContactLinks(collectedLink.id)
		}
		if sourceID != "" {
			srcName.setPointOfContactLinks(collectedLink.id)
		}

	}

	// build return GraphQL type
	builtPointOfContact, err := c.buildPointOfContact(ctx, &collectedLink, nil, true)
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
		link, err := byID[*pointOfContactLink](*filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		found, err := c.buildPointOfContact(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.PointOfContact{found}, nil
	}

	// Cant really search for an exact Pkg, as these can be linked to either
	// names or versions, and version could be empty.
	var search []string
	foundOne := false
	if filter != nil && filter.Subject != nil && filter.Subject.Artifact != nil {
		exactArtifact, err := c.artifactExact(ctx, filter.Subject.Artifact)
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
			out, err = c.addPOCIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.pointOfContacts {
			var err error
			out, err = c.addPOCIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addPOCIfMatch(ctx context.Context, out []*model.PointOfContact, filter *model.PointOfContactSpec, link *pointOfContactLink) (
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

	found, err := c.buildPointOfContact(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return out, nil
	}
	return append(out, found), nil
}

func (c *demoClient) buildPointOfContact(ctx context.Context, link *pointOfContactLink, filter *model.PointOfContactSpec, ingestOrIDProvided bool) (*model.PointOfContact, error) {
	var p *model.Package
	var a *model.Artifact
	var s *model.Source
	var err error
	if filter != nil && filter.Subject != nil {
		if filter.Subject.Package != nil && link.packageID != "" {
			p, err = c.buildPackageResponse(link.packageID, filter.Subject.Package)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Artifact != nil && link.artifactID != "" {
			a, err = c.buildArtifactResponse(ctx, link.artifactID, filter.Subject.Artifact)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Source != nil && link.sourceID != "" {
			s, err = c.buildSourceResponse(link.sourceID, filter.Subject.Source)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.packageID != "" {
			p, err = c.buildPackageResponse(link.packageID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.artifactID != "" {
			a, err = c.buildArtifactResponse(ctx, link.artifactID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.sourceID != "" {
			s, err = c.buildSourceResponse(link.sourceID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	var subj model.PackageSourceOrArtifact
	if link.packageID != "" {
		if p == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve package via packageID")
		} else if p == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = p
	}
	if link.artifactID != "" {
		if a == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve artifact via artifactID")
		} else if a == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = a
	}
	if link.sourceID != "" {
		if s == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve source via sourceID")
		} else if s == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = s
	}

	pointOfContact := model.PointOfContact{
		ID:            link.id,
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
