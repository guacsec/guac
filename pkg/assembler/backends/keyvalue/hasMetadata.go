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
type hasMetadataList []*hasMetadataLink
type hasMetadataLink struct {
	id            string
	packageID     string
	artifactID    string
	sourceID      string
	timestamp     time.Time
	key           string
	value         string
	justification string
	origin        string
	collector     string
}

func (n *hasMetadataLink) ID() string { return n.id }

func (n *hasMetadataLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 1)
	if n.packageID != "" && allowedEdges[model.EdgeHasMetadataPackage] {
		out = append(out, n.packageID)
	}
	if n.artifactID != "" && allowedEdges[model.EdgeHasMetadataArtifact] {
		out = append(out, n.artifactID)
	}
	if n.sourceID != "" && allowedEdges[model.EdgeHasMetadataSource] {
		out = append(out, n.sourceID)
	}
	return out
}

func (n *hasMetadataLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildHasMetadata(ctx, n, nil, true)
}

// Ingest HasMetadata

func (c *demoClient) IngestBulkHasMetadata(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) ([]string, error) {
	var modelHasMetadataIDs []string

	for i := range hasMetadataList {
		var hasMetadata *model.HasMetadata
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageSourceOrArtifactInput{Package: subjects.Packages[i]}
			hasMetadata, err = c.IngestHasMetadata(ctx, subject, pkgMatchType, *hasMetadataList[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestHasMetadata failed with err: %v", err)
			}
		} else if len(subjects.Sources) > 0 {
			subject := model.PackageSourceOrArtifactInput{Source: subjects.Sources[i]}
			hasMetadata, err = c.IngestHasMetadata(ctx, subject, pkgMatchType, *hasMetadataList[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestHasMetadata failed with err: %v", err)
			}
		} else {
			subject := model.PackageSourceOrArtifactInput{Artifact: subjects.Artifacts[i]}
			hasMetadata, err = c.IngestHasMetadata(ctx, subject, pkgMatchType, *hasMetadataList[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestHasMetadata failed with err: %v", err)
			}
		}
		modelHasMetadataIDs = append(modelHasMetadataIDs, hasMetadata.ID)
	}
	return modelHasMetadataIDs, nil
}

func (c *demoClient) IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (*model.HasMetadata, error) {
	return c.ingestHasMetadata(ctx, subject, pkgMatchType, hasMetadata, true)
}

func (c *demoClient) ingestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec, readOnly bool) (*model.HasMetadata, error) {
	funcName := "IngestHasMetadata"

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
		searchIDs = append(searchIDs, foundPkgNameorVersionNode.getHasMetadataLinks()...)
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
		searchIDs = append(searchIDs, foundArtStrct.hasMetadataLinks...)
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
		searchIDs = append(searchIDs, srcName.hasMetadataLinks...)
	}

	// Don't insert duplicates
	duplicate := false
	collectedLink := hasMetadataLink{}
	for _, id := range searchIDs {
		v, err := byID[*hasMetadataLink](id, c)
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
		if subjectMatch && hasMetadata.Justification == v.justification &&
			hasMetadata.Key == v.key && hasMetadata.Value == v.value &&
			hasMetadata.Timestamp.Equal(v.timestamp) &&
			hasMetadata.Origin == v.origin && hasMetadata.Collector == v.collector {

			collectedLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			b, err := c.ingestHasMetadata(ctx, subject, pkgMatchType, hasMetadata, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return b, err
		}
		// store the link
		collectedLink = hasMetadataLink{
			id:            c.getNextID(),
			packageID:     packageID,
			artifactID:    artifactID,
			sourceID:      sourceID,
			key:           hasMetadata.Key,
			value:         hasMetadata.Value,
			timestamp:     hasMetadata.Timestamp,
			justification: hasMetadata.Justification,
			origin:        hasMetadata.Origin,
			collector:     hasMetadata.Collector,
		}
		c.index[collectedLink.id] = &collectedLink
		c.hasMetadatas = append(c.hasMetadatas, &collectedLink)
		// set the backlinks
		if packageID != "" {
			foundPkgNameorVersionNode.setHasMetadataLinks(collectedLink.id)
		}
		if artifactID != "" {
			foundArtStrct.setHasMetadataLinks(collectedLink.id)
		}
		if sourceID != "" {
			srcName.setHasMetadataLinks(collectedLink.id)
		}

	}

	// build return GraphQL type
	builtHasMetadata, err := c.buildHasMetadata(ctx, &collectedLink, nil, true)
	if err != nil {
		return nil, err
	}
	return builtHasMetadata, nil
}

// Query HasMetadata
func (c *demoClient) HasMetadata(ctx context.Context, filter *model.HasMetadataSpec) ([]*model.HasMetadata, error) {
	funcName := "HasMetadata"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byID[*hasMetadataLink](*filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		found, err := c.buildHasMetadata(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.HasMetadata{found}, nil
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
			search = append(search, exactArtifact.hasMetadataLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.hasMetadataLinks...)
			foundOne = true
		}
	}

	var out []*model.HasMetadata
	if foundOne {
		for _, id := range search {
			link, err := byID[*hasMetadataLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addHMIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.hasMetadatas {
			var err error
			out, err = c.addHMIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addHMIfMatch(ctx context.Context, out []*model.HasMetadata, filter *model.HasMetadataSpec, link *hasMetadataLink) (
	[]*model.HasMetadata, error) {

	if filter != nil && noMatch(filter.Justification, link.justification) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.origin) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Key, link.key) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Value, link.value) {
		return out, nil
	}
	// no match if filter time since is after the timestamp
	if filter != nil && filter.Since != nil && filter.Since.After(link.timestamp) {
		return out, nil
	}

	found, err := c.buildHasMetadata(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return out, nil
	}
	return append(out, found), nil
}

func (c *demoClient) buildHasMetadata(ctx context.Context, link *hasMetadataLink, filter *model.HasMetadataSpec, ingestOrIDProvided bool) (*model.HasMetadata, error) {
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

	hasMetadata := model.HasMetadata{
		ID:            link.id,
		Subject:       subj,
		Timestamp:     link.timestamp,
		Key:           link.key,
		Value:         link.value,
		Justification: link.justification,
		Origin:        link.origin,
		Collector:     link.collector,
	}
	return &hasMetadata, nil
}
