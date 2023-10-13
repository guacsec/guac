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
type goodList []*goodLink
type goodLink struct {
	id            string
	packageID     string
	artifactID    string
	sourceID      string
	justification string
	origin        string
	collector     string
	knownSince    time.Time
}

func (n *goodLink) ID() string { return n.id }

func (n *goodLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 1)
	if n.packageID != "" && allowedEdges[model.EdgeCertifyGoodPackage] {
		out = append(out, n.packageID)
	}
	if n.artifactID != "" && allowedEdges[model.EdgeCertifyGoodArtifact] {
		out = append(out, n.artifactID)
	}
	if n.sourceID != "" && allowedEdges[model.EdgeCertifyGoodSource] {
		out = append(out, n.sourceID)
	}
	return out
}

func (n *goodLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildCertifyGood(ctx, n, nil, true)
}

// Ingest CertifyGood

func (c *demoClient) IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]*model.CertifyGood, error) {
	var modelCertifyGoods []*model.CertifyGood

	for i := range certifyGoods {
		var certifyGood *model.CertifyGood
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageSourceOrArtifactInput{Package: subjects.Packages[i]}
			certifyGood, err = c.IngestCertifyGood(ctx, subject, pkgMatchType, *certifyGoods[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyGood failed with err: %v", err)
			}
		} else if len(subjects.Sources) > 0 {
			subject := model.PackageSourceOrArtifactInput{Source: subjects.Sources[i]}
			certifyGood, err = c.IngestCertifyGood(ctx, subject, pkgMatchType, *certifyGoods[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyGood failed with err: %v", err)
			}
		} else {
			subject := model.PackageSourceOrArtifactInput{Artifact: subjects.Artifacts[i]}
			certifyGood, err = c.IngestCertifyGood(ctx, subject, pkgMatchType, *certifyGoods[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyGood failed with err: %v", err)
			}
		}
		modelCertifyGoods = append(modelCertifyGoods, certifyGood)
	}
	return modelCertifyGoods, nil
}

func (c *demoClient) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (*model.CertifyGood, error) {
	return c.ingestCertifyGood(ctx, subject, pkgMatchType, certifyGood, true)
}
func (c *demoClient) ingestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec, readOnly bool) (*model.CertifyGood, error) {
	funcName := "IngestCertifyGood"

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
		searchIDs = append(searchIDs, foundPkgNameorVersionNode.getCertifyGoodLinks()...)
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
		searchIDs = append(searchIDs, foundArtStrct.goodLinks...)
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
		searchIDs = append(searchIDs, srcName.goodLinks...)
	}

	// Don't insert duplicates
	duplicate := false
	collectedCertifyGoodLink := goodLink{}
	for _, id := range searchIDs {
		v, err := byID[*goodLink](id, c)
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
		if subjectMatch && certifyGood.Justification == v.justification &&
			certifyGood.Origin == v.origin && certifyGood.Collector == v.collector &&
			certifyGood.KnownSince.Equal(v.knownSince) {

			collectedCertifyGoodLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			b, err := c.ingestCertifyGood(ctx, subject, pkgMatchType, certifyGood, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return b, err
		}
		// store the link
		collectedCertifyGoodLink = goodLink{
			id:            c.getNextID(),
			packageID:     packageID,
			artifactID:    artifactID,
			sourceID:      sourceID,
			justification: certifyGood.Justification,
			origin:        certifyGood.Origin,
			collector:     certifyGood.Collector,
			knownSince:    certifyGood.KnownSince.UTC(),
		}
		c.index[collectedCertifyGoodLink.id] = &collectedCertifyGoodLink
		c.certifyGoods = append(c.certifyGoods, &collectedCertifyGoodLink)
		// set the backlinks
		if packageID != "" {
			foundPkgNameorVersionNode.setCertifyGoodLinks(collectedCertifyGoodLink.id)
		}
		if artifactID != "" {
			foundArtStrct.setCertifyGoodLinks(collectedCertifyGoodLink.id)
		}
		if sourceID != "" {
			srcName.setCertifyGoodLinks(collectedCertifyGoodLink.id)
		}

	}

	// build return GraphQL type
	builtCertifyGood, err := c.buildCertifyGood(ctx, &collectedCertifyGoodLink, nil, true)
	if err != nil {
		return nil, err
	}
	return builtCertifyGood, nil
}

// Query CertifyGood
func (c *demoClient) CertifyGood(ctx context.Context, filter *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	funcName := "CertifyGood"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byID[*goodLink](*filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundCertifyGood, err := c.buildCertifyGood(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyGood{foundCertifyGood}, nil
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
			search = append(search, exactArtifact.goodLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.goodLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyGood
	if foundOne {
		for _, id := range search {
			link, err := byID[*goodLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addCGIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.certifyGoods {
			var err error
			out, err = c.addCGIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addCGIfMatch(ctx context.Context, out []*model.CertifyGood,
	filter *model.CertifyGoodSpec, link *goodLink) (
	[]*model.CertifyGood, error) {

	if filter != nil {
		if noMatch(filter.Justification, link.justification) ||
			noMatch(filter.Collector, link.collector) ||
			noMatch(filter.Collector, link.collector) ||
			noMatch(filter.Origin, link.origin) ||
			filter.KnownSince != nil && filter.KnownSince.After(link.knownSince) {
			return out, nil
		}
	}

	foundCertifyGood, err := c.buildCertifyGood(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyGood == nil {
		return out, nil
	}
	return append(out, foundCertifyGood), nil
}

func (c *demoClient) buildCertifyGood(ctx context.Context, link *goodLink, filter *model.CertifyGoodSpec, ingestOrIDProvided bool) (*model.CertifyGood, error) {
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

	certifyGood := model.CertifyGood{
		ID:            link.id,
		Subject:       subj,
		Justification: link.justification,
		Origin:        link.origin,
		Collector:     link.collector,
		KnownSince:    link.knownSince.UTC(),
	}
	return &certifyGood, nil
}
