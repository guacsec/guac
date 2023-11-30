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
	"errors"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: link that a package/source/artifact is good
type pointOfContactLink struct {
	ThisID        string
	PackageID     string
	ArtifactID    string
	SourceID      string
	Email         string
	Info          string
	Since         time.Time
	Justification string
	Origin        string
	Collector     string
}

func (n *pointOfContactLink) ID() string { return n.ThisID }
func (n *pointOfContactLink) Key() string {
	return strings.Join([]string{
		n.PackageID,
		n.ArtifactID,
		n.SourceID,
		n.Email,
		n.Info,
		timeKey(n.Since),
		n.Justification,
		n.Origin,
		n.Collector,
	}, ":")
}

func (n *pointOfContactLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 1)
	if n.PackageID != "" && allowedEdges[model.EdgePointOfContactPackage] {
		out = append(out, n.PackageID)
	}
	if n.ArtifactID != "" && allowedEdges[model.EdgePointOfContactArtifact] {
		out = append(out, n.ArtifactID)
	}
	if n.SourceID != "" && allowedEdges[model.EdgePointOfContactSource] {
		out = append(out, n.SourceID)
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
		var pointOfContact string
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
		modelPointOfContactIDs = append(modelPointOfContactIDs, pointOfContact)
	}
	return modelPointOfContactIDs, nil
}

func (c *demoClient) IngestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec) (string, error) {
	return c.ingestPointOfContact(ctx, subject, pkgMatchType, pointOfContact, true)
}

func (c *demoClient) ingestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec, readOnly bool) (string, error) {
	funcName := "IngestPointOfContact"

	in := &pointOfContactLink{
		Email:         pointOfContact.Email,
		Info:          pointOfContact.Info,
		Since:         pointOfContact.Since.UTC(),
		Justification: pointOfContact.Justification,
		Origin:        pointOfContact.Origin,
		Collector:     pointOfContact.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var foundPkgNameorVersionNode pkgNameOrVersion
	var foundArtStrct *artStruct
	var srcName *srcNameNode
	if subject.Package != nil {
		var err error
		foundPkgNameorVersionNode, err = c.getPackageNameOrVerFromInput(ctx, *subject.Package, *pkgMatchType)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.PackageID = foundPkgNameorVersionNode.ID()
	} else if subject.Artifact != nil {
		var err error
		foundArtStrct, err = c.artifactByInput(ctx, subject.Artifact)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.ArtifactID = foundArtStrct.ThisID
	} else {
		var err error
		srcName, err = c.getSourceNameFromInput(ctx, *subject.Source)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.SourceID = srcName.ThisID
	}

	out, err := byKeykv[*pointOfContactLink](ctx, pocCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestPointOfContact(ctx, subject, pkgMatchType, pointOfContact, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, pocCol, in); err != nil {
		return "", err
	}

	if foundPkgNameorVersionNode != nil {
		if err := foundPkgNameorVersionNode.setPointOfContactLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if foundArtStrct != nil {
		if err := foundArtStrct.setPointOfContactLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if srcName != nil {
		if err := srcName.setPointOfContactLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if err := setkv(ctx, pocCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

// Query PointOfContact
func (c *demoClient) PointOfContact(ctx context.Context, filter *model.PointOfContactSpec) ([]*model.PointOfContact, error) {
	funcName := "PointOfContact"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*pointOfContactLink](ctx, *filter.ID, c)
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
			search = append(search, exactArtifact.PointOfContactLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(ctx, filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.PointOfContactLinks...)
			foundOne = true
		}
	}

	var out []*model.PointOfContact
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*pointOfContactLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addPOCIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		pocKeys, err := c.kv.Keys(ctx, pocCol)
		if err != nil {
			return nil, err
		}
		for _, pk := range pocKeys {
			link, err := byKeykv[*pointOfContactLink](ctx, pocCol, pk, c)
			if err != nil {
				return nil, err
			}
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

	if filter != nil && noMatch(filter.Justification, link.Justification) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Email, link.Email) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Info, link.Info) {
		return out, nil
	}
	// no match if filter time since is after the timestamp
	if filter != nil && filter.Since != nil && filter.Since.After(link.Since) {
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
		if filter.Subject.Package != nil && link.PackageID != "" {
			p, err = c.buildPackageResponse(ctx, link.PackageID, filter.Subject.Package)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Artifact != nil && link.ArtifactID != "" {
			a, err = c.buildArtifactResponse(ctx, link.ArtifactID, filter.Subject.Artifact)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Source != nil && link.SourceID != "" {
			s, err = c.buildSourceResponse(ctx, link.SourceID, filter.Subject.Source)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.PackageID != "" {
			p, err = c.buildPackageResponse(ctx, link.PackageID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.ArtifactID != "" {
			a, err = c.buildArtifactResponse(ctx, link.ArtifactID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.SourceID != "" {
			s, err = c.buildSourceResponse(ctx, link.SourceID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	var subj model.PackageSourceOrArtifact
	if link.PackageID != "" {
		if p == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve package via packageID")
		} else if p == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = p
	}
	if link.ArtifactID != "" {
		if a == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve artifact via artifactID")
		} else if a == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = a
	}
	if link.SourceID != "" {
		if s == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve source via sourceID")
		} else if s == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = s
	}

	pointOfContact := model.PointOfContact{
		ID:            link.ThisID,
		Subject:       subj,
		Email:         link.Email,
		Info:          link.Info,
		Since:         link.Since,
		Justification: link.Justification,
		Origin:        link.Origin,
		Collector:     link.Collector,
	}
	return &pointOfContact, nil
}
