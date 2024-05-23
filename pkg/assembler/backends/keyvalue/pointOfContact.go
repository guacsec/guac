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
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"sort"
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
	DocumentRef   string
}

func (n *pointOfContactLink) ID() string { return n.ThisID }
func (n *pointOfContactLink) Key() string {
	return hashKey(strings.Join([]string{
		n.PackageID,
		n.ArtifactID,
		n.SourceID,
		n.Email,
		n.Info,
		timeKey(n.Since),
		n.Justification,
		n.Origin,
		n.Collector,
		n.DocumentRef,
	}, ":"))
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
		DocumentRef:   pointOfContact.DocumentRef,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var foundPkgNameOrVersionNode pkgNameOrVersion
	var foundArtStruct *artStruct
	var srcName *srcNameNode
	if subject.Package != nil {
		var err error
		in.PackageID, foundPkgNameOrVersionNode, err = c.returnFoundPkgBasedOnMatchType(ctx, subject.Package, pkgMatchType)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
	} else if subject.Artifact != nil {
		var err error
		foundArtStruct, err = c.returnFoundArtifact(ctx, subject.Artifact)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.ArtifactID = foundArtStruct.ID()
	} else {
		var err error
		srcName, err = c.returnFoundSource(ctx, subject.Source)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.SourceID = srcName.ID()
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

	if foundPkgNameOrVersionNode != nil {
		if err := foundPkgNameOrVersionNode.setPointOfContactLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if foundArtStruct != nil {
		if err := foundArtStruct.setPointOfContactLinks(ctx, in.ThisID, c); err != nil {
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

func (c *demoClient) PointOfContactList(ctx context.Context, pointOfContactSpec model.PointOfContactSpec, after *string, first *int) (*model.PointOfContactConnection, error) {
	funcName := "PointOfContact"

	c.m.RLock()
	defer c.m.RUnlock()

	if pointOfContactSpec.ID != nil {
		link, err := byIDkv[*pointOfContactLink](ctx, *pointOfContactSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		found, err := c.buildPointOfContact(ctx, link, &pointOfContactSpec, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}

		return &model.PointOfContactConnection{
			TotalCount: 1,
			PageInfo: &model.PageInfo{
				HasNextPage: false,
				StartCursor: ptrfrom.String(found.ID),
				EndCursor:   ptrfrom.String(found.ID),
			},
			Edges: []*model.PointOfContactEdge{
				{
					Cursor: found.ID,
					Node:   found,
				},
			},
		}, nil
	}

	edges := make([]*model.PointOfContactEdge, 0)
	hasNextPage := false
	numNodes := 0
	totalCount := 0
	addToCount := 0

	// Cant really search for an exact Pkg, as these can be linked to either
	// names or versions, and version could be empty.
	var search []string
	foundOne := false
	if pointOfContactSpec.Subject != nil && pointOfContactSpec.Subject.Artifact != nil {
		exactArtifact, err := c.artifactExact(ctx, pointOfContactSpec.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.PointOfContactLinks...)
			foundOne = true
		}
	}
	if !foundOne && pointOfContactSpec.Subject != nil && pointOfContactSpec.Subject.Source != nil {
		exactSource, err := c.exactSource(ctx, pointOfContactSpec.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.PointOfContactLinks...)
			foundOne = true
		}
	}

	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*pointOfContactLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			poc, err := c.pointOfContactIfMatch(ctx, &pointOfContactSpec, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if poc == nil {
				continue
			}

			if (after != nil && poc.ID > *after) || after == nil {
				addToCount += 1

				if first != nil {
					if numNodes < *first {
						edges = append(edges, &model.PointOfContactEdge{
							Cursor: poc.ID,
							Node:   poc,
						})
						numNodes++
					} else if numNodes == *first {
						hasNextPage = true
					}
				} else {
					edges = append(edges, &model.PointOfContactEdge{
						Cursor: poc.ID,
						Node:   poc,
					})
				}
			}
		}
	} else {
		currentPage := false

		// If no cursor present start from the top
		if after == nil {
			currentPage = true
		}

		var done bool
		scn := c.kv.Keys(pocCol)
		for !done {
			var pocKeys []string
			var err error
			pocKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}

			sort.Strings(pocKeys)
			totalCount = len(pocKeys)

			for i, pk := range pocKeys {
				link, err := byKeykv[*pointOfContactLink](ctx, pocCol, pk, c)
				if err != nil {
					return nil, err
				}
				poc, err := c.pointOfContactIfMatch(ctx, &pointOfContactSpec, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}

				if poc == nil {
					continue
				}

				if after != nil && !currentPage {
					if poc.ID == *after {
						totalCount = len(pocKeys) - (i + 1)
						currentPage = true
					}
					continue
				}

				if first != nil {
					if numNodes < *first {
						edges = append(edges, &model.PointOfContactEdge{
							Cursor: poc.ID,
							Node:   poc,
						})
						numNodes++
					} else if numNodes == *first {
						hasNextPage = true
					}
				} else {
					edges = append(edges, &model.PointOfContactEdge{
						Cursor: poc.ID,
						Node:   poc,
					})
				}
			}
		}
	}

	if len(edges) != 0 {
		return &model.PointOfContactConnection{
			TotalCount: totalCount + addToCount,
			PageInfo: &model.PageInfo{
				HasNextPage: hasNextPage,
				StartCursor: ptrfrom.String(edges[0].Node.ID),
				EndCursor:   ptrfrom.String(edges[max(numNodes-1, 0)].Node.ID),
			},
			Edges: edges,
		}, nil
	}
	return nil, nil
}

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
			poc, err := c.pointOfContactIfMatch(ctx, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if poc == nil {
				continue
			}

			out = append(out, poc)
		}
	} else {
		var done bool
		scn := c.kv.Keys(pocCol)
		for !done {
			var pocKeys []string
			var err error
			pocKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, pk := range pocKeys {
				link, err := byKeykv[*pointOfContactLink](ctx, pocCol, pk, c)
				if err != nil {
					return nil, err
				}
				poc, err := c.pointOfContactIfMatch(ctx, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
				if poc == nil {
					continue
				}

				out = append(out, poc)
			}
		}
	}
	return out, nil
}

func (c *demoClient) pointOfContactIfMatch(ctx context.Context, filter *model.PointOfContactSpec, link *pointOfContactLink) (
	*model.PointOfContact, error) {

	if filter != nil && noMatch(filter.Justification, link.Justification) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Email, link.Email) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Info, link.Info) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.DocumentRef, link.DocumentRef) {
		return nil, nil
	}
	// no match if filter time since is after the timestamp
	if filter != nil && filter.Since != nil && filter.Since.After(link.Since) {
		return nil, nil
	}

	found, err := c.buildPointOfContact(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, nil
	}
	return found, nil
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
		DocumentRef:   link.DocumentRef,
	}
	return &pointOfContact, nil
}
