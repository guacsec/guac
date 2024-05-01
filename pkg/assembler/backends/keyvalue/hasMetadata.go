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

type hasMetadataLink struct {
	ThisID        string
	PackageID     string
	ArtifactID    string
	SourceID      string
	Timestamp     time.Time
	MDKey         string
	Value         string
	Justification string
	Origin        string
	Collector     string
	DocumentRef   string
}

func (n *hasMetadataLink) ID() string { return n.ThisID }
func (n *hasMetadataLink) Key() string {
	return hashKey(strings.Join([]string{
		n.PackageID,
		n.ArtifactID,
		n.SourceID,
		timeKey(n.Timestamp),
		n.MDKey,
		n.Value,
		n.Justification,
		n.Origin,
		n.Collector,
		n.DocumentRef,
	}, ":"))
}

func (n *hasMetadataLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 1)
	if n.PackageID != "" && allowedEdges[model.EdgeHasMetadataPackage] {
		out = append(out, n.PackageID)
	}
	if n.ArtifactID != "" && allowedEdges[model.EdgeHasMetadataArtifact] {
		out = append(out, n.ArtifactID)
	}
	if n.SourceID != "" && allowedEdges[model.EdgeHasMetadataSource] {
		out = append(out, n.SourceID)
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
		var hasMetadata string
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
		modelHasMetadataIDs = append(modelHasMetadataIDs, hasMetadata)
	}
	return modelHasMetadataIDs, nil
}

func (c *demoClient) IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (string, error) {
	return c.ingestHasMetadata(ctx, subject, pkgMatchType, hasMetadata, true)
}

func (c *demoClient) ingestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec, readOnly bool) (string, error) {
	funcName := "IngestHasMetadata"

	in := &hasMetadataLink{
		MDKey:         hasMetadata.Key,
		Value:         hasMetadata.Value,
		Timestamp:     hasMetadata.Timestamp.UTC(),
		Justification: hasMetadata.Justification,
		Origin:        hasMetadata.Origin,
		Collector:     hasMetadata.Collector,
		DocumentRef:   hasMetadata.DocumentRef,
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

	out, err := byKeykv[*hasMetadataLink](ctx, hasMDCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestHasMetadata(ctx, subject, pkgMatchType, hasMetadata, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, hasMDCol, in); err != nil {
		return "", err
	}

	// set the backlinks
	if foundPkgNameOrVersionNode != nil {
		if err := foundPkgNameOrVersionNode.setHasMetadataLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if foundArtStruct != nil {
		if err := foundArtStruct.setHasMetadataLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if srcName != nil {
		if err := srcName.setHasMetadataLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}

	if err := setkv(ctx, hasMDCol, in, c); err != nil {
		return "", err
	}

	// build return GraphQL type
	return in.ThisID, nil
}

// Query HasMetadata

func (c *demoClient) HasMetadataList(ctx context.Context, hasMetadataSpec model.HasMetadataSpec, after *string, first *int) (*model.HasMetadataConnection, error) {
	funcName := "HasMetadata"

	c.m.RLock()
	defer c.m.RUnlock()

	if hasMetadataSpec.ID != nil {
		link, err := byIDkv[*hasMetadataLink](ctx, *hasMetadataSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		found, err := c.buildHasMetadata(ctx, link, &hasMetadataSpec, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return &model.HasMetadataConnection{
			TotalCount: 1,
			PageInfo: &model.PageInfo{
				HasNextPage: false,
				StartCursor: ptrfrom.String(found.ID),
				EndCursor:   ptrfrom.String(found.ID),
			},
			Edges: []*model.HasMetadataEdge{
				{
					Cursor: found.ID,
					Node:   found,
				},
			},
		}, nil
	}

	edges := make([]*model.HasMetadataEdge, 0)
	hasNextPage := false
	numNodes := 0
	totalCount := 0

	// Cant really search for an exact Pkg, as these can be linked to either
	// names or versions, and version could be empty.
	var search []string
	foundOne := false
	if hasMetadataSpec.Subject != nil && hasMetadataSpec.Subject.Artifact != nil {
		exactArtifact, err := c.artifactExact(ctx, hasMetadataSpec.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.HasMetadataLinks...)
			foundOne = true
		}
	}
	if !foundOne && hasMetadataSpec.Subject != nil && hasMetadataSpec.Subject.Source != nil {
		exactSource, err := c.exactSource(ctx, hasMetadataSpec.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.HasMetadataLinks...)
			foundOne = true
		}
	}

	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*hasMetadataLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			hm, err := c.hasMetadataIfMatch(ctx, &hasMetadataSpec, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}

			edges = append(edges, &model.HasMetadataEdge{
				Cursor: hm.ID,
				Node:   hm,
			})
		}
	} else {
		currentPage := false

		// If no cursor present start from the top
		if after == nil {
			currentPage = true
		}

		var done bool
		scn := c.kv.Keys(hasMDCol)
		for !done {
			var hmKeys []string
			var err error
			hmKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}

			sort.Strings(hmKeys)
			totalCount = len(hmKeys)

			for i, hmKey := range hmKeys {
				link, err := byKeykv[*hasMetadataLink](ctx, hasMDCol, hmKey, c)
				if err != nil {
					return nil, err
				}
				hm, err := c.hasMetadataIfMatch(ctx, &hasMetadataSpec, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}

				if after != nil && !currentPage {
					if hm.ID == *after {
						totalCount = len(hmKeys) - (i + 1)
						currentPage = true
					}
					continue
				}

				if first != nil {
					if numNodes < *first {
						edges = append(edges, &model.HasMetadataEdge{
							Cursor: hm.ID,
							Node:   hm,
						})
						numNodes++
					} else if numNodes == *first {
						hasNextPage = true
					}
				} else {
					edges = append(edges, &model.HasMetadataEdge{
						Cursor: hm.ID,
						Node:   hm,
					})
				}
			}
		}
	}

	if len(edges) != 0 {
		return &model.HasMetadataConnection{
			TotalCount: totalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: hasNextPage,
				StartCursor: ptrfrom.String(edges[0].Node.ID),
				EndCursor:   ptrfrom.String(edges[numNodes-1].Node.ID),
			},
			Edges: edges,
		}, nil
	}
	return nil, nil
}

func (c *demoClient) HasMetadata(ctx context.Context, filter *model.HasMetadataSpec) ([]*model.HasMetadata, error) {
	funcName := "HasMetadata"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*hasMetadataLink](ctx, *filter.ID, c)
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
			search = append(search, exactArtifact.HasMetadataLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(ctx, filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.HasMetadataLinks...)
			foundOne = true
		}
	}

	var out []*model.HasMetadata
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*hasMetadataLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			hm, err := c.hasMetadataIfMatch(ctx, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out = append(out, hm)
		}
	} else {
		var done bool
		scn := c.kv.Keys(hasMDCol)
		for !done {
			var hmk []string
			var err error
			hmk, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, hk := range hmk {
				link, err := byKeykv[*hasMetadataLink](ctx, hasMDCol, hk, c)
				if err != nil {
					return nil, err
				}
				hm, err := c.hasMetadataIfMatch(ctx, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
				out = append(out, hm)
			}
		}
	}
	return out, nil
}

func (c *demoClient) hasMetadataIfMatch(ctx context.Context, filter *model.HasMetadataSpec, link *hasMetadataLink) (
	*model.HasMetadata, error) {

	if filter != nil && noMatch(filter.Justification, link.Justification) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Key, link.MDKey) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Value, link.Value) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.DocumentRef, link.DocumentRef) {
		return nil, nil
	}
	// no match if filter time since is after the timestamp
	if filter != nil && filter.Since != nil && filter.Since.After(link.Timestamp) {
		return nil, nil
	}

	found, err := c.buildHasMetadata(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, nil
	}
	return found, nil
}

func (c *demoClient) buildHasMetadata(ctx context.Context, link *hasMetadataLink, filter *model.HasMetadataSpec, ingestOrIDProvided bool) (*model.HasMetadata, error) {
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

	hasMetadata := model.HasMetadata{
		ID:            link.ThisID,
		Subject:       subj,
		Timestamp:     link.Timestamp,
		Key:           link.MDKey,
		Value:         link.Value,
		Justification: link.Justification,
		Origin:        link.Origin,
		Collector:     link.Collector,
		DocumentRef:   link.DocumentRef,
	}
	return &hasMetadata, nil
}
