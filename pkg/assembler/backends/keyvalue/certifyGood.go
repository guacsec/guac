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
type goodLink struct {
	ThisID        string
	PackageID     string
	ArtifactID    string
	SourceID      string
	Justification string
	Origin        string
	Collector     string
	KnownSince    time.Time
}

func (n *goodLink) ID() string { return n.ThisID }

func (n *goodLink) Key() string {
	return strings.Join([]string{
		n.PackageID,
		n.ArtifactID,
		n.SourceID,
		n.Justification,
		n.Origin,
		n.Collector,
		timeKey(n.KnownSince),
	}, ":")
}

func (n *goodLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 1)
	if n.PackageID != "" && allowedEdges[model.EdgeCertifyGoodPackage] {
		out = append(out, n.PackageID)
	}
	if n.ArtifactID != "" && allowedEdges[model.EdgeCertifyGoodArtifact] {
		out = append(out, n.ArtifactID)
	}
	if n.SourceID != "" && allowedEdges[model.EdgeCertifyGoodSource] {
		out = append(out, n.SourceID)
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

	in := &goodLink{
		Justification: certifyGood.Justification,
		Origin:        certifyGood.Origin,
		Collector:     certifyGood.Collector,
		KnownSince:    certifyGood.KnownSince.UTC(),
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var foundPkgNameorVersionNode pkgNameOrVersion
	var foundArtStrct *artStruct
	var foundSrcName *srcNameNode

	if subject.Package != nil {
		var err error
		foundPkgNameorVersionNode, err = c.getPackageNameOrVerFromInput(ctx, *subject.Package, *pkgMatchType)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.PackageID = foundPkgNameorVersionNode.ID()
	} else if subject.Artifact != nil {
		var err error
		foundArtStrct, err = c.artifactByInput(ctx, subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.ArtifactID = foundArtStrct.ThisID
	} else {
		var err error
		foundSrcName, err = c.getSourceNameFromInput(ctx, *subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.SourceID = foundSrcName.ThisID
	}

	out, err := byKeykv[*goodLink](ctx, cgCol, in.Key(), c)
	if err == nil {
		return c.buildCertifyGood(ctx, out, nil, true)
	}
	if !errors.Is(err, kv.NotFoundError) {
		return nil, err
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestCertifyGood(ctx, subject, pkgMatchType, certifyGood, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}
	in.ThisID = c.getNextID()

	if err := c.addToIndex(ctx, cgCol, in); err != nil {
		return nil, err
	}
	if foundPkgNameorVersionNode != nil {
		if err := foundPkgNameorVersionNode.setCertifyGoodLinks(ctx, in.ThisID, c); err != nil {
			return nil, err
		}
	} else if foundArtStrct != nil {
		if err := foundArtStrct.setCertifyGoodLinks(ctx, in.ThisID, c); err != nil {
			return nil, err
		}
	} else {
		if err := foundSrcName.setCertifyGoodLinks(ctx, in.ThisID, c); err != nil {
			return nil, err
		}
	}
	if err := setkv(ctx, cgCol, in, c); err != nil {
		return nil, err
	}

	return c.buildCertifyGood(ctx, in, nil, true)
}

// Query CertifyGood
func (c *demoClient) CertifyGood(ctx context.Context, filter *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	funcName := "CertifyGood"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*goodLink](ctx, *filter.ID, c)
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
			search = append(search, exactArtifact.GoodLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(ctx, filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.GoodLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyGood
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*goodLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addCGIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		cgKeys, err := c.kv.Keys(ctx, cgCol)
		if err != nil {
			return nil, err
		}
		for _, cgk := range cgKeys {
			link, err := byKeykv[*goodLink](ctx, cgCol, cgk, c)
			if err != nil {
				return nil, err
			}
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
		if noMatch(filter.Justification, link.Justification) ||
			noMatch(filter.Collector, link.Collector) ||
			noMatch(filter.Origin, link.Origin) ||
			filter.KnownSince != nil && filter.KnownSince.After(link.KnownSince) {
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

	certifyGood := model.CertifyGood{
		ID:            link.ThisID,
		Subject:       subj,
		Justification: link.Justification,
		Origin:        link.Origin,
		Collector:     link.Collector,
		KnownSince:    link.KnownSince.UTC(),
	}
	return &certifyGood, nil
}
