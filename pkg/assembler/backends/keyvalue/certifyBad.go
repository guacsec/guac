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

// TODO: update the other backends to handle the new timestamp fields beacuse of: https://github.com/guacsec/guac/pull/1338/files#r1343080326

// Internal data: link that a package/source/artifact is bad
type badLink struct {
	ThisID        string
	PackageID     string
	ArtifactID    string
	SourceID      string
	Justification string
	Origin        string
	Collector     string
	KnownSince    time.Time
}

func (n *badLink) ID() string { return n.ThisID }

func (n *badLink) Key() string {
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

func (n *badLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 1)
	if n.PackageID != "" && allowedEdges[model.EdgeCertifyBadPackage] {
		out = append(out, n.PackageID)
	}
	if n.ArtifactID != "" && allowedEdges[model.EdgeCertifyBadArtifact] {
		out = append(out, n.ArtifactID)
	}
	if n.SourceID != "" && allowedEdges[model.EdgeCertifyBadSource] {
		out = append(out, n.SourceID)
	}
	return out
}

func (n *badLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildCertifyBad(ctx, n, nil, true)
}

// Ingest CertifyBad
func (c *demoClient) IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]string, error) {
	var modelCertifyBads []string

	for i := range certifyBads {
		var certifyBad string
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageSourceOrArtifactInput{Package: subjects.Packages[i]}
			certifyBad, err = c.IngestCertifyBad(ctx, subject, pkgMatchType, *certifyBads[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyBad failed with err: %v", err)
			}
		} else if len(subjects.Sources) > 0 {
			subject := model.PackageSourceOrArtifactInput{Source: subjects.Sources[i]}
			certifyBad, err = c.IngestCertifyBad(ctx, subject, pkgMatchType, *certifyBads[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyBad failed with err: %v", err)
			}
		} else {
			subject := model.PackageSourceOrArtifactInput{Artifact: subjects.Artifacts[i]}
			certifyBad, err = c.IngestCertifyBad(ctx, subject, pkgMatchType, *certifyBads[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyBad failed with err: %v", err)
			}
		}
		modelCertifyBads = append(modelCertifyBads, certifyBad)
	}
	return modelCertifyBads, nil
}

func (c *demoClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (string, error) {
	return c.ingestCertifyBad(ctx, subject, pkgMatchType, certifyBad, true)
}
func (c *demoClient) ingestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec, readOnly bool) (string, error) {
	funcName := "IngestCertifyBad"

	in := &badLink{
		Justification: certifyBad.Justification,
		Origin:        certifyBad.Origin,
		Collector:     certifyBad.Collector,
		KnownSince:    certifyBad.KnownSince.UTC(),
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var foundPkgNameorVersionNode pkgNameOrVersion
	var foundArtStruct *artStruct
	var foundSrcName *srcNameNode

	if subject.Package != nil {
		var err error
		foundPkgNameorVersionNode, err = c.getPackageNameOrVerFromInput(ctx, *subject.Package, *pkgMatchType)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.PackageID = foundPkgNameorVersionNode.ID()
	} else if subject.Artifact != nil {
		var err error
		foundArtStruct, err = c.artifactByInput(ctx, subject.Artifact)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.ArtifactID = foundArtStruct.ThisID
	} else {
		var err error
		foundSrcName, err = c.getSourceNameFromInput(ctx, *subject.Source)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.SourceID = foundSrcName.ThisID
	}

	out, err := byKeykv[*badLink](ctx, cbCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestCertifyBad(ctx, subject, pkgMatchType, certifyBad, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}
	in.ThisID = c.getNextID()

	if err := c.addToIndex(ctx, cbCol, in); err != nil {
		return "", err
	}
	if foundPkgNameorVersionNode != nil {
		if err := foundPkgNameorVersionNode.setCertifyBadLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	} else if foundArtStruct != nil {
		if err := foundArtStruct.setCertifyBadLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	} else {
		if err := foundSrcName.setCertifyBadLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if err := setkv(ctx, cbCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

// Query CertifyBad
func (c *demoClient) CertifyBad(ctx context.Context, filter *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	funcName := "CertifyBad"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*badLink](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundCertifyBad, err := c.buildCertifyBad(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyBad{foundCertifyBad}, nil
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
			search = append(search, exactArtifact.BadLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(ctx, filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.BadLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyBad
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*badLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addCBIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		var done bool
		scn := c.kv.Keys(cbCol)
		for !done {
			var cgKeys []string
			var err error
			cgKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, cgk := range cgKeys {
				link, err := byKeykv[*badLink](ctx, cbCol, cgk, c)
				if err != nil {
					return nil, err
				}
				out, err = c.addCBIfMatch(ctx, out, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
			}
		}
	}
	return out, nil
}

func (c *demoClient) addCBIfMatch(ctx context.Context, out []*model.CertifyBad,
	filter *model.CertifyBadSpec, link *badLink) (
	[]*model.CertifyBad, error) {

	if filter != nil {
		if noMatch(filter.Justification, link.Justification) ||
			noMatch(filter.Collector, link.Collector) ||
			noMatch(filter.Origin, link.Origin) ||
			filter.KnownSince != nil && filter.KnownSince.After(link.KnownSince) {
			return out, nil
		}
	}

	foundCertifyBad, err := c.buildCertifyBad(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyBad == nil {
		return out, nil
	}
	return append(out, foundCertifyBad), nil
}

func (c *demoClient) buildCertifyBad(ctx context.Context, link *badLink, filter *model.CertifyBadSpec, ingestOrIDProvided bool) (*model.CertifyBad, error) {
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

	certifyBad := model.CertifyBad{
		ID:            link.ThisID,
		Subject:       subj,
		Justification: link.Justification,
		Origin:        link.Origin,
		Collector:     link.Collector,
		KnownSince:    link.KnownSince.UTC(),
	}
	return &certifyBad, nil
}
