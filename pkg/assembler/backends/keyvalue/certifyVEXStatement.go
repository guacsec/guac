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

// Internal data: link between a package or an artifact with its corresponding
// vulnerability VEX statement
type vexLink struct {
	ThisID          string
	PackageID       string
	ArtifactID      string
	VulnerabilityID string
	KnownSince      time.Time
	Status          model.VexStatus
	Statement       string
	StatusNotes     string
	Justification   model.VexJustification
	Origin          string
	Collector       string
}

func (n *vexLink) ID() string { return n.ThisID }

func (n *vexLink) Key() string {
	return strings.Join([]string{
		n.PackageID,
		n.ArtifactID,
		n.VulnerabilityID,
		timeKey(n.KnownSince),
		string(n.Status),
		n.Statement,
		n.StatusNotes,
		string(n.Justification),
		n.Origin,
		n.Collector,
	}, ":")
}

func (n *vexLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 2)
	if n.PackageID != "" && allowedEdges[model.EdgeCertifyVexStatementPackage] {
		out = append(out, n.PackageID)
	}
	if n.ArtifactID != "" && allowedEdges[model.EdgeCertifyVexStatementArtifact] {
		out = append(out, n.ArtifactID)
	}
	if allowedEdges[model.EdgeCertifyVexStatementVulnerability] {
		out = append(out, n.VulnerabilityID)
	}
	return out
}

func (n *vexLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildCertifyVEXStatement(ctx, n, nil, true)
}

// Ingest CertifyVex

func (c *demoClient) IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.VulnerabilityInputSpec, vexStatements []*model.VexStatementInputSpec) ([]string, error) {
	var modelVexStatementIDs []string

	for i := range vexStatements {
		var certVex *model.CertifyVEXStatement
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageOrArtifactInput{Package: subjects.Packages[i]}
			certVex, err = c.IngestVEXStatement(ctx, subject, *vulnerabilities[i], *vexStatements[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestVEXStatement failed with err: %v", err)
			}
		} else {
			subject := model.PackageOrArtifactInput{Artifact: subjects.Artifacts[i]}
			certVex, err = c.IngestVEXStatement(ctx, subject, *vulnerabilities[i], *vexStatements[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestVEXStatement failed with err: %v", err)
			}
		}
		modelVexStatementIDs = append(modelVexStatementIDs, certVex.ID)
	}
	return modelVexStatementIDs, nil
}

func (c *demoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInputSpec, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	return c.ingestVEXStatement(ctx, subject, vulnerability, vexStatement, true)
}

func (c *demoClient) ingestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInputSpec, vexStatement model.VexStatementInputSpec, readOnly bool) (*model.CertifyVEXStatement, error) {
	funcName := "IngestVEXStatement"

	in := &vexLink{
		KnownSince:    vexStatement.KnownSince.UTC(),
		Status:        vexStatement.Status,
		Statement:     vexStatement.Statement,
		StatusNotes:   vexStatement.StatusNotes,
		Justification: vexStatement.VexJustification,
		Origin:        vexStatement.Origin,
		Collector:     vexStatement.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var foundPkgVersionNode *pkgVersion
	var foundArtStrct *artStruct
	if subject.Package != nil {
		var err error
		foundPkgVersionNode, err = c.getPackageVerFromInput(ctx, *subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.PackageID = foundPkgVersionNode.ThisID
	} else {
		var err error
		foundArtStrct, err = c.artifactByInput(ctx, subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.ArtifactID = foundArtStrct.ThisID
	}

	foundVulnNode, err := c.getVulnerabilityFromInput(ctx, vulnerability)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	in.VulnerabilityID = foundVulnNode.ThisID

	out, err := byKeykv[*vexLink](ctx, cVEXCol, in.Key(), c)
	if err == nil {
		return c.buildCertifyVEXStatement(ctx, out, nil, true)
	}
	if !errors.Is(err, kv.NotFoundError) {
		return nil, err
	}

	if readOnly {
		c.m.RUnlock()
		v, err := c.ingestVEXStatement(ctx, subject, vulnerability, vexStatement, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return v, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, cVEXCol, in); err != nil {
		return nil, err
	}
	// set the backlinks
	if foundPkgVersionNode != nil {
		if err := foundPkgVersionNode.setVexLinks(ctx, in.ThisID, c); err != nil {
			return nil, err
		}
	} else {
		if err := foundArtStrct.setVexLinks(ctx, in.ThisID, c); err != nil {
			return nil, err
		}
	}
	if err := foundVulnNode.setVexLinks(ctx, in.ThisID, c); err != nil {
		return nil, err
	}
	if err := setkv(ctx, cVEXCol, in, c); err != nil {
		return nil, err
	}

	return c.buildCertifyVEXStatement(ctx, in, nil, true)
}

// Query CertifyVex
func (c *demoClient) CertifyVEXStatement(ctx context.Context, filter *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "CertifyVEXStatement"

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*vexLink](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundCertifyVex, err := c.buildCertifyVEXStatement(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyVEXStatement{foundCertifyVex}, nil
	}

	var search []string
	foundOne := false

	if filter != nil && filter.Subject != nil && filter.Subject.Artifact != nil {
		exactArtifact, err := c.artifactExact(ctx, filter.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.VexLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.VexLinks...)
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil {
		exactVuln, err := c.exactVulnerability(ctx, filter.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.VexLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyVEXStatement
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*vexLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addVexIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		keys, err := c.kv.Keys(ctx, cVEXCol)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			link, err := byKeykv[*vexLink](ctx, cVEXCol, key, c)
			if err != nil {
				return nil, err
			}
			out, err = c.addVexIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addVexIfMatch(ctx context.Context, out []*model.CertifyVEXStatement,
	filter *model.CertifyVEXStatementSpec, link *vexLink) (
	[]*model.CertifyVEXStatement, error) {

	if filter != nil && filter.KnownSince != nil && !filter.KnownSince.Equal(link.KnownSince) {
		return out, nil
	}
	if filter != nil && filter.VexJustification != nil && *filter.VexJustification != link.Justification {
		return out, nil
	}
	if filter != nil && filter.Status != nil && *filter.Status != link.Status {
		return out, nil
	}
	if filter != nil && noMatch(filter.Statement, link.Statement) {
		return out, nil
	}
	if filter != nil && noMatch(filter.StatusNotes, link.StatusNotes) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return out, nil
	}

	foundCertifyVex, err := c.buildCertifyVEXStatement(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyVex == nil {
		return out, nil
	}
	return append(out, foundCertifyVex), nil

}

func (c *demoClient) buildCertifyVEXStatement(ctx context.Context, link *vexLink, filter *model.CertifyVEXStatementSpec, ingestOrIDProvided bool) (*model.CertifyVEXStatement, error) {
	var p *model.Package
	var a *model.Artifact
	var vuln *model.Vulnerability
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
	}

	if filter != nil && filter.Vulnerability != nil {
		if filter.Vulnerability != nil && link.VulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(ctx, link.VulnerabilityID, filter.Vulnerability)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.VulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(ctx, link.VulnerabilityID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	var subj model.PackageOrArtifact
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

	if link.VulnerabilityID != "" {
		if vuln == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve vuln via vulnID")
		} else if vuln == nil && !ingestOrIDProvided {
			return nil, nil
		}
	}

	return &model.CertifyVEXStatement{
		ID:               link.ThisID,
		Subject:          subj,
		Vulnerability:    vuln,
		Status:           link.Status,
		VexJustification: link.Justification,
		Statement:        link.Statement,
		StatusNotes:      link.StatusNotes,
		KnownSince:       link.KnownSince,
		Origin:           link.Origin,
		Collector:        link.Collector,
	}, nil
}
