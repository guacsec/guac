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

// Internal data: link between a package or an artifact with its corresponding vulnerability VEX statement
type vexList []*vexLink
type vexLink struct {
	id              string
	packageID       string
	artifactID      string
	vulnerabilityID string
	knownSince      time.Time
	status          model.VexStatus
	statement       string
	statusNotes     string
	justification   model.VexJustification
	origin          string
	collector       string
}

func (n *vexLink) ID() string { return n.id }

func (n *vexLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 2)
	if n.packageID != "" && allowedEdges[model.EdgeCertifyVexStatementPackage] {
		out = append(out, n.packageID)
	}
	if n.artifactID != "" && allowedEdges[model.EdgeCertifyVexStatementArtifact] {
		out = append(out, n.artifactID)
	}
	if n.vulnerabilityID != "" && allowedEdges[model.EdgeCertifyVexStatementVulnerability] {
		out = append(out, n.vulnerabilityID)
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

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var packageID string
	var foundPkgVersionNode *pkgVersionNode
	var artifactID string
	var foundArtStrct *artStruct
	var subjectVexLinks []string
	if subject.Package != nil {
		var err error
		packageID, err = getPackageIDFromInput(c, *subject.Package, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion})
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundPkgVersionNode, err = byID[*pkgVersionNode](packageID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		subjectVexLinks = foundPkgVersionNode.vexLinks
	} else {
		var err error
		artifactID, err = c.artifactIDByInput(ctx, subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundArtStrct, err = byID[*artStruct](artifactID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		subjectVexLinks = foundArtStrct.vexLinks
	}

	var vulnerabilityVexLinks []string
	vulnID, err := getVulnerabilityIDFromInput(c, vulnerability)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	foundVulnNode, err := byID[*vulnIDNode](vulnID, c)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	vulnerabilityVexLinks = foundVulnNode.vexLinks

	var searchIDs []string
	if len(subjectVexLinks) < len(vulnerabilityVexLinks) {
		searchIDs = subjectVexLinks
	} else {
		searchIDs = vulnerabilityVexLinks
	}

	// Don't insert duplicates
	duplicate := false
	collectedCertifyVexLink := vexLink{}
	for _, id := range searchIDs {
		v, err := byID[*vexLink](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vulnMatch := false
		subjectMatch := false
		if vulnID != "" && vulnID == v.vulnerabilityID {
			vulnMatch = true
		}
		if packageID != "" && packageID == v.packageID {
			subjectMatch = true
		}
		if artifactID != "" && artifactID == v.artifactID {
			subjectMatch = true
		}
		if vulnMatch && subjectMatch && vexStatement.KnownSince.Equal(v.knownSince) && vexStatement.VexJustification == v.justification &&
			vexStatement.Status == v.status && vexStatement.Statement == v.statement && vexStatement.StatusNotes == v.statusNotes &&
			vexStatement.Origin == v.origin && vexStatement.Collector == v.collector {

			collectedCertifyVexLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			v, err := c.ingestVEXStatement(ctx, subject, vulnerability, vexStatement, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return v, err
		}
		// store the link
		collectedCertifyVexLink = vexLink{
			id:              c.getNextID(),
			packageID:       packageID,
			artifactID:      artifactID,
			vulnerabilityID: vulnID,
			knownSince:      vexStatement.KnownSince.UTC(),
			status:          vexStatement.Status,
			justification:   vexStatement.VexJustification,
			statement:       vexStatement.Statement,
			statusNotes:     vexStatement.StatusNotes,
			origin:          vexStatement.Origin,
			collector:       vexStatement.Collector,
		}
		c.index[collectedCertifyVexLink.id] = &collectedCertifyVexLink
		c.vexs = append(c.vexs, &collectedCertifyVexLink)
		// set the backlinks
		if packageID != "" {
			foundPkgVersionNode.setVexLinks(collectedCertifyVexLink.id)
		}
		if artifactID != "" {
			foundArtStrct.setVexLinks(collectedCertifyVexLink.id)
		}
		if vulnID != "" {
			foundVulnNode.setVexLinks(collectedCertifyVexLink.id)
		}
	}

	// build return GraphQL type
	builtCertifyVex, err := c.buildCertifyVEXStatement(ctx, &collectedCertifyVexLink, nil, true)
	if err != nil {
		return nil, err
	}
	return builtCertifyVex, nil
}

// Query CertifyVex
func (c *demoClient) CertifyVEXStatement(ctx context.Context, filter *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "CertifyVEXStatement"

	if filter != nil && filter.ID != nil {
		link, err := byID[*vexLink](*filter.ID, c)
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
			search = append(search, exactArtifact.vexLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		pkgs, err := c.findPackageVersion(filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.vexLinks...)
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil {
		exactVuln, err := c.exactVulnerability(filter.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.vexLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyVEXStatement
	if foundOne {
		for _, id := range search {
			link, err := byID[*vexLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addVexIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.vexs {
			var err error
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

	if filter != nil && filter.KnownSince != nil && !filter.KnownSince.Equal(link.knownSince) {
		return out, nil
	}
	if filter != nil && filter.VexJustification != nil && *filter.VexJustification != link.justification {
		return out, nil
	}
	if filter != nil && filter.Status != nil && *filter.Status != link.status {
		return out, nil
	}
	if filter != nil && noMatch(filter.Statement, link.statement) {
		return out, nil
	}
	if filter != nil && noMatch(filter.StatusNotes, link.statusNotes) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.origin) {
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
	}

	if filter != nil && filter.Vulnerability != nil {
		if filter.Vulnerability != nil && link.vulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(link.vulnerabilityID, filter.Vulnerability)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.vulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(link.vulnerabilityID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	var subj model.PackageOrArtifact
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

	if link.vulnerabilityID != "" {
		if vuln == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve vuln via vulnID")
		} else if vuln == nil && !ingestOrIDProvided {
			return nil, nil
		}
	}

	certifyVuln := model.CertifyVEXStatement{
		ID:               link.id,
		Subject:          subj,
		Vulnerability:    vuln,
		Status:           link.status,
		VexJustification: link.justification,
		Statement:        link.statement,
		StatusNotes:      link.statusNotes,
		KnownSince:       link.knownSince,
		Origin:           link.origin,
		Collector:        link.collector,
	}
	return &certifyVuln, nil
}
