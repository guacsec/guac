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

package inmem

import (
	"context"
	"strconv"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: link between a package or an artifact with its corresponding vulnerability VEX statement
type vexList []*vexLink
type vexLink struct {
	id            uint32
	packageID     uint32
	artifactID    uint32
	cveID         uint32
	ghsaID        uint32
	osvID         uint32
	knownSince    time.Time
	status        string
	justification string
	origin        string
	collector     string
}

func (n *vexLink) ID() uint32 { return n.id }

func (n *vexLink) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 2)
	if n.packageID != 0 && allowedEdges[model.EdgeCertifyVexStatementPackage] {
		out = append(out, n.packageID)
	}
	if n.artifactID != 0 && allowedEdges[model.EdgeCertifyVexStatementArtifact] {
		out = append(out, n.artifactID)
	}
	if n.cveID != 0 && allowedEdges[model.EdgeCertifyVexStatementCve] {
		out = append(out, n.cveID)
	}
	if n.ghsaID != 0 && allowedEdges[model.EdgeCertifyVexStatementGhsa] {
		out = append(out, n.ghsaID)
	}
	if n.osvID != 0 && allowedEdges[model.EdgeCertifyVexStatementOsv] {
		out = append(out, n.osvID)
	}
	return out
}

func (n *vexLink) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildCertifyVEXStatement(n, nil, true)
}

// Ingest CertifyVex

func (c *demoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	return c.ingestVEXStatement(ctx, subject, vulnerability, vexStatement, true)
}

func (c *demoClient) ingestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec, readOnly bool) (*model.CertifyVEXStatement, error) {
	funcName := "IngestVEXStatement"
	if err := helper.ValidatePackageOrArtifactInput(&subject, "IngestVEXStatement"); err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	if err := helper.ValidateVulnerabilityIngestionInput(vulnerability, "IngestVEXStatement", false); err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var packageID uint32
	var foundPkgVersionNode *pkgVersionNode
	var artifactID uint32
	var foundArtStrct *artStruct
	var subjectVexLinks []uint32
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
		artifactID, err = getArtifactIDFromInput(c, *subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundArtStrct, err = byID[*artStruct](artifactID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		subjectVexLinks = foundArtStrct.vexLinks
	}

	var osvID uint32
	var foundOsvNode *osvNode
	var cveID uint32
	var foundCveNode *cveNode
	var ghsaID uint32
	var foundGhsaNode *ghsaNode
	var vulnerabilityVexLinks []uint32
	if vulnerability.Osv != nil {
		var err error
		osvID, err = getOsvIDFromInput(c, *vulnerability.Osv)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundOsvNode, err = byID[*osvNode](osvID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vulnerabilityVexLinks = foundOsvNode.vexLinks
	} else if vulnerability.Cve != nil {
		var err error
		cveID, err = getCveIDFromInput(c, *vulnerability.Cve)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundCveNode, err = byID[*cveNode](cveID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vulnerabilityVexLinks = foundCveNode.vexLinks
	} else {
		var err error
		ghsaID, err = getGhsaIDFromInput(c, *vulnerability.Ghsa)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundGhsaNode, err = byID[*ghsaNode](ghsaID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vulnerabilityVexLinks = foundGhsaNode.vexLinks
	}

	var searchIDs []uint32
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
		if osvID != 0 && osvID == v.osvID {
			vulnMatch = true
		}
		if cveID != 0 && cveID == v.cveID {
			vulnMatch = true
		}
		if ghsaID != 0 && ghsaID == v.ghsaID {
			vulnMatch = true
		}
		if packageID != 0 && packageID == v.packageID {
			subjectMatch = true
		}
		if artifactID != 0 && artifactID == v.artifactID {
			subjectMatch = true
		}
		if vulnMatch && subjectMatch && vexStatement.KnownSince.UTC() == v.knownSince && vexStatement.Justification == v.justification &&
			vexStatement.Status == v.status && vexStatement.Origin == v.origin && vexStatement.Collector == v.collector {

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
			id:            c.getNextID(),
			packageID:     packageID,
			artifactID:    artifactID,
			cveID:         cveID,
			ghsaID:        ghsaID,
			osvID:         osvID,
			knownSince:    vexStatement.KnownSince.UTC(),
			status:        vexStatement.Status,
			justification: vexStatement.Justification,
			origin:        vexStatement.Origin,
			collector:     vexStatement.Collector,
		}
		c.index[collectedCertifyVexLink.id] = &collectedCertifyVexLink
		c.vexs = append(c.vexs, &collectedCertifyVexLink)
		// set the backlinks
		if packageID != 0 {
			foundPkgVersionNode.setVexLinks(collectedCertifyVexLink.id)
		}
		if artifactID != 0 {
			foundArtStrct.setVexLinks(collectedCertifyVexLink.id)
		}
		if osvID != 0 {
			foundOsvNode.setVexLinks(collectedCertifyVexLink.id)
		}
		if cveID != 0 {
			foundCveNode.setVexLinks(collectedCertifyVexLink.id)
		}
		if ghsaID != 0 {
			foundGhsaNode.setVexLinks(collectedCertifyVexLink.id)
		}
	}

	// build return GraphQL type
	builtCertifyVex, err := c.buildCertifyVEXStatement(&collectedCertifyVexLink, nil, true)
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
	if err := helper.ValidatePackageOrArtifactQueryFilter(filter.Subject); err != nil {
		return nil, err
	}
	if err := helper.ValidateVulnerabilityQueryFilter(filter.Vulnerability, false); err != nil {
		return nil, err
	}

	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*vexLink](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundCertifyVex, err := c.buildCertifyVEXStatement(link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyVEXStatement{foundCertifyVex}, nil
	}

	var search []uint32
	foundOne := false

	if filter != nil && filter.Subject != nil && filter.Subject.Artifact != nil {
		exactArtifact, err := c.artifactExact(filter.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.vexLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		exactPackage, err := c.exactPackageVersion(filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactPackage != nil {
			search = append(search, exactPackage.vexLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil && filter.Vulnerability.Osv != nil {
		exactOSV, err := c.exactOSV(filter.Vulnerability.Osv)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactOSV != nil {
			search = append(search, exactOSV.vexLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil && filter.Vulnerability.Cve != nil {
		exactCVE, err := c.exactCVE(filter.Vulnerability.Cve)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactCVE != nil {
			search = append(search, exactCVE.vexLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil && filter.Vulnerability.Ghsa != nil {
		exactGHSA, err := c.exactGHSA(filter.Vulnerability.Ghsa)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactGHSA != nil {
			search = append(search, exactGHSA.vexLinks...)
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
			out, err = c.addVexIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.vexs {
			var err error
			out, err = c.addVexIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addVexIfMatch(out []*model.CertifyVEXStatement,
	filter *model.CertifyVEXStatementSpec, link *vexLink) (
	[]*model.CertifyVEXStatement, error) {

	if filter != nil && filter.KnownSince != nil && filter.KnownSince.UTC() == link.knownSince {
		return out, nil
	}
	if filter != nil && noMatch(filter.Justification, link.justification) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Status, link.status) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.origin) {
		return out, nil
	}

	foundCertifyVex, err := c.buildCertifyVEXStatement(link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyVex == nil {
		return out, nil
	}
	return append(out, foundCertifyVex), nil

}

func (c *demoClient) buildCertifyVEXStatement(link *vexLink, filter *model.CertifyVEXStatementSpec, ingestOrIDProvided bool) (*model.CertifyVEXStatement, error) {
	var p *model.Package
	var a *model.Artifact
	var osv *model.Osv
	var cve *model.Cve
	var ghsa *model.Ghsa
	var err error
	if filter != nil && filter.Subject != nil {
		if filter.Subject.Package != nil && link.packageID != 0 {
			p, err = c.buildPackageResponse(link.packageID, filter.Subject.Package)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Artifact != nil && link.artifactID != 0 {
			a, err = c.buildArtifactResponse(link.artifactID, filter.Subject.Artifact)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.packageID != 0 {
			p, err = c.buildPackageResponse(link.packageID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.artifactID != 0 {
			a, err = c.buildArtifactResponse(link.artifactID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	if filter != nil && filter.Vulnerability != nil {
		if filter.Vulnerability.Osv != nil && link.osvID != 0 {
			osv, err = c.buildOsvResponse(link.osvID, filter.Vulnerability.Osv)
			if err != nil {
				return nil, err
			}
		}
		if filter.Vulnerability.Cve != nil && link.cveID != 0 {
			cve, err = c.buildCveResponse(link.cveID, filter.Vulnerability.Cve)
			if err != nil {
				return nil, err
			}
		}
		if filter.Vulnerability.Ghsa != nil && link.ghsaID != 0 {
			ghsa, err = c.buildGhsaResponse(link.ghsaID, filter.Vulnerability.Ghsa)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.osvID != 0 {
			osv, err = c.buildOsvResponse(link.osvID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.cveID != 0 {
			cve, err = c.buildCveResponse(link.cveID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.ghsaID != 0 {
			ghsa, err = c.buildGhsaResponse(link.ghsaID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	var subj model.PackageOrArtifact
	if link.packageID != 0 {
		if p == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve package via packageID")
		} else if p == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = p
	}
	if link.artifactID != 0 {
		if a == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve artifact via artifactID")
		} else if a == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = a
	}

	var vuln model.Vulnerability
	if link.osvID != 0 {
		if osv == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve osv via osvID")
		} else if osv == nil && !ingestOrIDProvided {
			return nil, nil
		}
		vuln = osv
	}
	if link.cveID != 0 {
		if cve == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve cve via cveID")
		} else if cve == nil && !ingestOrIDProvided {
			return nil, nil
		}
		vuln = cve
	}
	if link.ghsaID != 0 {
		if ghsa == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve ghsa via ghsaID")
		} else if ghsa == nil && !ingestOrIDProvided {
			return nil, nil
		}
		vuln = ghsa
	}

	certifyVuln := model.CertifyVEXStatement{
		ID:            nodeID(link.id),
		Subject:       subj,
		Vulnerability: vuln,
		Status:        link.status,
		Justification: link.justification,
		KnownSince:    link.knownSince,
		Origin:        link.origin,
		Collector:     link.collector,
	}
	return &certifyVuln, nil
}
