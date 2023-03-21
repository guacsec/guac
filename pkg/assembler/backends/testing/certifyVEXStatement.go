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

package testing

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal data: link between a package or an artifact with its corresponding vulnerability VEX statement
type vexList []*vexLink
type vexLink struct {
	id            uint32
	packageID     uint32
	artifactID    uint32
	cveID         uint32
	ghsaID        uint32
	knownSince    time.Time
	justification string
	origin        string
	collector     string
}

func (n *vexLink) getID() uint32 { return n.id }

// Ingest CertifyPkg
func (c *demoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.CveOrGhsaInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	err := helper.ValidatePackageOrArtifactInput(&subject, "IngestVEXStatement")
	if err != nil {
		return nil, err
	}
	err = helper.ValidateCveOrGhsaIngestionInput(vulnerability, "IngestVEXStatement")
	if err != nil {
		return nil, err
	}

	var packageID uint32
	var artifactID uint32
	subjectVexLinks := []uint32{}
	if subject.Package != nil {
		packageID, err = getPackageIDFromInput(c, *subject.Package, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion})
		if err != nil {
			return nil, err
		}
		foundPkgVersionNode, ok := c.index[packageID].(*pkgVersionNode)
		if ok {
			subjectVexLinks = append(subjectVexLinks, foundPkgVersionNode.vexLinks...)
		}
	} else {
		artifactID, err = getArtifactIDFromInput(c, *subject.Artifact)
		if err != nil {
			return nil, err
		}
		foundArtStrct, ok := c.index[artifactID].(*artStruct)
		if ok {
			subjectVexLinks = append(subjectVexLinks, foundArtStrct.vexLinks...)
		}
	}

	var cveID uint32
	var ghsaID uint32
	vulnerabilityVexLinks := []uint32{}
	if vulnerability.Cve != nil {
		cveID, err = getCveIDFromInput(c, *vulnerability.Cve)
		if err != nil {
			return nil, err
		}
		cveNode, ok := c.index[cveID].(*cveIDNode)
		if ok {
			vulnerabilityVexLinks = append(vulnerabilityVexLinks, cveNode.vexLinks...)
		}
	}

	if vulnerability.Ghsa != nil {
		ghsaID, err = getGhsaIDFromInput(c, *vulnerability.Ghsa)
		if err != nil {
			return nil, err
		}
		ghsaNode, ok := c.index[ghsaID].(*ghsaIDNode)
		if ok {
			vulnerabilityVexLinks = append(vulnerabilityVexLinks, ghsaNode.vexLinks...)
		}
	}

	searchIDs := []uint32{}
	if len(subjectVexLinks) > len(vulnerabilityVexLinks) {
		searchIDs = append(searchIDs, vulnerabilityVexLinks...)
	} else {
		searchIDs = append(searchIDs, subjectVexLinks...)
	}

	// Don't insert duplicates
	duplicate := false
	collectedCertifyVexLink := vexLink{}
	for _, id := range searchIDs {
		v, _ := c.vexLinkByID(id)
		vulnMatch := false
		subjectMatch := false
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
			vexStatement.Origin == v.origin && vexStatement.Collector == v.collector {

			collectedCertifyVexLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		// store the link
		collectedCertifyVexLink = vexLink{
			id:            c.getNextID(),
			packageID:     packageID,
			artifactID:    artifactID,
			cveID:         cveID,
			ghsaID:        ghsaID,
			knownSince:    vexStatement.KnownSince.UTC(),
			justification: vexStatement.Justification,
			origin:        vexStatement.Origin,
			collector:     vexStatement.Collector,
		}
		c.index[collectedCertifyVexLink.id] = &collectedCertifyVexLink
		c.vexs = append(c.vexs, &collectedCertifyVexLink)
		// set the backlinks
		if packageID != 0 {
			c.index[packageID].(*pkgVersionNode).setVexLinks(collectedCertifyVexLink.id)
		}
		if artifactID != 0 {
			c.index[packageID].(*pkgVersionNode).setVexLinks(collectedCertifyVexLink.id)
		}
		if cveID != 0 {
			c.index[cveID].(*cveIDNode).setVexLinks(collectedCertifyVexLink.id)
		}
		if ghsaID != 0 {
			c.index[ghsaID].(*ghsaIDNode).setVexLinks(collectedCertifyVexLink.id)
		}
	}

	// build return GraphQL type
	builtCertifyVex, err := buildCertifyVEXStatement(c, &collectedCertifyVexLink, nil, true)
	if err != nil {
		return nil, err
	}
	return builtCertifyVex, nil
}

// Query CertifyPkg
func (c *demoClient) CertifyVEXStatement(ctx context.Context, filter *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	err := helper.ValidatePackageOrArtifactQueryFilter(filter.Subject)
	if err != nil {
		return nil, err
	}
	err = helper.ValidateCveOrGhsaQueryFilter(filter.Vulnerability)
	if err != nil {
		return nil, err
	}
	out := []*model.CertifyVEXStatement{}

	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		node, ok := c.index[uint32(id)]
		if !ok {
			return nil, gqlerror.Errorf("ID does not match existing node")
		}
		if link, ok := node.(*vexLink); ok {
			foundCertifyVex, err := buildCertifyVEXStatement(c, link, filter, true)
			if err != nil {
				return nil, err
			}
			return []*model.CertifyVEXStatement{foundCertifyVex}, nil
		} else {
			return nil, gqlerror.Errorf("ID does not match expected node type for certifyVex")
		}
	}

	// TODO if any of the pkg/artifact/vulnerabilities are specified, ony search those backedges
	for _, link := range c.vexs {
		if filter != nil && filter.KnownSince != nil && filter.KnownSince.UTC() == link.knownSince {
			continue
		}
		if filter != nil && noMatch(filter.Justification, link.justification) {
			continue
		}
		if filter != nil && noMatch(filter.Collector, link.collector) {
			continue
		}
		if filter != nil && noMatch(filter.Origin, link.origin) {
			continue
		}

		foundCertifyVex, err := buildCertifyVEXStatement(c, link, filter, false)
		if err != nil {
			return nil, err
		}
		if foundCertifyVex == nil {
			continue
		}
		out = append(out, foundCertifyVex)
	}

	return out, nil
}

func buildCertifyVEXStatement(c *demoClient, link *vexLink, filter *model.CertifyVEXStatementSpec, ingestOrIDProvided bool) (*model.CertifyVEXStatement, error) {
	var p *model.Package
	var a *model.Artifact
	var cve *model.Cve
	var ghsa *model.Ghsa
	var err error
	if filter != nil && filter.Subject != nil {
		p, err = c.buildPackageResponse(link.packageID, filter.Subject.Package)
		if err != nil {
			return nil, err
		}
		a, err = c.buildArtifactResponse(link.artifactID, filter.Subject.Artifact)
		if err != nil {
			return nil, err
		}
	} else {
		p, err = c.buildPackageResponse(link.packageID, nil)
		if err != nil {
			return nil, err
		}
		a, err = c.buildArtifactResponse(link.artifactID, nil)
		if err != nil {
			return nil, err
		}
	}

	if filter != nil && filter.Vulnerability != nil {
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

	var vuln model.CveOrGhsa
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
		Justification: link.justification,
		KnownSince:    link.knownSince,
		Origin:        link.origin,
		Collector:     link.collector,
	}
	return &certifyVuln, nil
}

func (c *demoClient) vexLinkByID(id uint32) (*vexLink, error) {
	node, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find vexLink")
	}
	link, ok := node.(*vexLink)
	if !ok {
		return nil, errors.New("not an vexLink")
	}
	return link, nil
}
