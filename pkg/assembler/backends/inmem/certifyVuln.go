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
	"errors"
	"strconv"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: link between packages and vulnerabilities (certifyVulnerability)
type vulnerabilityList []*vulnerabilityLink
type vulnerabilityLink struct {
	id             uint32
	packageID      uint32
	osvID          uint32
	cveID          uint32
	ghsaID         uint32
	timeScanned    time.Time
	dbURI          string
	dbVersion      string
	scannerURI     string
	scannerVersion string
	origin         string
	collector      string
}

func (n *vulnerabilityLink) ID() uint32 { return n.id }

func (n *vulnerabilityLink) Neighbors() []uint32 {
	out := make([]uint32, 0, 2)
	out = append(out, n.packageID)
	if n.osvID != 0 {
		out = append(out, n.osvID)
	}
	if n.cveID != 0 {
		out = append(out, n.cveID)
	}
	if n.ghsaID != 0 {
		out = append(out, n.ghsaID)
	}
	return out
}

func (n *vulnerabilityLink) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildCertifyVulnerability(n, nil, true)
}

// Ingest CertifyVuln
func (c *demoClient) IngestVulnerability(ctx context.Context, packageArg model.PkgInputSpec, vulnerability model.OsvCveOrGhsaInput, certifyVuln model.VulnerabilityMetaDataInput) (*model.CertifyVuln, error) {

	err := helper.ValidateOsvCveOrGhsaIngestionInput(vulnerability)
	if err != nil {
		return nil, err
	}
	packageID, err := getPackageIDFromInput(c, packageArg, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion})
	if err != nil {
		return nil, err
	}

	var osvID uint32
	var cveID uint32
	var ghsaID uint32
	vulnerabilityLinks := []uint32{}
	if vulnerability.Osv != nil {
		osvID, err = getOsvIDFromInput(c, *vulnerability.Osv)
		if err != nil {
			return nil, err
		}
		osvNode, ok := c.index[osvID].(*osvIDNode)
		if ok {
			vulnerabilityLinks = append(vulnerabilityLinks, osvNode.certifyVulnLinks...)
		}
	}

	if vulnerability.Cve != nil {
		cveID, err = getCveIDFromInput(c, *vulnerability.Cve)
		if err != nil {
			return nil, err
		}
		cveNode, ok := c.index[cveID].(*cveIDNode)
		if ok {
			vulnerabilityLinks = append(vulnerabilityLinks, cveNode.certifyVulnLinks...)
		}
	}

	if vulnerability.Ghsa != nil {
		ghsaID, err = getGhsaIDFromInput(c, *vulnerability.Ghsa)
		if err != nil {
			return nil, err
		}
		ghsaNode, ok := c.index[ghsaID].(*ghsaIDNode)
		if ok {
			vulnerabilityLinks = append(vulnerabilityLinks, ghsaNode.certifyVulnLinks...)
		}
	}

	packageVulns := []uint32{}
	foundPkgVersionNode, ok := c.index[packageID].(*pkgVersionNode)
	if ok {
		packageVulns = append(packageVulns, foundPkgVersionNode.certifyVulnLinks...)
	}

	searchIDs := []uint32{}
	if len(packageVulns) > len(vulnerabilityLinks) {
		searchIDs = append(searchIDs, vulnerabilityLinks...)
	} else {
		searchIDs = append(searchIDs, packageVulns...)
	}

	// Don't insert duplicates
	duplicate := false
	collectedCertifyVulnLink := vulnerabilityLink{}
	for _, id := range searchIDs {
		v, _ := c.vulnLinkByID(id)
		vulnMatch := false
		if osvID != 0 && osvID == v.osvID {
			vulnMatch = true
		}
		if cveID != 0 && cveID == v.cveID {
			vulnMatch = true
		}
		if ghsaID != 0 && ghsaID == v.ghsaID {
			vulnMatch = true
		}
		if vulnMatch && packageID == v.packageID && certifyVuln.TimeScanned.UTC() == v.timeScanned && certifyVuln.DbURI == v.dbURI &&
			certifyVuln.DbVersion == v.dbVersion && certifyVuln.ScannerURI == v.scannerURI && certifyVuln.ScannerVersion == v.scannerVersion &&
			certifyVuln.Origin == v.origin && certifyVuln.Collector == v.collector {

			collectedCertifyVulnLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		// store the link
		collectedCertifyVulnLink = vulnerabilityLink{
			id:             c.getNextID(),
			packageID:      packageID,
			osvID:          osvID,
			cveID:          cveID,
			ghsaID:         ghsaID,
			timeScanned:    certifyVuln.TimeScanned.UTC(),
			dbURI:          certifyVuln.DbURI,
			dbVersion:      certifyVuln.DbVersion,
			scannerURI:     certifyVuln.ScannerURI,
			scannerVersion: certifyVuln.ScannerVersion,
			origin:         certifyVuln.Origin,
			collector:      certifyVuln.Collector,
		}
		c.index[collectedCertifyVulnLink.id] = &collectedCertifyVulnLink
		c.vulnerabilities = append(c.vulnerabilities, &collectedCertifyVulnLink)
		// set the backlinks
		c.index[packageID].(*pkgVersionNode).setVulnerabilityLinks(collectedCertifyVulnLink.id)
		if osvID != 0 {
			c.index[osvID].(*osvIDNode).setVulnerabilityLinks(collectedCertifyVulnLink.id)
		}
		if cveID != 0 {
			c.index[cveID].(*cveIDNode).setVulnerabilityLinks(collectedCertifyVulnLink.id)
		}
		if ghsaID != 0 {
			c.index[ghsaID].(*ghsaIDNode).setVulnerabilityLinks(collectedCertifyVulnLink.id)
		}
	}

	// build return GraphQL type
	builtCertifyVuln, err := c.buildCertifyVulnerability(&collectedCertifyVulnLink, nil, true)
	if err != nil {
		return nil, err
	}
	return builtCertifyVuln, nil
}

// Query CertifyVuln
func (c *demoClient) CertifyVuln(ctx context.Context, filter *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	err := helper.ValidateOsvCveOrGhsaQueryFilter(filter.Vulnerability)
	if err != nil {
		return nil, err
	}
	out := []*model.CertifyVuln{}

	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		node, ok := c.index[uint32(id)]
		if !ok {
			return nil, gqlerror.Errorf("ID does not match existing node")
		}
		if link, ok := node.(*vulnerabilityLink); ok {
			foundCertifyVuln, err := c.buildCertifyVulnerability(link, filter, true)
			if err != nil {
				return nil, err
			}
			return []*model.CertifyVuln{foundCertifyVuln}, nil
		} else {
			return nil, gqlerror.Errorf("ID does not match expected node type for certifyVuln")
		}
	}

	// TODO if any of the pkg/vulnerabilities are specified, ony search those backedges
	for _, link := range c.vulnerabilities {
		if filter != nil && filter.TimeScanned != nil && filter.TimeScanned.UTC() == link.timeScanned {
			continue
		}
		if filter != nil && noMatch(filter.DbURI, link.dbURI) {
			continue
		}
		if filter != nil && noMatch(filter.DbVersion, link.dbVersion) {
			continue
		}
		if filter != nil && noMatch(filter.ScannerURI, link.scannerURI) {
			continue
		}
		if filter != nil && noMatch(filter.ScannerVersion, link.scannerVersion) {
			continue
		}
		if filter != nil && noMatch(filter.Collector, link.collector) {
			continue
		}
		if filter != nil && noMatch(filter.Origin, link.origin) {
			continue
		}

		foundCertifyVuln, err := c.buildCertifyVulnerability(link, filter, false)
		if err != nil {
			return nil, err
		}
		if foundCertifyVuln == nil {
			continue
		}
		out = append(out, foundCertifyVuln)
	}

	return out, nil
}

func (c *demoClient) buildCertifyVulnerability(link *vulnerabilityLink, filter *model.CertifyVulnSpec, ingestOrIDProvided bool) (*model.CertifyVuln, error) {
	var p *model.Package
	var osv *model.Osv
	var cve *model.Cve
	var ghsa *model.Ghsa
	var err error
	if filter != nil {
		p, err = c.buildPackageResponse(link.packageID, filter.Package)
		if err != nil {
			return nil, err
		}
	} else {
		p, err = c.buildPackageResponse(link.packageID, nil)
		if err != nil {
			return nil, err
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
	// if package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if p == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve package via packageID")
	} else if p == nil && !ingestOrIDProvided {
		return nil, nil
	}

	var vuln model.OsvCveOrGhsa
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

	metadata := &model.VulnerabilityMetaData{
		TimeScanned:    link.timeScanned,
		DbURI:          link.dbURI,
		DbVersion:      link.dbVersion,
		ScannerURI:     link.scannerURI,
		ScannerVersion: link.scannerVersion,
		Origin:         link.origin,
		Collector:      link.collector,
	}

	certifyVuln := model.CertifyVuln{
		ID:            nodeID(link.id),
		Package:       p,
		Vulnerability: vuln,
		Metadata:      metadata,
	}
	return &certifyVuln, nil
}

func (c *demoClient) vulnLinkByID(id uint32) (*vulnerabilityLink, error) {
	node, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find vulnerabilityLink")
	}
	link, ok := node.(*vulnerabilityLink)
	if !ok {
		return nil, errors.New("not an vulnerabilityLink")
	}
	return link, nil
}
