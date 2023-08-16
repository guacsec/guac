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
	"reflect"
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
	noKnownVulnID  uint32
	timeScanned    time.Time
	dbURI          string
	dbVersion      string
	scannerURI     string
	scannerVersion string
	origin         string
	collector      string
}

func (n *vulnerabilityLink) ID() uint32 { return n.id }

func (n *vulnerabilityLink) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 2)
	if allowedEdges[model.EdgeCertifyVulnPackage] {
		out = append(out, n.packageID)
	}
	if n.osvID != 0 && allowedEdges[model.EdgeCertifyVulnOsv] {
		out = append(out, n.osvID)
	}
	if n.cveID != 0 && allowedEdges[model.EdgeCertifyVulnCve] {
		out = append(out, n.cveID)
	}
	if n.ghsaID != 0 && allowedEdges[model.EdgeCertifyVulnGhsa] {
		out = append(out, n.ghsaID)
	}
	if n.noKnownVulnID != 0 && allowedEdges[model.EdgeCertifyVulnNoVuln] {
		out = append(out, n.noKnownVulnID)
	}
	return out
}

func (n *vulnerabilityLink) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildCertifyVulnerability(n, nil, true)
}

// Ingest CertifyVuln
func (c *demoClient) IngestVulnerability(ctx context.Context, packageArg model.PkgInputSpec, vulnerability model.VulnerabilityInput, certifyVuln model.VulnerabilityMetaDataInput) (*model.CertifyVuln, error) {
	return c.ingestVulnerability(ctx, packageArg, vulnerability, certifyVuln, true)
}

func (c *demoClient) ingestVulnerability(ctx context.Context, packageArg model.PkgInputSpec, vulnerability model.VulnerabilityInput, certifyVuln model.VulnerabilityMetaDataInput, readOnly bool) (*model.CertifyVuln, error) {
	funcName := "IngestVulnerability"
	if err := helper.ValidateVulnerabilityIngestionInput(vulnerability, "IngestVulnerability", true); err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	packageID, err := getPackageIDFromInput(c, packageArg, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion})
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	foundPackage, err := byID[*pkgVersionNode](packageID, c)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	packageVulns := foundPackage.certifyVulnLinks

	var osvID uint32
	var foundOsvNode *osvNode
	var cveID uint32
	var foundCveNode *cveNode
	var ghsaID uint32
	var foundGhsaNode *ghsaNode
	var noKnownVulnID uint32
	var vulnerabilityLinks []uint32
	if vulnerability.Osv != nil {
		osvID, err = getOsvIDFromInput(c, *vulnerability.Osv)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundOsvNode, err = byID[*osvNode](osvID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vulnerabilityLinks = foundOsvNode.certifyVulnLinks
	} else if vulnerability.Cve != nil {
		cveID, err = getCveIDFromInput(c, *vulnerability.Cve)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundCveNode, err = byID[*cveNode](cveID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vulnerabilityLinks = foundCveNode.certifyVulnLinks
	} else if vulnerability.Ghsa != nil {
		ghsaID, err = getGhsaIDFromInput(c, *vulnerability.Ghsa)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		foundGhsaNode, err = byID[*ghsaNode](ghsaID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vulnerabilityLinks = foundGhsaNode.certifyVulnLinks
	} else {
		noKnownVulnID = c.noKnownVulnNode.id
		vulnerabilityLinks = c.noKnownVulnNode.certifyVulnLinks
	}

	var searchIDs []uint32
	if len(packageVulns) < len(vulnerabilityLinks) {
		searchIDs = packageVulns
	} else {
		searchIDs = vulnerabilityLinks
	}

	// Don't insert duplicates
	duplicate := false
	collectedCertifyVulnLink := vulnerabilityLink{}
	for _, id := range searchIDs {
		v, err := byID[*vulnerabilityLink](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
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
		if noKnownVulnID != 0 && noKnownVulnID == v.noKnownVulnID {
			vulnMatch = true
		}
		if vulnMatch && packageID == v.packageID && certifyVuln.TimeScanned.Equal(v.timeScanned) && certifyVuln.DbURI == v.dbURI &&
			certifyVuln.DbVersion == v.dbVersion && certifyVuln.ScannerURI == v.scannerURI && certifyVuln.ScannerVersion == v.scannerVersion &&
			certifyVuln.Origin == v.origin && certifyVuln.Collector == v.collector {

			collectedCertifyVulnLink = *v
			duplicate = true
			break
		}
	}

	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			cv, err := c.ingestVulnerability(ctx, packageArg, vulnerability, certifyVuln, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return cv, err
		}
		// store the link
		collectedCertifyVulnLink = vulnerabilityLink{
			id:             c.getNextID(),
			packageID:      packageID,
			osvID:          osvID,
			cveID:          cveID,
			ghsaID:         ghsaID,
			noKnownVulnID:  noKnownVulnID,
			timeScanned:    certifyVuln.TimeScanned,
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
		foundPackage.setVulnerabilityLinks(collectedCertifyVulnLink.id)
		if osvID != 0 {
			foundOsvNode.setVulnerabilityLinks(collectedCertifyVulnLink.id)
		}
		if cveID != 0 {
			foundCveNode.setVulnerabilityLinks(collectedCertifyVulnLink.id)
		}
		if ghsaID != 0 {
			foundGhsaNode.setVulnerabilityLinks(collectedCertifyVulnLink.id)
		}
		if noKnownVulnID != 0 {
			c.noKnownVulnNode.setVulnerabilityLinks(collectedCertifyVulnLink.id)
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
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "CertifyVuln"

	if filter != nil {
		if err := helper.ValidateVulnerabilityQueryFilter(filter.Vulnerability, true); err != nil {
			return nil, err
		}
	}

	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*vulnerabilityLink](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundCertifyVuln, err := c.buildCertifyVulnerability(link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyVuln{foundCertifyVuln}, nil
	}

	var search []uint32
	foundOne := false
	if filter != nil && filter.Package != nil {
		exactPackage, err := c.exactPackageVersion(filter.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactPackage != nil {
			search = append(search, exactPackage.certifyVulnLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil && filter.Vulnerability.Osv != nil {
		exactOSV, err := c.exactOSV(filter.Vulnerability.Osv)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactOSV != nil {
			search = append(search, exactOSV.certifyVulnLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil && filter.Vulnerability.Cve != nil {
		exactCVE, err := c.exactCVE(filter.Vulnerability.Cve)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactCVE != nil {
			search = append(search, exactCVE.certifyVulnLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil && filter.Vulnerability.Ghsa != nil {
		exactGHSA, err := c.exactGHSA(filter.Vulnerability.Ghsa)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactGHSA != nil {
			search = append(search, exactGHSA.certifyVulnLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil &&
		filter.Vulnerability.NoVuln != nil && *filter.Vulnerability.NoVuln {
		search = append(search, c.noKnownVulnNode.certifyVulnLinks...)
		foundOne = true
	}

	var out []*model.CertifyVuln
	if foundOne {
		for _, id := range search {
			link, err := byID[*vulnerabilityLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addCVIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.vulnerabilities {
			var err error
			out, err = c.addCVIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}

	return out, nil
}

func (c *demoClient) addCVIfMatch(out []*model.CertifyVuln,
	filter *model.CertifyVulnSpec,
	link *vulnerabilityLink) ([]*model.CertifyVuln, error) {
	if filter != nil && filter.TimeScanned != nil && !filter.TimeScanned.Equal(link.timeScanned) {
		return out, nil
	}
	if filter != nil && noMatch(filter.DbURI, link.dbURI) {
		return out, nil
	}
	if filter != nil && noMatch(filter.DbVersion, link.dbVersion) {
		return out, nil
	}
	if filter != nil && noMatch(filter.ScannerURI, link.scannerURI) {
		return out, nil
	}
	if filter != nil && noMatch(filter.ScannerVersion, link.scannerVersion) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.origin) {
		return out, nil
	}

	foundCertifyVuln, err := c.buildCertifyVulnerability(link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyVuln == nil || reflect.ValueOf(foundCertifyVuln.Vulnerability).IsNil() {
		return out, nil
	}
	return append(out, foundCertifyVuln), nil
}

func (c *demoClient) buildCertifyVulnerability(link *vulnerabilityLink, filter *model.CertifyVulnSpec, ingestOrIDProvided bool) (*model.CertifyVuln, error) {
	var p *model.Package
	var osv *model.Osv
	var cve *model.Cve
	var ghsa *model.Ghsa
	var noVuln *model.NoVuln
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

	if filter != nil && filter.Vulnerability != nil && filter.Vulnerability.NoVuln == nil {
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
		if filter.Vulnerability.NoVuln != nil && link.noKnownVulnID != 0 {
			noVuln, err = c.buildNoVulnResponse()
			if err != nil {
				return nil, err
			}
		}
	} else {
		if checkNoVulnFilter(filter, false) {
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
		if checkNoVulnFilter(filter, true) {
			if link.noKnownVulnID != 0 {
				noVuln, err = c.buildNoVulnResponse()
				if err != nil {
					return nil, err
				}
			}
		}
	}
	// if package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if p == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve package via packageID")
	} else if p == nil && !ingestOrIDProvided {
		return nil, nil
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
	if link.noKnownVulnID != 0 {
		vuln = noVuln
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

// Checks if the given filter satisfies the condition for NoVuln in the CertifyVulnSpec.
// It returns true if any of the following conditions are met:
// 1. The filter is nil.
// 2. The filter.Vulnerability is nil.
// 3. The value of filter.Vulnerability.NoVuln matches the expected value.
func checkNoVulnFilter(filter *model.CertifyVulnSpec, expected bool) bool {
	return filter == nil || filter.Vulnerability == nil || *filter.Vulnerability.NoVuln == expected
}
