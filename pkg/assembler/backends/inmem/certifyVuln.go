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

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: link between packages and vulnerabilities (certifyVulnerability)
type certifyVulnerabilityList []*certifyVulnerabilityLink
type certifyVulnerabilityLink struct {
	id              uint32
	packageID       uint32
	vulnerabilityID uint32
	timeScanned     time.Time
	dbURI           string
	dbVersion       string
	scannerURI      string
	scannerVersion  string
	origin          string
	collector       string
}

func (n *certifyVulnerabilityLink) ID() uint32 { return n.id }

func (n *certifyVulnerabilityLink) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 2)
	if allowedEdges[model.EdgeCertifyVulnPackage] {
		out = append(out, n.packageID)
	}
	if n.vulnerabilityID != 0 && allowedEdges[model.EdgeCertifyVulnVulnerability] {
		out = append(out, n.vulnerabilityID)
	}
	return out
}

func (n *certifyVulnerabilityLink) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildCertifyVulnerability(n, nil, true)
}

// Ingest CertifyVuln
func (c *demoClient) IngestCertifyVulns(ctx context.Context, pkgs []*model.PkgInputSpec, vulnerabilities []*model.VulnerabilityInputSpec, certifyVulns []*model.ScanMetadataInput) ([]*model.CertifyVuln, error) {
	var modelCertifyVulnList []*model.CertifyVuln
	for i := range certifyVulns {
		certifyVuln, err := c.IngestCertifyVuln(ctx, *pkgs[i], *vulnerabilities[i], *certifyVulns[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestCertifyVuln failed with err: %v", err)
		}
		modelCertifyVulnList = append(modelCertifyVulnList, certifyVuln)
	}
	return modelCertifyVulnList, nil
}

func (c *demoClient) IngestCertifyVuln(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInputSpec, certifyVuln model.ScanMetadataInput) (*model.CertifyVuln, error) {
	return c.ingestVulnerability(ctx, pkg, vulnerability, certifyVuln, true)
}

func (c *demoClient) ingestVulnerability(ctx context.Context, packageArg model.PkgInputSpec, vulnerability model.VulnerabilityInputSpec, certifyVuln model.ScanMetadataInput, readOnly bool) (*model.CertifyVuln, error) {
	funcName := "IngestVulnerability"
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

	var vulnerabilityLinks []uint32

	vulnID, err := getVulnerabilityIDFromInput(c, vulnerability)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	foundVulnNode, err := byID[*vulnIDNode](vulnID, c)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	vulnerabilityLinks = foundVulnNode.certifyVulnLinks

	var searchIDs []uint32
	if len(packageVulns) < len(vulnerabilityLinks) {
		searchIDs = packageVulns
	} else {
		searchIDs = vulnerabilityLinks
	}

	// Don't insert duplicates
	duplicate := false
	collectedCertifyVulnLink := certifyVulnerabilityLink{}
	for _, id := range searchIDs {
		v, err := byID[*certifyVulnerabilityLink](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vulnMatch := false
		if vulnID != 0 && vulnID == v.vulnerabilityID {
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
		collectedCertifyVulnLink = certifyVulnerabilityLink{
			id:              c.getNextID(),
			packageID:       packageID,
			vulnerabilityID: vulnID,
			timeScanned:     certifyVuln.TimeScanned,
			dbURI:           certifyVuln.DbURI,
			dbVersion:       certifyVuln.DbVersion,
			scannerURI:      certifyVuln.ScannerURI,
			scannerVersion:  certifyVuln.ScannerVersion,
			origin:          certifyVuln.Origin,
			collector:       certifyVuln.Collector,
		}
		c.index[collectedCertifyVulnLink.id] = &collectedCertifyVulnLink
		c.certifyVulnerabilities = append(c.certifyVulnerabilities, &collectedCertifyVulnLink)
		// set the backlinks
		foundPackage.setVulnerabilityLinks(collectedCertifyVulnLink.id)
		if vulnID != 0 {
			foundVulnNode.setVulnerabilityLinks(collectedCertifyVulnLink.id)
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

	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*certifyVulnerabilityLink](id, c)
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
		pkgs, err := c.findPackageVersion(filter.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.certifyVulnLinks...)
		}
	}
	if !foundOne && filter != nil && filter.Vulnerability != nil &&
		filter.Vulnerability.NoVuln != nil && *filter.Vulnerability.NoVuln {

		exactVuln, err := c.exactVulnerability(&model.VulnerabilitySpec{
			Type:            ptrfrom.String(noVulnType),
			VulnerabilityID: ptrfrom.String(""),
		})
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.certifyVulnLinks...)
			foundOne = true
		}
	} else if !foundOne && filter != nil && filter.Vulnerability != nil {

		if filter.Vulnerability.NoVuln != nil && !*filter.Vulnerability.NoVuln {
			if filter.Vulnerability.Type != nil && *filter.Vulnerability.Type == noVulnType {
				return []*model.CertifyVuln{}, gqlerror.Errorf("novuln boolean set to false, cannot specify vulnerability type to be novuln")
			}
		}

		exactVuln, err := c.exactVulnerability(filter.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.certifyVulnLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyVuln
	if foundOne {
		for _, id := range search {
			link, err := byID[*certifyVulnerabilityLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addCVIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.certifyVulnerabilities {
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
	link *certifyVulnerabilityLink) ([]*model.CertifyVuln, error) {
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

func (c *demoClient) buildCertifyVulnerability(link *certifyVulnerabilityLink, filter *model.CertifyVulnSpec, ingestOrIDProvided bool) (*model.CertifyVuln, error) {
	var p *model.Package
	var vuln *model.Vulnerability
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
		if filter.Vulnerability != nil && link.vulnerabilityID != 0 {
			vuln, err = c.buildVulnResponse(link.vulnerabilityID, filter.Vulnerability)
			if err != nil {
				return nil, err
			}
			if filter.Vulnerability.NoVuln != nil && !*filter.Vulnerability.NoVuln {
				if vuln != nil {
					if vuln.Type == noVulnType {
						vuln = nil
					}
				}
			}
		}
	} else {
		if link.vulnerabilityID != 0 {
			vuln, err = c.buildVulnResponse(link.vulnerabilityID, nil)
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

	if link.vulnerabilityID != 0 {
		if vuln == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve vuln via vulnID")
		} else if vuln == nil && !ingestOrIDProvided {
			return nil, nil
		}
	}

	metadata := &model.ScanMetadata{
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
