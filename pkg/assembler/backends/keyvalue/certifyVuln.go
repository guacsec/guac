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
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: link between packages and vulnerabilities (certifyVulnerability)
type certifyVulnerabilityLink struct {
	ThisID          string
	PackageID       string
	VulnerabilityID string
	TimeScanned     time.Time
	DBURI           string
	DBVersion       string
	ScannerURI      string
	ScannerVersion  string
	Origin          string
	Collector       string
	DocumentRef     string
}

func (n *certifyVulnerabilityLink) ID() string { return n.ThisID }
func (n *certifyVulnerabilityLink) Key() string {
	return hashKey(strings.Join([]string{
		n.PackageID,
		n.VulnerabilityID,
		timeKey(n.TimeScanned),
		n.DBURI,
		n.DBVersion,
		n.ScannerURI,
		n.ScannerVersion,
		n.Origin,
		n.Collector,
		n.DocumentRef,
	}, ":"))
}

func (n *certifyVulnerabilityLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 2)
	if allowedEdges[model.EdgeCertifyVulnPackage] {
		out = append(out, n.PackageID)
	}
	if allowedEdges[model.EdgeCertifyVulnVulnerability] {
		out = append(out, n.VulnerabilityID)
	}
	return out
}

func (n *certifyVulnerabilityLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildCertifyVulnerability(ctx, n, nil, true)
}

// Ingest CertifyVuln
func (c *demoClient) IngestCertifyVulns(ctx context.Context, pkgs []*model.IDorPkgInput, vulnerabilities []*model.IDorVulnerabilityInput, certifyVulns []*model.ScanMetadataInput) ([]string, error) {
	var modelCertifyVulnList []string
	for i := range certifyVulns {
		certifyVuln, err := c.IngestCertifyVuln(ctx, *pkgs[i], *vulnerabilities[i], *certifyVulns[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestCertifyVuln failed with err: %v", err)
		}
		modelCertifyVulnList = append(modelCertifyVulnList, certifyVuln)
	}
	return modelCertifyVulnList, nil
}

func (c *demoClient) IngestCertifyVuln(ctx context.Context, pkg model.IDorPkgInput, vulnerability model.IDorVulnerabilityInput, certifyVuln model.ScanMetadataInput) (string, error) {
	return c.ingestVulnerability(ctx, pkg, vulnerability, certifyVuln, true)
}

func (c *demoClient) ingestVulnerability(ctx context.Context, packageArg model.IDorPkgInput, vulnerability model.IDorVulnerabilityInput, certifyVuln model.ScanMetadataInput, readOnly bool) (string, error) {
	funcName := "IngestVulnerability"

	in := &certifyVulnerabilityLink{
		TimeScanned:    certifyVuln.TimeScanned.UTC(),
		DBURI:          certifyVuln.DbURI,
		DBVersion:      certifyVuln.DbVersion,
		ScannerURI:     certifyVuln.ScannerURI,
		ScannerVersion: certifyVuln.ScannerVersion,
		Origin:         certifyVuln.Origin,
		Collector:      certifyVuln.Collector,
		DocumentRef:    certifyVuln.DocumentRef,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	foundPackage, err := c.returnFoundPkgVersion(ctx, &packageArg)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	in.PackageID = foundPackage.ID()

	foundVulnNode, err := c.returnFoundVulnerability(ctx, &vulnerability)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	in.VulnerabilityID = foundVulnNode.ID()

	out, err := byKeykv[*certifyVulnerabilityLink](ctx, cVulnCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		cv, err := c.ingestVulnerability(ctx, packageArg, vulnerability, certifyVuln, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return cv, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, cVulnCol, in); err != nil {
		return "", err
	}
	// set the backlinks
	if err := foundPackage.setVulnerabilityLinks(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := foundVulnNode.setVulnerabilityLinks(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := setkv(ctx, cVulnCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

// Query CertifyVuln

func (c *demoClient) CertifyVulnList(ctx context.Context, certifyVulnSpec model.CertifyVulnSpec, after *string, first *int) (*model.CertifyVulnConnection, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "CertifyVuln"

	if certifyVulnSpec.ID != nil {
		link, err := byIDkv[*certifyVulnerabilityLink](ctx, *certifyVulnSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundCertifyVuln, err := c.buildCertifyVulnerability(ctx, link, &certifyVulnSpec, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return &model.CertifyVulnConnection{
			TotalCount: 1,
			PageInfo: &model.PageInfo{
				HasNextPage: false,
				StartCursor: ptrfrom.String(foundCertifyVuln.ID),
				EndCursor:   ptrfrom.String(foundCertifyVuln.ID),
			},
			Edges: []*model.CertifyVulnEdge{
				{
					Cursor: foundCertifyVuln.ID,
					Node:   foundCertifyVuln,
				},
			},
		}, nil
	}

	edges := make([]*model.CertifyVulnEdge, 0)
	hasNextPage := false
	numNodes := 0
	totalCount := 0

	var search []string
	foundOne := false

	if certifyVulnSpec.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, certifyVulnSpec.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.CertifyVulnLinks...)
		}
	}

	if !foundOne && certifyVulnSpec.Vulnerability != nil &&
		certifyVulnSpec.Vulnerability.NoVuln != nil && *certifyVulnSpec.Vulnerability.NoVuln {
		exactVuln, err := c.exactVulnerability(ctx, &model.VulnerabilitySpec{
			Type:            ptrfrom.String(noVulnType),
			VulnerabilityID: ptrfrom.String(""),
		})
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.CertifyVulnLinks...)
			foundOne = true
		}
	} else if !foundOne && certifyVulnSpec.Vulnerability != nil {
		if certifyVulnSpec.Vulnerability.NoVuln != nil && !*certifyVulnSpec.Vulnerability.NoVuln {
			if certifyVulnSpec.Vulnerability.Type != nil && *certifyVulnSpec.Vulnerability.Type == noVulnType {
				return nil, gqlerror.Errorf("novuln boolean set to false, cannot specify vulnerability type to be novuln")
			}
		}
		exactVuln, err := c.exactVulnerability(ctx, certifyVulnSpec.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.CertifyVulnLinks...)
			foundOne = true
		}
	}

	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*certifyVulnerabilityLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			cv, err := c.certifyVulnIfMatch(ctx, &certifyVulnSpec, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}

			edges = append(edges, &model.CertifyVulnEdge{
				Cursor: cv.ID,
				Node:   cv,
			})
		}
	} else {
		currentPage := false

		// If no cursor present start from the top
		if after == nil {
			currentPage = true
		}
		var done bool
		scn := c.kv.Keys(cVulnCol)
		for !done {
			var keys []string
			var err error
			keys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}

			sort.Strings(keys)
			totalCount = len(keys)

			for i, key := range keys {
				link, err := byKeykv[*certifyVulnerabilityLink](ctx, cVulnCol, key, c)
				if err != nil {
					return nil, err
				}
				cv, err := c.certifyVulnIfMatch(ctx, &certifyVulnSpec, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}

				if after != nil && !currentPage {
					if cv.ID == *after {
						totalCount = len(keys) - (i + 1)
						currentPage = true
					}
					continue
				}

				if first != nil {
					if numNodes < *first {
						edges = append(edges, &model.CertifyVulnEdge{
							Cursor: cv.ID,
							Node:   cv,
						})
						numNodes++
					} else if numNodes == *first {
						hasNextPage = true
					}
				} else {
					edges = append(edges, &model.CertifyVulnEdge{
						Cursor: cv.ID,
						Node:   cv,
					})
				}
			}
		}
	}

	if len(edges) != 0 {
		return &model.CertifyVulnConnection{
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

func (c *demoClient) CertifyVuln(ctx context.Context, filter *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "CertifyVuln"

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*certifyVulnerabilityLink](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundCertifyVuln, err := c.buildCertifyVulnerability(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyVuln{foundCertifyVuln}, nil
	}

	var search []string
	foundOne := false

	if filter != nil && filter.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, filter.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.CertifyVulnLinks...)
		}
	}

	if !foundOne && filter != nil && filter.Vulnerability != nil &&
		filter.Vulnerability.NoVuln != nil && *filter.Vulnerability.NoVuln {
		exactVuln, err := c.exactVulnerability(ctx, &model.VulnerabilitySpec{
			Type:            ptrfrom.String(noVulnType),
			VulnerabilityID: ptrfrom.String(""),
		})
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.CertifyVulnLinks...)
			foundOne = true
		}
	} else if !foundOne && filter != nil && filter.Vulnerability != nil {
		if filter.Vulnerability.NoVuln != nil && !*filter.Vulnerability.NoVuln {
			if filter.Vulnerability.Type != nil && *filter.Vulnerability.Type == noVulnType {
				return nil, gqlerror.Errorf("novuln boolean set to false, cannot specify vulnerability type to be novuln")
			}
		}
		exactVuln, err := c.exactVulnerability(ctx, filter.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.CertifyVulnLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyVuln
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*certifyVulnerabilityLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			cv, err := c.certifyVulnIfMatch(ctx, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out = append(out, cv)
		}
	} else {
		var done bool
		scn := c.kv.Keys(cVulnCol)
		for !done {
			var keys []string
			var err error
			keys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, key := range keys {
				link, err := byKeykv[*certifyVulnerabilityLink](ctx, cVulnCol, key, c)
				if err != nil {
					return nil, err
				}
				cv, err := c.certifyVulnIfMatch(ctx, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
				out = append(out, cv)
			}
		}
	}

	return out, nil
}

func (c *demoClient) certifyVulnIfMatch(ctx context.Context, filter *model.CertifyVulnSpec, link *certifyVulnerabilityLink) (
	*model.CertifyVuln, error) {
	if filter != nil && filter.TimeScanned != nil && !filter.TimeScanned.Equal(link.TimeScanned) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.DbURI, link.DBURI) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.DbVersion, link.DBVersion) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.ScannerURI, link.ScannerURI) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.ScannerVersion, link.ScannerVersion) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.DocumentRef, link.DocumentRef) {
		return nil, nil
	}

	foundCertifyVuln, err := c.buildCertifyVulnerability(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyVuln == nil || reflect.ValueOf(foundCertifyVuln.Vulnerability).IsNil() {
		return nil, nil
	}
	return foundCertifyVuln, nil
}

func (c *demoClient) buildCertifyVulnerability(ctx context.Context, link *certifyVulnerabilityLink, filter *model.CertifyVulnSpec, ingestOrIDProvided bool) (*model.CertifyVuln, error) {
	var p *model.Package
	var vuln *model.Vulnerability
	var err error
	if filter != nil {
		p, err = c.buildPackageResponse(ctx, link.PackageID, filter.Package)
		if err != nil {
			return nil, err
		}
	} else {
		p, err = c.buildPackageResponse(ctx, link.PackageID, nil)
		if err != nil {
			return nil, err
		}
	}

	if filter != nil && filter.Vulnerability != nil {
		if filter.Vulnerability != nil && link.VulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(ctx, link.VulnerabilityID, filter.Vulnerability)
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
		if link.VulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(ctx, link.VulnerabilityID, nil)
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

	if link.VulnerabilityID != "" {
		if vuln == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve vuln via vulnID")
		} else if vuln == nil && !ingestOrIDProvided {
			return nil, nil
		}
	}

	return &model.CertifyVuln{
		ID:            link.ThisID,
		Package:       p,
		Vulnerability: vuln,
		Metadata: &model.ScanMetadata{
			TimeScanned:    link.TimeScanned,
			DbURI:          link.DBURI,
			DbVersion:      link.DBVersion,
			ScannerURI:     link.ScannerURI,
			ScannerVersion: link.ScannerVersion,
			Origin:         link.Origin,
			Collector:      link.Collector,
			DocumentRef:    link.DocumentRef,
		},
	}, nil
}
