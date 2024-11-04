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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/maps"
)

const guacType string = "guac"

func (c *demoClient) FindSoftwareList(ctx context.Context, searchText string, after *string, first *int) (*model.FindSoftwareConnection, error) {
	return nil, fmt.Errorf("not implemented: FindSoftwareList")
}

func (c *demoClient) BatchQuerySubjectPkgDependency(ctx context.Context, pkgIDs []string) ([]*model.IsDependency, error) {
	var collectedIsDep []*model.IsDependency
	for _, pkgID := range pkgIDs {
		isDep, err := c.IsDependency(ctx, &model.IsDependencySpec{Package: &model.PkgSpec{ID: &pkgID}})
		if err != nil {
			return nil, fmt.Errorf("failed to query IsDependency for pkgID: %s, with error: %w", pkgID, err)
		}
		collectedIsDep = append(collectedIsDep, isDep...)
	}
	return collectedIsDep, nil
}

func (c *demoClient) BatchQueryDepPkgDependency(ctx context.Context, pkgIDs []string) ([]*model.IsDependency, error) {
	var collectedIsDep []*model.IsDependency
	for _, pkgID := range pkgIDs {
		isDep, err := c.IsDependency(ctx, &model.IsDependencySpec{DependencyPackage: &model.PkgSpec{ID: &pkgID}})
		if err != nil {
			return nil, fmt.Errorf("failed to query IsDependency for dependency pkgID: %s, with error: %w", pkgID, err)
		}
		collectedIsDep = append(collectedIsDep, isDep...)
	}
	return collectedIsDep, nil
}

func (c *demoClient) BatchQueryPkgIDCertifyVuln(ctx context.Context, pkgIDs []string) ([]*model.CertifyVuln, error) {
	pkgCVs := make(map[string][]*model.CertifyVuln)
	for _, pkgID := range pkgIDs {
		certVuln, err := c.CertifyVuln(ctx, &model.CertifyVulnSpec{Package: &model.PkgSpec{ID: &pkgID}})
		if err != nil {
			return nil, fmt.Errorf("failed to query CertifyVuln for pkgID: %s, with error: %w", pkgID, err)
		}
		pkgCVs[pkgID] = append(pkgCVs[pkgID], certVuln...)
	}

	deduplicatedPkgCVs := make(map[string][]*model.CertifyVuln)
	for _, certVulns := range pkgCVs {
		pkgID := certVulns[0].Package.Namespaces[0].Names[0].Versions[0].ID
		cvsByVulnID := make(map[string]*model.CertifyVuln)
		for _, cv := range certVulns {
			cv := cv
			vulnID := cv.Vulnerability.VulnerabilityIDs[0].VulnerabilityID
			if existing, ok := cvsByVulnID[vulnID]; ok {
				if existing.Metadata.TimeScanned.After(cv.Metadata.TimeScanned) {
					continue
				}
			}
			cvsByVulnID[vulnID] = cv
		}
		deduplicatedPkgCVs[pkgID] = append(deduplicatedPkgCVs[pkgID], maps.Values(cvsByVulnID)...)
	}

	var filteredCertVulns []*model.CertifyVuln
	for _, certVulns := range deduplicatedPkgCVs {
		filteredCertVulns = append(filteredCertVulns, certVulns...)
	}

	return filteredCertVulns, nil
}

func (c *demoClient) BatchQueryPkgIDCertifyLegal(ctx context.Context, pkgIDs []string) ([]*model.CertifyLegal, error) {
	pkgCLs := make(map[string][]*model.CertifyLegal)
	for _, pkgID := range pkgIDs {
		certLegal, err := c.CertifyLegal(ctx, &model.CertifyLegalSpec{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{ID: &pkgID}}})
		if err != nil {
			return nil, fmt.Errorf("failed to query CertifyLegal for pkgID: %s, with error: %w", pkgID, err)
		}
		pkgCLs[pkgID] = append(pkgCLs[pkgID], certLegal...)
	}

	deduplicatedPkgCLs := make(map[string]*model.CertifyLegal)
	for _, certLegals := range pkgCLs {
		if pkg, ok := certLegals[0].Subject.(*model.Package); ok {
			var latest time.Time
			pkgID := pkg.Namespaces[0].Names[0].Versions[0].ID
			for _, cl := range certLegals {
				if cl.TimeScanned.After(latest) {
					latestcl := cl
					latest = cl.TimeScanned
					deduplicatedPkgCLs[pkgID] = latestcl
				}
			}
		} else {
			continue
		}
	}

	var filteredCertLegals []*model.CertifyLegal
	for _, certLegal := range deduplicatedPkgCLs {
		filteredCertLegals = append(filteredCertLegals, certLegal)
	}

	return filteredCertLegals, nil
}

func (c *demoClient) FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error) {
	scanner := c.kv.Keys("artifacts")
	var res []model.PackageSourceOrArtifact

	for {
		keys, end, err := scanner.Scan(ctx)
		if err != nil {
			return nil, fmt.Errorf("error scanning artifacts %v", err)
		}

		if keys == nil {
			break
		}

		for _, key := range keys {
			var pkg *artStruct
			err := c.kv.Get(ctx, "artifacts", key, &pkg)
			if err != nil {
				continue
			}

			if strings.Contains(pkg.Digest, searchText) {
				res = append(res, c.convArtifact(pkg))
			}
		}

		if end {
			break
		}
	}

	packagesWithSearchText, err := c.searchPackages(ctx, searchText)
	if err != nil {
		return nil, fmt.Errorf("error searching packages, %v", err)
	}

	for _, p := range packagesWithSearchText {
		res = append(res, p)
	}

	sourcesWithSearchText, err := c.searchSources(ctx, searchText)
	if err != nil {
		return nil, fmt.Errorf("error searching sources, %v", err)
	}

	for _, s := range sourcesWithSearchText {
		res = append(res, s)
	}

	return res, nil
}

func (c *demoClient) searchSources(ctx context.Context, searchText string) ([]*model.Source, error) {
	c.m.RLock()
	defer c.m.RUnlock()

	var out []*model.Source
	var done bool
	scn := c.kv.Keys(srcTypeCol)

	for !done {
		var typeKeys []string
		var err error
		typeKeys, done, err = scn.Scan(ctx)
		if err != nil {
			return nil, err
		}

		for _, tk := range typeKeys {
			srcTypeNode, err := byKeykv[*srcType](ctx, srcTypeCol, tk, c)
			if err != nil {
				return nil, err
			}
			sNamespaces := c.searchSourceNamespace(ctx, srcTypeNode, searchText, strings.Contains(srcTypeNode.Type, searchText))
			if len(sNamespaces) > 0 {
				out = append(out, &model.Source{
					ID:         srcTypeNode.ThisID,
					Type:       srcTypeNode.Type,
					Namespaces: sNamespaces,
				})
			}
		}
	}
	return out, nil
}

func (c *demoClient) searchSourceNamespace(ctx context.Context, srcTypeNode *srcType, searchText string, foundText bool) []*model.SourceNamespace {
	var sNamespaces []*model.SourceNamespace
	for _, nsID := range srcTypeNode.Namespaces {
		srcNS, err := byIDkv[*srcNamespace](ctx, nsID, c)
		if err != nil {
			continue
		}
		sns := c.searchSourceName(ctx, srcNS, searchText, foundText || strings.Contains(srcNS.Namespace, searchText))
		if len(sns) > 0 {
			sNamespaces = append(sNamespaces, &model.SourceNamespace{
				ID:        srcNS.ThisID,
				Namespace: srcNS.Namespace,
				Names:     sns,
			})
		}
	}
	return sNamespaces
}

func (c *demoClient) searchSourceName(ctx context.Context, srcNamespace *srcNamespace, searchText string, foundText bool) []*model.SourceName {
	var sns []*model.SourceName
	for _, nameID := range srcNamespace.Names {
		s, err := byIDkv[*srcNameNode](ctx, nameID, c)
		if err != nil {
			return nil
		}

		if foundText || strings.Contains(s.Name, searchText) {
			m := &model.SourceName{
				ID:   s.ThisID,
				Name: s.Name,
			}
			if s.Tag != "" {
				m.Tag = &s.Tag
			}
			if s.Commit != "" {
				m.Commit = &s.Commit
			}
			sns = append(sns, m)
		}
	}
	return sns
}

func (c *demoClient) searchPackages(ctx context.Context, searchText string) ([]*model.Package, error) {
	c.m.RLock()
	defer c.m.RUnlock()

	var out []*model.Package
	var done bool
	scn := c.kv.Keys(pkgTypeCol)

	for !done {
		var typeKeys []string
		var err error
		typeKeys, done, err = scn.Scan(ctx)
		if err != nil {
			return nil, err
		}

		for _, tk := range typeKeys {
			pkgTypeNode, err := byKeykv[*pkgType](ctx, pkgTypeCol, tk, c)
			if err != nil {
				return nil, err
			}
			pNamespaces := c.searchPkgNamespaces(ctx, pkgTypeNode, searchText, strings.Contains(pkgTypeNode.Type, searchText))
			if len(pNamespaces) > 0 {
				out = append(out, &model.Package{
					ID:         pkgTypeNode.ThisID,
					Type:       pkgTypeNode.Type,
					Namespaces: pNamespaces,
				})
			}
		}
	}
	return out, nil
}

func (c *demoClient) searchPkgNamespaces(ctx context.Context, pkgTypeNode *pkgType, searchText string, foundText bool) []*model.PackageNamespace {
	var pNamespaces []*model.PackageNamespace

	for _, nsID := range pkgTypeNode.Namespaces {
		pkgNS, err := byIDkv[*pkgNamespace](ctx, nsID, c)
		if err != nil {
			continue
		}

		pns := c.searchPkgNames(ctx, pkgNS, searchText, foundText || strings.Contains(pkgNS.Namespace, searchText))
		if len(pns) > 0 {
			pNamespaces = append(pNamespaces, &model.PackageNamespace{
				ID:        pkgNS.ThisID,
				Namespace: pkgNS.Namespace,
				Names:     pns,
			})
		}
	}
	return pNamespaces
}

func (c *demoClient) searchPkgNames(ctx context.Context, pkgNS *pkgNamespace, searchText string, foundText bool) []*model.PackageName {
	var pns []*model.PackageName

	for _, nameID := range pkgNS.Names {
		pkgNameNode, err := byIDkv[*pkgName](ctx, nameID, c)
		if err != nil {
			continue
		}

		pvs := c.searchPkgVersion(ctx, pkgNameNode, searchText, foundText || strings.Contains(pkgNameNode.Name, searchText))
		if len(pvs) > 0 {
			pns = append(pns, &model.PackageName{
				ID:       pkgNameNode.ThisID,
				Name:     pkgNameNode.Name,
				Versions: pvs,
			})
		}
	}

	return pns
}

func (c *demoClient) searchPkgVersion(ctx context.Context, pkgNameNode *pkgName, searchText string, foundText bool) []*model.PackageVersion {
	var pvs []*model.PackageVersion

	for _, verID := range pkgNameNode.Versions {
		pkgVer, err := byIDkv[*pkgVersion](ctx, verID, c)
		if err != nil {
			continue
		}

		if foundText || strings.Contains(pkgVer.Version, searchText) {
			pvs = append(pvs, &model.PackageVersion{
				ID:         pkgVer.ThisID,
				Version:    pkgVer.Version,
				Subpath:    pkgVer.Subpath,
				Qualifiers: getCollectedPackageQualifiers(pkgVer.Qualifiers),
			})
		}
	}

	return pvs
}

func (c *demoClient) FindPackagesThatNeedScanning(ctx context.Context, queryType model.QueryType, lastScan *int) ([]string, error) {
	c.m.RLock()
	defer c.m.RUnlock()

	var pkgIDs []string
	var done bool
	scn := c.kv.Keys(pkgTypeCol)
	for !done {
		var typeKeys []string
		var err error
		typeKeys, done, err = scn.Scan(ctx)
		if err != nil {
			return nil, err
		}

		sort.Strings(typeKeys)

		for _, tk := range typeKeys {
			pkgTypeNode, err := byKeykv[*pkgType](ctx, pkgTypeCol, tk, c)
			if err != nil {
				return nil, err
			}
			if pkgTypeNode.Type == guacType {
				continue
			}
			for _, nsID := range pkgTypeNode.Namespaces {
				pkgNS, err := byIDkv[*pkgNamespace](ctx, nsID, c)
				if err != nil {
					continue
				}
				for _, nameID := range pkgNS.Names {
					pkgNameNode, err := byIDkv[*pkgName](ctx, nameID, c)
					if err != nil {
						continue
					}
					for _, verID := range pkgNameNode.Versions {
						pkgVer, err := byIDkv[*pkgVersion](ctx, verID, c)
						if err != nil {
							continue
						}
						if queryType == model.QueryTypeVulnerability {
							if len(pkgVer.CertifyVulnLinks) > 0 {
								var timeScanned []time.Time
								for _, certVulnID := range pkgVer.CertifyVulnLinks {
									link, err := byIDkv[*certifyVulnerabilityLink](ctx, certVulnID, c)
									if err != nil {
										continue
									}
									timeScanned = append(timeScanned, link.TimeScanned)
								}
								lastScanTime := latestTime(timeScanned)
								lastIntervalTime := time.Now().Add(time.Duration(-*lastScan) * time.Hour).UTC()
								if lastScanTime.Before(lastIntervalTime) {
									pkgIDs = append(pkgIDs, pkgVer.ThisID)
								}
							} else {
								pkgIDs = append(pkgIDs, pkgVer.ThisID)
							}
						} else if queryType == model.QueryTypeLicense {
							if len(pkgVer.CertifyLegals) > 0 {
								var timeScanned []time.Time
								for _, certLegalID := range pkgVer.CertifyLegals {
									link, err := byIDkv[*certifyLegalStruct](ctx, certLegalID, c)
									if err != nil {
										continue
									}
									timeScanned = append(timeScanned, link.TimeScanned)
								}
								lastScanTime := latestTime(timeScanned)
								lastIntervalTime := time.Now().Add(time.Duration(-*lastScan) * time.Hour).UTC()
								if lastScanTime.Before(lastIntervalTime) {
									pkgIDs = append(pkgIDs, pkgVer.ThisID)

								}
							} else {
								pkgIDs = append(pkgIDs, pkgVer.ThisID)
							}
						} else { // queryType == model.QueryTypeEol via hasMetadataLink
							if len(pkgVer.HasMetadataLinks) > 0 {
								var timeScanned []time.Time
								for _, hasMetadataLinkID := range pkgVer.HasMetadataLinks {
									link, err := byIDkv[*hasMetadataLink](ctx, hasMetadataLinkID, c)
									if err != nil {
										continue
									}
									// only pick endoflife metadata
									if link.MDKey != "endoflife" {
										continue
									}
									timeScanned = append(timeScanned, link.Timestamp)
								}
								lastScanTime := latestTime(timeScanned)
								lastIntervalTime := time.Now().Add(time.Duration(-*lastScan) * time.Hour).UTC()
								if lastScanTime.Before(lastIntervalTime) {
									pkgIDs = append(pkgIDs, pkgVer.ThisID)
								}
							} else {
								pkgIDs = append(pkgIDs, pkgVer.ThisID)
							}
						}
					}
				}
			}
		}
	}
	return pkgIDs, nil
}

func (c *demoClient) QueryPackagesListForScan(ctx context.Context, pkgIDs []string, after *string, first *int) (*model.PackageConnection, error) {
	c.m.RLock()
	defer c.m.RUnlock()

	var edges []*model.PackageEdge
	for _, pkgID := range pkgIDs {
		p, err := c.buildPackageResponse(ctx, pkgID, nil)
		if err != nil {
			if errors.Is(err, errNotFound) {
				// not found
				return nil, nil
			}
			return nil, err
		}
		edges = append(edges, &model.PackageEdge{
			Cursor: p.ID,
			Node:   p,
		})
	}

	return &model.PackageConnection{
		TotalCount: len(pkgIDs),
		PageInfo: &model.PageInfo{
			HasNextPage: false,
			StartCursor: ptrfrom.String(pkgIDs[0]),
			EndCursor:   ptrfrom.String(pkgIDs[len(pkgIDs)-1]),
		},
		Edges: edges,
	}, nil
}

// Get the latest time from a slice of time.Time
func latestTime(times []time.Time) time.Time {
	if len(times) == 0 {
		return time.Time{} // Return zero value of time.Time if slice is empty
	}

	latest := times[0] // Initialize with the first time in the slice
	for _, t := range times {
		if t.After(latest) {
			latest = t
		}
	}
	return latest
}
