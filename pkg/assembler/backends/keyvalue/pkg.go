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
	"reflect"
	"slices"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: Packages
type pkgType struct {
	ThisID     string
	Type       string
	Namespaces []string
}
type pkgNamespace struct {
	ThisID    string
	Parent    string
	Namespace string
	Names     []string
}
type pkgName struct {
	ThisID              string
	Parent              string
	Name                string
	Versions            []string
	SrcMapLinks         []string
	IsDependencyLinks   []string
	BadLinks            []string
	GoodLinks           []string
	HasMetadataLinks    []string
	PointOfContactLinks []string
}
type pkgVersion struct {
	ThisID              string
	Parent              string
	Version             string
	Subpath             string
	Qualifiers          map[string]string
	SrcMapLinks         []string
	IsDependencyLinks   []string
	Occurrences         []string
	CertifyVulnLinks    []string
	HasSBOMs            []string
	VexLinks            []string
	BadLinks            []string
	GoodLinks           []string
	HasMetadataLinks    []string
	PointOfContactLinks []string
	PkgEquals           []string
	CertifyLegals       []string
}

// Be type safe, don't use any / interface{}
type pkgNameOrVersion interface {
	setSrcMapLinks(ctx context.Context, ID string, c *demoClient) error
	getSrcMapLinks() []string
	setIsDependencyLinks(ctx context.Context, ID string, c *demoClient) error
	getIsDependencyLinks() []string
	setCertifyBadLinks(ctx context.Context, ID string, c *demoClient) error
	getCertifyBadLinks() []string
	setCertifyGoodLinks(ctx context.Context, ID string, c *demoClient) error
	getCertifyGoodLinks() []string
	setHasMetadataLinks(ctx context.Context, ID string, c *demoClient) error
	getHasMetadataLinks() []string
	setPointOfContactLinks(ctx context.Context, ID string, c *demoClient) error
	getPointOfContactLinks() []string

	node
}

var _ pkgNameOrVersion = &pkgName{}
var _ pkgNameOrVersion = &pkgVersion{}

func (n *pkgType) ID() string      { return n.ThisID }
func (n *pkgNamespace) ID() string { return n.ThisID }
func (n *pkgName) ID() string      { return n.ThisID }
func (n *pkgVersion) ID() string   { return n.ThisID }

func (n *pkgType) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgePackageTypePackageNamespace] {
		return n.Namespaces
	}
	return nil
}
func (n *pkgNamespace) Neighbors(allowedEdges edgeMap) []string {
	var out []string
	if allowedEdges[model.EdgePackageNamespacePackageName] {
		out = append(out, n.Names...)
	}
	if allowedEdges[model.EdgePackageNamespacePackageType] {
		out = append(out, n.Parent)
	}
	return out
}
func (n *pkgName) Neighbors(allowedEdges edgeMap) []string {
	var out []string
	if allowedEdges[model.EdgePackageNamePackageNamespace] {
		out = append(out, n.Parent)
	}
	if allowedEdges[model.EdgePackageNamePackageVersion] {
		out = append(out, n.Versions...)
	}
	if allowedEdges[model.EdgePackageHasSourceAt] {
		out = append(out, n.SrcMapLinks...)
	}
	if allowedEdges[model.EdgePackageIsDependency] {
		out = append(out, n.IsDependencyLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyBad] {
		out = append(out, n.BadLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyGood] {
		out = append(out, n.GoodLinks...)
	}
	if allowedEdges[model.EdgePackageHasMetadata] {
		out = append(out, n.HasMetadataLinks...)
	}
	if allowedEdges[model.EdgePackagePointOfContact] {
		out = append(out, n.PointOfContactLinks...)
	}

	return out
}
func (n *pkgVersion) Neighbors(allowedEdges edgeMap) []string {
	var out []string
	if allowedEdges[model.EdgePackageVersionPackageName] {
		out = append(out, n.Parent)
	}
	if allowedEdges[model.EdgePackageHasSourceAt] {
		out = append(out, n.SrcMapLinks...)
	}
	if allowedEdges[model.EdgePackageIsDependency] {
		out = append(out, n.IsDependencyLinks...)
	}
	if allowedEdges[model.EdgePackageIsOccurrence] {
		out = append(out, n.Occurrences...)
	}
	if allowedEdges[model.EdgePackageCertifyVuln] {
		out = append(out, n.CertifyVulnLinks...)
	}
	if allowedEdges[model.EdgePackageHasSbom] {
		out = append(out, n.HasSBOMs...)
	}
	if allowedEdges[model.EdgePackageCertifyVexStatement] {
		out = append(out, n.VexLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyBad] {
		out = append(out, n.BadLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyGood] {
		out = append(out, n.GoodLinks...)
	}
	if allowedEdges[model.EdgePackagePkgEqual] {
		out = append(out, n.PkgEquals...)
	}
	if allowedEdges[model.EdgePackageHasMetadata] {
		out = append(out, n.HasMetadataLinks...)
	}
	if allowedEdges[model.EdgePackagePointOfContact] {
		out = append(out, n.PointOfContactLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyLegal] {
		out = append(out, n.CertifyLegals...)
	}

	return out
}

func (n *pkgType) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildPackageResponse(ctx, n.ThisID, nil)
}
func (n *pkgNamespace) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildPackageResponse(ctx, n.ThisID, nil)
}
func (n *pkgName) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildPackageResponse(ctx, n.ThisID, nil)
}
func (n *pkgVersion) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildPackageResponse(ctx, n.ThisID, nil)
}

// hasSourceAt back edges
func (p *pkgName) setSrcMapLinks(ctx context.Context, id string, c *demoClient) error {
	p.SrcMapLinks = append(p.SrcMapLinks, id)
	return setkv(ctx, pkgNameCol, p, c)
}
func (p *pkgVersion) setSrcMapLinks(ctx context.Context, id string, c *demoClient) error {
	p.SrcMapLinks = append(p.SrcMapLinks, id)
	return setkv(ctx, pkgVerCol, p, c)
}
func (p *pkgName) getSrcMapLinks() []string    { return p.SrcMapLinks }
func (p *pkgVersion) getSrcMapLinks() []string { return p.SrcMapLinks }

// isDependency back edges
func (p *pkgName) setIsDependencyLinks(ctx context.Context, id string, c *demoClient) error {
	p.IsDependencyLinks = append(p.IsDependencyLinks, id)
	return setkv(ctx, pkgNameCol, p, c)
}
func (p *pkgVersion) setIsDependencyLinks(ctx context.Context, id string, c *demoClient) error {
	p.IsDependencyLinks = append(p.IsDependencyLinks, id)
	return setkv(ctx, pkgVerCol, p, c)
}
func (p *pkgName) getIsDependencyLinks() []string    { return p.IsDependencyLinks }
func (p *pkgVersion) getIsDependencyLinks() []string { return p.IsDependencyLinks }

// isOccurrence back edges
func (p *pkgVersion) setOccurrenceLinks(ctx context.Context, id string, c *demoClient) error {
	p.Occurrences = append(p.Occurrences, id)
	return setkv(ctx, pkgVerCol, p, c)
}

// certifyVulnerability back edges
func (p *pkgVersion) setVulnerabilityLinks(ctx context.Context, id string, c *demoClient) error {
	p.CertifyVulnLinks = append(p.CertifyVulnLinks, id)
	return setkv(ctx, pkgVerCol, p, c)
}

// certifyVexStatement back edges
func (p *pkgVersion) setVexLinks(ctx context.Context, id string, c *demoClient) error {
	p.VexLinks = append(p.VexLinks, id)
	return setkv(ctx, pkgVerCol, p, c)
}

// hasSBOM back edges
func (p *pkgVersion) setHasSBOM(ctx context.Context, id string, c *demoClient) error {
	p.HasSBOMs = append(p.HasSBOMs, id)
	return setkv(ctx, pkgVerCol, p, c)
}

// certifyBad back edges
func (p *pkgName) setCertifyBadLinks(ctx context.Context, id string, c *demoClient) error {
	p.BadLinks = append(p.BadLinks, id)
	return setkv(ctx, pkgNameCol, p, c)
}
func (p *pkgVersion) setCertifyBadLinks(ctx context.Context, id string, c *demoClient) error {
	p.BadLinks = append(p.BadLinks, id)
	return setkv(ctx, pkgVerCol, p, c)
}
func (p *pkgName) getCertifyBadLinks() []string    { return p.BadLinks }
func (p *pkgVersion) getCertifyBadLinks() []string { return p.BadLinks }

// certifyGood back edges
func (p *pkgName) setCertifyGoodLinks(ctx context.Context, id string, c *demoClient) error {
	p.GoodLinks = append(p.GoodLinks, id)
	return setkv(ctx, pkgNameCol, p, c)
}
func (p *pkgVersion) setCertifyGoodLinks(ctx context.Context, id string, c *demoClient) error {
	p.GoodLinks = append(p.GoodLinks, id)
	return setkv(ctx, pkgVerCol, p, c)
}
func (p *pkgName) getCertifyGoodLinks() []string    { return p.GoodLinks }
func (p *pkgVersion) getCertifyGoodLinks() []string { return p.GoodLinks }

// hasMetadata back edges
func (p *pkgName) setHasMetadataLinks(ctx context.Context, id string, c *demoClient) error {
	p.HasMetadataLinks = append(p.HasMetadataLinks, id)
	return setkv(ctx, pkgNameCol, p, c)
}
func (p *pkgVersion) setHasMetadataLinks(ctx context.Context, id string, c *demoClient) error {
	p.HasMetadataLinks = append(p.HasMetadataLinks, id)
	return setkv(ctx, pkgVerCol, p, c)
}
func (p *pkgName) getHasMetadataLinks() []string    { return p.HasMetadataLinks }
func (p *pkgVersion) getHasMetadataLinks() []string { return p.HasMetadataLinks }

// pointOfContact back edges
func (p *pkgName) setPointOfContactLinks(ctx context.Context, id string, c *demoClient) error {
	p.PointOfContactLinks = append(p.PointOfContactLinks, id)
	return setkv(ctx, pkgNameCol, p, c)
}
func (p *pkgVersion) setPointOfContactLinks(ctx context.Context, id string, c *demoClient) error {
	p.PointOfContactLinks = append(p.PointOfContactLinks, id)
	return setkv(ctx, pkgVerCol, p, c)
}
func (p *pkgName) getPointOfContactLinks() []string    { return p.PointOfContactLinks }
func (p *pkgVersion) getPointOfContactLinks() []string { return p.PointOfContactLinks }

// pkgEqual back edges
func (p *pkgVersion) setPkgEquals(ctx context.Context, id string, c *demoClient) error {
	p.PkgEquals = append(p.PkgEquals, id)
	return setkv(ctx, pkgVerCol, p, c)
}

func (p *pkgVersion) setCertifyLegals(ctx context.Context, id string, c *demoClient) error {
	p.CertifyLegals = append(p.CertifyLegals, id)
	return setkv(ctx, pkgVerCol, p, c)
}

func (n *pkgType) Key() string {
	return hashKey(n.Type)
}

func (n *pkgType) addNamespace(ctx context.Context, ns string, c *demoClient) error {
	n.Namespaces = append(n.Namespaces, ns)
	return setkv(ctx, pkgTypeCol, n, c)
}

func (n *pkgNamespace) Key() string {
	return hashKey(strings.Join([]string{
		n.Parent,
		n.Namespace,
	}, ":"))
}

func (n *pkgNamespace) addName(ctx context.Context, name string, c *demoClient) error {
	n.Names = append(n.Names, name)
	return setkv(ctx, pkgNSCol, n, c)
}

func (n *pkgName) Key() string {
	return hashKey(strings.Join([]string{
		n.Parent,
		n.Name,
	}, ":"))
}

func (n *pkgName) addVersion(ctx context.Context, ver string, c *demoClient) error {
	n.Versions = append(n.Versions, ver)
	return setkv(ctx, pkgNameCol, n, c)
}

func (n *pkgVersion) Key() string {
	return hashKey(strings.Join([]string{
		n.Parent,
		hashVersionHelper(n.Version, n.Subpath, n.Qualifiers),
	}, ":"))
}

// Ingest Package

func (c *demoClient) IngestPackages(ctx context.Context, pkgs []*model.PkgInputSpec) ([]*model.PackageIDs, error) {
	var modelPkgs []*model.PackageIDs
	for _, pkg := range pkgs {
		modelPkg, err := c.IngestPackage(ctx, *pkg)
		if err != nil {
			return nil, gqlerror.Errorf("ingestPackage failed with err: %v", err)
		}
		modelPkgs = append(modelPkgs, modelPkg)
	}
	return modelPkgs, nil
}

func (c *demoClient) IngestPackage(ctx context.Context, input model.PkgInputSpec) (*model.PackageIDs, error) {
	inType := &pkgType{
		Type: input.Type,
	}
	c.m.RLock()
	outType, err := byKeykv[*pkgType](ctx, pkgTypeCol, inType.Key(), c)
	c.m.RUnlock()
	if err != nil {
		if !errors.Is(err, kv.NotFoundError) {
			return nil, err
		}
		c.m.Lock()
		outType, err = byKeykv[*pkgType](ctx, pkgTypeCol, inType.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) {
				c.m.Unlock()
				return nil, err
			}
			inType.ThisID = c.getNextID()
			if err := c.addToIndex(ctx, pkgTypeCol, inType); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := setkv(ctx, pkgTypeCol, inType, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			outType = inType
		}
		c.m.Unlock()
	}

	inNamespace := &pkgNamespace{
		Parent:    outType.ThisID,
		Namespace: nilToEmpty(input.Namespace),
	}
	c.m.RLock()
	outNamespace, err := byKeykv[*pkgNamespace](ctx, pkgNSCol, inNamespace.Key(), c)
	c.m.RUnlock()
	if err != nil {
		c.m.Lock()
		outNamespace, err = byKeykv[*pkgNamespace](ctx, pkgNSCol, inNamespace.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) {
				c.m.Unlock()
				return nil, err
			}
			inNamespace.ThisID = c.getNextID()
			if err := c.addToIndex(ctx, pkgNSCol, inNamespace); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := setkv(ctx, pkgNSCol, inNamespace, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := outType.addNamespace(ctx, inNamespace.ThisID, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			outNamespace = inNamespace
		}
		c.m.Unlock()
	}

	inName := &pkgName{
		Parent: outNamespace.ThisID,
		Name:   input.Name,
	}
	c.m.RLock()
	outName, err := byKeykv[*pkgName](ctx, pkgNameCol, inName.Key(), c)
	c.m.RUnlock()
	if err != nil {
		c.m.Lock()
		outName, err = byKeykv[*pkgName](ctx, pkgNameCol, inName.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) {
				c.m.Unlock()
				return nil, err
			}
			inName.ThisID = c.getNextID()
			if err := c.addToIndex(ctx, pkgNameCol, inName); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := setkv(ctx, pkgNameCol, inName, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := outNamespace.addName(ctx, inName.ThisID, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			outName = inName
		}
		c.m.Unlock()
	}

	inVersion := &pkgVersion{
		Parent:     outName.ThisID,
		Version:    nilToEmpty(input.Version),
		Subpath:    nilToEmpty(input.Subpath),
		Qualifiers: getQualifiersFromInput(input.Qualifiers),
	}
	c.m.RLock()
	outVersion, err := byKeykv[*pkgVersion](ctx, pkgVerCol, inVersion.Key(), c)
	c.m.RUnlock()
	if err != nil {
		c.m.Lock()
		outVersion, err = byKeykv[*pkgVersion](ctx, pkgVerCol, inVersion.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) {
				c.m.Unlock()
				return nil, err
			}
			inVersion.ThisID = c.getNextID()
			if err := c.addToIndex(ctx, pkgVerCol, inVersion); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := setkv(ctx, pkgVerCol, inVersion, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := outName.addVersion(ctx, inVersion.ThisID, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			outVersion = inVersion
		}
		c.m.Unlock()
	}

	return &model.PackageIDs{
		PackageTypeID:      outType.ThisID,
		PackageNamespaceID: outNamespace.ThisID,
		PackageNameID:      outName.ThisID,
		PackageVersionID:   outVersion.ThisID,
	}, nil
}

func hashVersionHelper(version string, subpath string, qualifiers map[string]string) string {
	// first sort the qualifiers
	qualifierSlice := make([]string, 0, len(qualifiers))
	for key, value := range qualifiers {
		qualifierSlice = append(qualifierSlice, fmt.Sprintf("%s:%s", key, value))
	}
	slices.Sort(qualifierSlice)
	qualifiersStr := strings.Join(qualifierSlice, ",")

	canonicalVersion := fmt.Sprintf("%s,%s,%s", version, subpath, qualifiersStr)
	return canonicalVersion
	// digest := sha256.Sum256([]byte(canonicalVersion))
	// return fmt.Sprintf("%x", digest)
}

// Query Package
func (c *demoClient) Packages(ctx context.Context, filter *model.PkgSpec) ([]*model.Package, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	if filter != nil && filter.ID != nil {
		p, err := c.buildPackageResponse(ctx, *filter.ID, filter)
		if err != nil {
			if errors.Is(err, errNotFound) {
				// not found
				return nil, nil
			}
			return nil, err
		}
		return []*model.Package{p}, nil
	}

	out := []*model.Package{}
	if filter != nil && filter.Type != nil {
		inType := &pkgType{
			Type: *filter.Type,
		}
		pkgTypeNode, err := byKeykv[*pkgType](ctx, pkgTypeCol, inType.Key(), c)
		if err == nil {
			pNamespaces := c.buildPkgNamespace(ctx, pkgTypeNode, filter)
			if len(pNamespaces) > 0 {
				out = append(out, &model.Package{
					ID:         pkgTypeNode.ThisID,
					Type:       pkgTypeNode.Type,
					Namespaces: pNamespaces,
				})
			}
		}
	} else {
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
				pNamespaces := c.buildPkgNamespace(ctx, pkgTypeNode, filter)
				if len(pNamespaces) > 0 {
					out = append(out, &model.Package{
						ID:         pkgTypeNode.ThisID,
						Type:       pkgTypeNode.Type,
						Namespaces: pNamespaces,
					})
				}
			}
		}
	}
	return out, nil
}

func (c *demoClient) buildPkgNamespace(ctx context.Context, pkgTypeNode *pkgType, filter *model.PkgSpec) []*model.PackageNamespace {
	pNamespaces := []*model.PackageNamespace{}
	if filter != nil && filter.Namespace != nil {
		inNS := &pkgNamespace{
			Parent:    pkgTypeNode.ThisID,
			Namespace: *filter.Namespace,
		}
		pkgNS, err := byKeykv[*pkgNamespace](ctx, pkgNSCol, inNS.Key(), c)
		if err == nil {
			pns := c.buildPkgName(ctx, pkgNS, filter)
			if len(pns) > 0 {
				pNamespaces = append(pNamespaces, &model.PackageNamespace{
					ID:        pkgNS.ThisID,
					Namespace: pkgNS.Namespace,
					Names:     pns,
				})
			}
		}
	} else {
		for _, nsID := range pkgTypeNode.Namespaces {
			pkgNS, err := byIDkv[*pkgNamespace](ctx, nsID, c)
			if err != nil {
				continue
			}
			pns := c.buildPkgName(ctx, pkgNS, filter)
			if len(pns) > 0 {
				pNamespaces = append(pNamespaces, &model.PackageNamespace{
					ID:        pkgNS.ThisID,
					Namespace: pkgNS.Namespace,
					Names:     pns,
				})
			}
		}
	}
	return pNamespaces
}

func (c *demoClient) buildPkgName(ctx context.Context, pkgNS *pkgNamespace, filter *model.PkgSpec) []*model.PackageName {
	pns := []*model.PackageName{}
	if filter != nil && filter.Name != nil {
		inName := &pkgName{
			Parent: pkgNS.ThisID,
			Name:   *filter.Name,
		}
		pkgNameNode, err := byKeykv[*pkgName](ctx, pkgNameCol, inName.Key(), c)
		if err == nil {
			pvs := c.buildPkgVersion(ctx, pkgNameNode, filter)
			if len(pvs) > 0 {
				pns = append(pns, &model.PackageName{
					ID:       pkgNameNode.ThisID,
					Name:     pkgNameNode.Name,
					Versions: pvs,
				})
			}
		}
	} else {
		for _, nameID := range pkgNS.Names {
			pkgNameNode, err := byIDkv[*pkgName](ctx, nameID, c)
			if err != nil {
				continue
			}
			pvs := c.buildPkgVersion(ctx, pkgNameNode, filter)
			if len(pvs) > 0 {
				pns = append(pns, &model.PackageName{
					ID:       pkgNameNode.ThisID,
					Name:     pkgNameNode.Name,
					Versions: pvs,
				})
			}
		}
	}
	return pns
}

func (c *demoClient) buildPkgVersion(ctx context.Context, pkgNameNode *pkgName, filter *model.PkgSpec) []*model.PackageVersion {
	pvs := []*model.PackageVersion{}
	if filter != nil &&
		filter.Version != nil &&
		filter.Subpath != nil &&
		((len(filter.Qualifiers) > 0) ||
			(filter.MatchOnlyEmptyQualifiers != nil && *filter.MatchOnlyEmptyQualifiers)) {
		inVer := &pkgVersion{
			Parent:  pkgNameNode.ThisID,
			Version: *filter.Version,
			Subpath: *filter.Subpath,
		}
		if filter.MatchOnlyEmptyQualifiers == nil || !*filter.MatchOnlyEmptyQualifiers {
			inVer.Qualifiers = getQualifiersFromFilter(filter.Qualifiers)
		}
		pkgVer, err := byKeykv[*pkgVersion](ctx, pkgVerCol, inVer.Key(), c)
		if err == nil {
			pvs = append(pvs, &model.PackageVersion{
				ID:         pkgVer.ThisID,
				Version:    pkgVer.Version,
				Subpath:    pkgVer.Subpath,
				Qualifiers: getCollectedPackageQualifiers(pkgVer.Qualifiers),
			})
		}
		return pvs
	}

	for _, verID := range pkgNameNode.Versions {
		pkgVer, err := byIDkv[*pkgVersion](ctx, verID, c)
		if err != nil {
			continue
		}
		if filter != nil && noMatch(filter.Version, pkgVer.Version) {
			continue
		}
		if filter != nil && noMatch(filter.Subpath, pkgVer.Subpath) {
			continue
		}
		if filter != nil && noMatchQualifiers(filter, pkgVer.Qualifiers) {
			continue
		}
		pvs = append(pvs, &model.PackageVersion{
			ID:         pkgVer.ThisID,
			Version:    pkgVer.Version,
			Subpath:    pkgVer.Subpath,
			Qualifiers: getCollectedPackageQualifiers(pkgVer.Qualifiers),
		})
	}
	return pvs
}

// Builds a model.Package to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildPackageResponse(ctx context.Context, id string, filter *model.PkgSpec) (*model.Package, error) {
	if filter != nil && filter.ID != nil && *filter.ID != id {
		return nil, nil
	}

	currentID := id

	pvl := []*model.PackageVersion{}
	if versionNode, err := byIDkv[*pkgVersion](ctx, currentID, c); err == nil {
		if filter != nil && noMatch(filter.Version, versionNode.Version) {
			return nil, nil
		}
		if filter != nil && noMatch(filter.Subpath, versionNode.Subpath) {
			return nil, nil
		}
		if filter != nil && noMatchQualifiers(filter, versionNode.Qualifiers) {
			return nil, nil
		}
		pvl = append(pvl, &model.PackageVersion{
			ID:         versionNode.ThisID,
			Version:    versionNode.Version,
			Subpath:    versionNode.Subpath,
			Qualifiers: getCollectedPackageQualifiers(versionNode.Qualifiers),
		})
		currentID = versionNode.Parent
	} else if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
		return nil, fmt.Errorf("Error retrieving node for id: %v : %w", currentID, err)
	}

	pnl := []*model.PackageName{}
	if nameNode, err := byIDkv[*pkgName](ctx, currentID, c); err == nil {
		if filter != nil && noMatch(filter.Name, nameNode.Name) {
			return nil, nil
		}
		pnl = append(pnl, &model.PackageName{
			ID:       nameNode.ThisID,
			Name:     nameNode.Name,
			Versions: pvl,
		})
		currentID = nameNode.Parent
	} else if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
		return nil, fmt.Errorf("Error retrieving node for id: %v : %w", currentID, err)
	}

	pnsl := []*model.PackageNamespace{}
	if namespaceNode, err := byIDkv[*pkgNamespace](ctx, currentID, c); err == nil {
		if filter != nil && noMatch(filter.Namespace, namespaceNode.Namespace) {
			return nil, nil
		}
		pnsl = append(pnsl, &model.PackageNamespace{
			ID:        namespaceNode.ThisID,
			Namespace: namespaceNode.Namespace,
			Names:     pnl,
		})
		currentID = namespaceNode.Parent
	} else if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
		return nil, fmt.Errorf("Error retrieving node for id: %v : %w", currentID, err)
	}

	typeNode, err := byIDkv[*pkgType](ctx, currentID, c)
	if err != nil {
		if errors.Is(err, kv.NotFoundError) || errors.Is(err, errTypeNotMatch) {
			return nil, fmt.Errorf("%w: ID does not match expected node type for package namespace", errNotFound)
		} else {
			return nil, fmt.Errorf("Error retrieving node for id: %v : %w", currentID, err)
		}
	}
	if filter != nil && noMatch(filter.Type, typeNode.Type) {
		return nil, nil
	}
	p := model.Package{
		ID:         typeNode.ThisID,
		Type:       typeNode.Type,
		Namespaces: pnsl,
	}
	return &p, nil
}

func (c *demoClient) getPackageNameFromInput(ctx context.Context, input model.PkgInputSpec) (*pkgName, error) {
	inType := &pkgType{
		Type: input.Type,
	}
	pkgT, err := byKeykv[*pkgType](ctx, pkgTypeCol, inType.Key(), c)
	if err != nil {
		return nil, gqlerror.Errorf("Package type \"%s\" not found", input.Type)
	}

	inNS := &pkgNamespace{
		Parent:    pkgT.ThisID,
		Namespace: nilToEmpty(input.Namespace),
	}
	pkgNS, err := byKeykv[*pkgNamespace](ctx, pkgNSCol, inNS.Key(), c)
	if err != nil {
		return nil, gqlerror.Errorf("Package namespace \"%s\" not found", nilToEmpty(input.Namespace))
	}

	inName := &pkgName{
		Parent: pkgNS.ThisID,
		Name:   input.Name,
	}
	pkgN, err := byKeykv[*pkgName](ctx, pkgNameCol, inName.Key(), c)
	if err != nil {
		return nil, gqlerror.Errorf("Package name \"%s\" not found", input.Name)
	}

	return pkgN, nil
}

func (c *demoClient) getPackageVerFromInput(ctx context.Context, input model.PkgInputSpec) (*pkgVersion, error) {
	pkgN, err := c.getPackageNameFromInput(ctx, input)
	if err != nil {
		return nil, gqlerror.Errorf("Package name \"%s\" not found", input.Name)
	}

	inVer := &pkgVersion{
		Parent:     pkgN.ThisID,
		Version:    nilToEmpty(input.Version),
		Subpath:    nilToEmpty(input.Subpath),
		Qualifiers: getQualifiersFromInput(input.Qualifiers),
	}
	pkgVer, err := byKeykv[*pkgVersion](ctx, pkgVerCol, inVer.Key(), c)
	if err != nil {
		return nil, gqlerror.Errorf("No package matches input")
	}
	return pkgVer, nil
}

func (c *demoClient) getPackageNameOrVerFromInput(ctx context.Context, input model.PkgInputSpec, pkgMatchType model.MatchFlags) (pkgNameOrVersion, error) {
	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		return c.getPackageNameFromInput(ctx, input)
	}
	return c.getPackageVerFromInput(ctx, input)
}

func getCollectedPackageQualifiers(qualifierMap map[string]string) []*model.PackageQualifier {
	qualifiers := []*model.PackageQualifier{}
	for key, val := range qualifierMap {
		qualifier := &model.PackageQualifier{
			Key:   key,
			Value: val,
		}
		qualifiers = append(qualifiers, qualifier)

	}
	return qualifiers
}

func getQualifiersFromInput(qualifiersSpec []*model.PackageQualifierInputSpec) map[string]string {
	qualifiersMap := map[string]string{}
	// if qualifiersSpec == nil {
	// 	return qualifiersMap
	// }
	for _, kv := range qualifiersSpec {
		if kv != nil {
			qualifiersMap[kv.Key] = kv.Value
		}
	}
	return qualifiersMap
}

func getQualifiersFromFilter(qualifiersSpec []*model.PackageQualifierSpec) map[string]string {
	qualifiersMap := map[string]string{}
	if qualifiersSpec == nil {
		return qualifiersMap
	}
	for _, kv := range qualifiersSpec {
		qualifiersMap[kv.Key] = nilToEmpty(kv.Value)
	}
	return qualifiersMap
}

func noMatchQualifiers(filter *model.PkgSpec, v map[string]string) bool {
	// Allow matching on nodes with no qualifiers
	if filter.MatchOnlyEmptyQualifiers != nil {
		if *filter.MatchOnlyEmptyQualifiers && len(v) != 0 {
			return true
		}
	}
	if filter.Qualifiers != nil && len(filter.Qualifiers) > 0 {
		filterQualifiers := getQualifiersFromFilter(filter.Qualifiers)
		return !reflect.DeepEqual(v, filterQualifiers)
	}
	return false
}

func (c *demoClient) findPackageVersion(ctx context.Context, filter *model.PkgSpec) ([]*pkgVersion, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.ID != nil {
		if pkgVer, err := byIDkv[*pkgVersion](ctx, *filter.ID, c); err == nil {
			return []*pkgVersion{pkgVer}, nil
		} else { // fixme check if err is not keyerror and bubble up if needed
			return nil, nil
		}
	}
	if filter.Type == nil || filter.Namespace != nil || filter.Name == nil || filter.Version == nil { // search all ver?
		return nil, nil
	}

	pkgN, err := c.exactPackageName(ctx, filter)
	if err != nil {
		return nil, nil
	}

	var out []*pkgVersion
	for _, vID := range pkgN.Versions {
		pkgVer, err := byIDkv[*pkgVersion](ctx, vID, c)
		if err != nil {
			return nil, err
		}
		if *filter.Version != pkgVer.Version ||
			noMatch(filter.Subpath, pkgVer.Subpath) ||
			noMatchQualifiers(filter, pkgVer.Qualifiers) {
			continue
		}
		out = append(out, pkgVer)
	}
	return out, nil
}

func (c *demoClient) exactPackageName(ctx context.Context, filter *model.PkgSpec) (*pkgName, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.ID != nil {
		if pkgN, err := byIDkv[*pkgName](ctx, *filter.ID, c); err == nil {
			return pkgN, nil
		} else {
			if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
				return nil, err
			}
			return nil, nil
		}
	}
	if filter.Type == nil || filter.Namespace == nil || filter.Name == nil {
		return nil, nil
	}
	inType := &pkgType{
		Type: *filter.Type,
	}
	pkgT, err := byKeykv[*pkgType](ctx, pkgTypeCol, inType.Key(), c)
	if err != nil {
		if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
			return nil, err
		}
		return nil, nil
	}

	inNS := &pkgNamespace{
		Parent:    pkgT.ThisID,
		Namespace: *filter.Namespace,
	}
	pkgNS, err := byKeykv[*pkgNamespace](ctx, pkgNSCol, inNS.Key(), c)
	if err != nil {
		if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
			return nil, err
		}
		return nil, nil
	}

	inName := &pkgName{
		Parent: pkgNS.ThisID,
		Name:   *filter.Name,
	}
	pkgN, err := byKeykv[*pkgName](ctx, pkgNameCol, inName.Key(), c)
	if err != nil {
		if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
			return nil, err
		}
		return nil, nil
	}
	return pkgN, nil
}

func (c *demoClient) matchPackages(ctx context.Context, filter []*model.PkgSpec, pkgs []string) bool {
	pkgs = slices.Clone(pkgs)
	pkgs = helper.SortAndRemoveDups(pkgs)

	for _, pvSpec := range filter {
		if pvSpec != nil {
			if pvSpec.ID != nil {
				// Check by ID if present
				if !helper.IsIDPresent(*pvSpec.ID, pkgs) {
					return false
				}
			} else {
				// Otherwise match spec information
				match := false
				for _, pkgId := range pkgs {
					id := pkgId
					pkgVersion, err := byIDkv[*pkgVersion](ctx, id, c)
					if err == nil {
						if noMatch(pvSpec.Subpath, pkgVersion.Subpath) || noMatchQualifiers(pvSpec, pkgVersion.Qualifiers) || noMatch(pvSpec.Version, pkgVersion.Version) {
							continue
						}
						id = pkgVersion.Parent
					}
					pkgName, err := byIDkv[*pkgName](ctx, id, c)
					if err == nil {
						if noMatch(pvSpec.Name, pkgName.Name) {
							continue
						}
						id = pkgName.Parent
					}
					pkgNamespace, err := byIDkv[*pkgNamespace](ctx, id, c)
					if err == nil {
						if noMatch(pvSpec.Namespace, pkgNamespace.Namespace) {
							continue
						}
						id = pkgNamespace.Parent
					}
					pkgType, err := byIDkv[*pkgType](ctx, id, c)
					if err == nil {
						if noMatch(pvSpec.Type, pkgType.Type) {
							continue
						} else {
							match = true
							break
						}
					}
				}
				if !match {
					return false
				}
			}
		}
	}
	return true
}
