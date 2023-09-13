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
	"fmt"
	"reflect"
	"strconv"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO: move this into a unit test for this file
// func registerAllPackages(client *demoClient) {
// 	ctx := context.Background()

// 	v11 := "2.11.1"
// 	v12 := "2.12.0"
// 	subpath1 := "saved_model_cli.py"
// 	subpath2 := "__init__.py"
// 	opensslNamespace := "openssl.org"
// 	opensslVersion := "3.0.3"

// 	inputs := []model.PkgInputSpec{{
// 		Type: "pypi",
// 		Name: "tensorflow",
// 	}, {
// 		Type:    "pypi",
// 		Name:    "tensorflow",
// 		Version: &v11,
// 	}, {
// 		Type:    "pypi",
// 		Name:    "tensorflow",
// 		Version: &v12,
// 	}, {
// 		Type:    "pypi",
// 		Name:    "tensorflow",
// 		Version: &v12,
// 		Subpath: &subpath1,
// 	}, {
// 		Type:    "pypi",
// 		Name:    "tensorflow",
// 		Version: &v12,
// 		Subpath: &subpath2,
// 	}, {
// 		Type:    "pypi",
// 		Name:    "tensorflow",
// 		Version: &v12,
// 		Subpath: &subpath1,
// 	}, {
// 		Type:      "conan",
// 		Namespace: &opensslNamespace,
// 		Name:      "openssl",
// 		Version:   &opensslVersion,
// 	}}

// 	for _, input := range inputs {
// 		_, err := client.IngestPackage(ctx, input)
// 		if err != nil {
// 			log.Printf("Error in ingesting: %v\n", err)
// 		}
// 	}
// }

// Internal data: Packages
type pkgTypeMap map[string]*pkgNamespaceStruct
type pkgNamespaceStruct struct {
	id         uint32
	typeKey    string
	namespaces pkgNamespaceMap
}
type pkgNamespaceMap map[string]*pkgNameStruct
type pkgNameStruct struct {
	id        uint32
	parent    uint32
	namespace string
	names     pkgNameMap
}
type pkgNameMap map[string]*pkgVersionStruct
type pkgVersionStruct struct {
	id                  uint32
	parent              uint32
	name                string
	versions            pkgVersionList
	srcMapLinks         []uint32
	isDependencyLinks   []uint32
	badLinks            []uint32
	goodLinks           []uint32
	hasMetadataLinks    []uint32
	pointOfContactLinks []uint32
}
type pkgVersionList []*pkgVersionNode
type pkgVersionNode struct {
	id                  uint32
	parent              uint32
	version             string
	subpath             string
	qualifiers          map[string]string
	srcMapLinks         []uint32
	isDependencyLinks   []uint32
	occurrences         []uint32
	certifyVulnLinks    []uint32
	hasSBOMs            []uint32
	vexLinks            []uint32
	badLinks            []uint32
	goodLinks           []uint32
	hasMetadataLinks    []uint32
	pointOfContactLinks []uint32
	pkgEquals           []uint32
	certifyLegals       []uint32
}

// Be type safe, don't use any / interface{}
type pkgNameOrVersion interface {
	implementsPkgNameOrVersion()
	setSrcMapLinks(id uint32)
	getSrcMapLinks() []uint32
	setIsDependencyLinks(id uint32)
	getIsDependencyLinks() []uint32
	setCertifyBadLinks(id uint32)
	getCertifyBadLinks() []uint32
	setCertifyGoodLinks(id uint32)
	getCertifyGoodLinks() []uint32
	setHasMetadataLinks(id uint32)
	getHasMetadataLinks() []uint32
	setPointOfContactLinks(id uint32)
	getPointOfContactLinks() []uint32

	node
}

func (n *pkgNamespaceStruct) ID() uint32 { return n.id }
func (n *pkgNameStruct) ID() uint32      { return n.id }
func (n *pkgVersionStruct) ID() uint32   { return n.id }
func (n *pkgVersionNode) ID() uint32     { return n.id }

func (n *pkgNamespaceStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 1+len(n.namespaces))
	for _, v := range n.namespaces {
		out = append(out, v.id)
	}
	return out
}
func (n *pkgNameStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 1+len(n.names))
	for _, v := range n.names {
		out = append(out, v.id)
	}
	out = append(out, n.parent)
	return out
}
func (n *pkgVersionStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	out := []uint32{n.parent}
	for _, v := range n.versions {
		out = append(out, v.id)
	}

	if allowedEdges[model.EdgePackageHasSourceAt] {
		out = append(out, n.srcMapLinks...)
	}
	if allowedEdges[model.EdgePackageIsDependency] {
		out = append(out, n.isDependencyLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyBad] {
		out = append(out, n.badLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyGood] {
		out = append(out, n.goodLinks...)
	}
	if allowedEdges[model.EdgePackageHasMetadata] {
		out = append(out, n.hasMetadataLinks...)
	}
	if allowedEdges[model.EdgePackagePointOfContact] {
		out = append(out, n.pointOfContactLinks...)
	}

	return out
}
func (n *pkgVersionNode) Neighbors(allowedEdges edgeMap) []uint32 {
	out := []uint32{n.parent}

	if allowedEdges[model.EdgePackageHasSourceAt] {
		out = append(out, n.srcMapLinks...)
	}
	if allowedEdges[model.EdgePackageIsDependency] {
		out = append(out, n.isDependencyLinks...)
	}
	if allowedEdges[model.EdgePackageIsOccurrence] {
		out = append(out, n.occurrences...)
	}
	if allowedEdges[model.EdgePackageCertifyVuln] {
		out = append(out, n.certifyVulnLinks...)
	}
	if allowedEdges[model.EdgePackageHasSbom] {
		out = append(out, n.hasSBOMs...)
	}
	if allowedEdges[model.EdgePackageCertifyVexStatement] {
		out = append(out, n.vexLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyBad] {
		out = append(out, n.badLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyGood] {
		out = append(out, n.goodLinks...)
	}
	if allowedEdges[model.EdgePackagePkgEqual] {
		out = append(out, n.pkgEquals...)
	}
	if allowedEdges[model.EdgePackageHasMetadata] {
		out = append(out, n.hasMetadataLinks...)
	}
	if allowedEdges[model.EdgePackagePointOfContact] {
		out = append(out, n.pointOfContactLinks...)
	}
	if allowedEdges[model.EdgePackageCertifyLegal] {
		out = append(out, n.certifyLegals...)
	}

	return out
}

func (n *pkgNamespaceStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildPackageResponse(n.id, nil)
}
func (n *pkgNameStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildPackageResponse(n.id, nil)
}
func (n *pkgVersionStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildPackageResponse(n.id, nil)
}
func (n *pkgVersionNode) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildPackageResponse(n.id, nil)
}

func (p *pkgVersionStruct) implementsPkgNameOrVersion() {}
func (p *pkgVersionNode) implementsPkgNameOrVersion()   {}

// hasSourceAt back edges
func (p *pkgVersionStruct) setSrcMapLinks(id uint32) { p.srcMapLinks = append(p.srcMapLinks, id) }
func (p *pkgVersionNode) setSrcMapLinks(id uint32)   { p.srcMapLinks = append(p.srcMapLinks, id) }
func (p *pkgVersionStruct) getSrcMapLinks() []uint32 { return p.srcMapLinks }
func (p *pkgVersionNode) getSrcMapLinks() []uint32   { return p.srcMapLinks }

// isDependency back edges
func (p *pkgVersionStruct) setIsDependencyLinks(id uint32) {
	p.isDependencyLinks = append(p.isDependencyLinks, id)
}
func (p *pkgVersionNode) setIsDependencyLinks(id uint32) {
	p.isDependencyLinks = append(p.isDependencyLinks, id)
}
func (p *pkgVersionStruct) getIsDependencyLinks() []uint32 { return p.isDependencyLinks }
func (p *pkgVersionNode) getIsDependencyLinks() []uint32   { return p.isDependencyLinks }

// isOccurrence back edges
func (p *pkgVersionNode) setOccurrenceLinks(id uint32) { p.occurrences = append(p.occurrences, id) }

// certifyVulnerability back edges
func (p *pkgVersionNode) setVulnerabilityLinks(id uint32) {
	p.certifyVulnLinks = append(p.certifyVulnLinks, id)
}

// certifyVexStatement back edges
func (p *pkgVersionNode) setVexLinks(id uint32) {
	p.vexLinks = append(p.vexLinks, id)
}

// hasSBOM back edges
func (p *pkgVersionNode) setHasSBOM(id uint32) { p.hasSBOMs = append(p.hasSBOMs, id) }

// certifyBad back edges
func (p *pkgVersionStruct) setCertifyBadLinks(id uint32) { p.badLinks = append(p.badLinks, id) }
func (p *pkgVersionNode) setCertifyBadLinks(id uint32)   { p.badLinks = append(p.badLinks, id) }
func (p *pkgVersionStruct) getCertifyBadLinks() []uint32 { return p.badLinks }
func (p *pkgVersionNode) getCertifyBadLinks() []uint32   { return p.badLinks }

// certifyGood back edges
func (p *pkgVersionStruct) setCertifyGoodLinks(id uint32) { p.goodLinks = append(p.goodLinks, id) }
func (p *pkgVersionNode) setCertifyGoodLinks(id uint32)   { p.goodLinks = append(p.goodLinks, id) }
func (p *pkgVersionStruct) getCertifyGoodLinks() []uint32 { return p.goodLinks }
func (p *pkgVersionNode) getCertifyGoodLinks() []uint32   { return p.goodLinks }

// hasMetadata back edges
func (p *pkgVersionStruct) setHasMetadataLinks(id uint32) {
	p.hasMetadataLinks = append(p.hasMetadataLinks, id)
}
func (p *pkgVersionNode) setHasMetadataLinks(id uint32) {
	p.hasMetadataLinks = append(p.hasMetadataLinks, id)
}
func (p *pkgVersionStruct) getHasMetadataLinks() []uint32 { return p.hasMetadataLinks }
func (p *pkgVersionNode) getHasMetadataLinks() []uint32   { return p.hasMetadataLinks }

// pointOfContact back edges
func (p *pkgVersionStruct) setPointOfContactLinks(id uint32) {
	p.pointOfContactLinks = append(p.pointOfContactLinks, id)
}
func (p *pkgVersionNode) setPointOfContactLinks(id uint32) {
	p.pointOfContactLinks = append(p.pointOfContactLinks, id)
}
func (p *pkgVersionStruct) getPointOfContactLinks() []uint32 { return p.pointOfContactLinks }
func (p *pkgVersionNode) getPointOfContactLinks() []uint32   { return p.pointOfContactLinks }

// pkgEqual back edges
func (p *pkgVersionNode) setPkgEquals(id uint32) { p.pkgEquals = append(p.pkgEquals, id) }

func (p *pkgVersionNode) setCertifyLegals(id uint32) { p.certifyLegals = append(p.certifyLegals, id) }

// Ingest Package

func (c *demoClient) IngestPackages(ctx context.Context, pkgs []*model.PkgInputSpec) ([]*model.Package, error) {
	var modelPkgs []*model.Package
	for _, pkg := range pkgs {
		modelPkg, err := c.IngestPackage(ctx, *pkg)
		if err != nil {
			return nil, gqlerror.Errorf("ingestPackage failed with err: %v", err)
		}
		modelPkgs = append(modelPkgs, modelPkg)
	}
	return modelPkgs, nil
}

func (c *demoClient) IngestPackage(ctx context.Context, input model.PkgInputSpec) (*model.Package, error) {
	c.m.RLock()
	namespacesStruct, hasNamespace := c.packages[input.Type]
	c.m.RUnlock()
	if !hasNamespace {
		c.m.Lock()
		namespacesStruct, hasNamespace = c.packages[input.Type]
		if !hasNamespace {
			namespacesStruct = &pkgNamespaceStruct{
				id:         c.getNextID(),
				typeKey:    input.Type,
				namespaces: pkgNamespaceMap{},
			}
			c.index[namespacesStruct.id] = namespacesStruct
			c.packages[input.Type] = namespacesStruct
		}
		c.m.Unlock()
	}
	namespaces := namespacesStruct.namespaces

	c.m.RLock()
	namesStruct, hasName := namespaces[nilToEmpty(input.Namespace)]
	c.m.RUnlock()
	if !hasName {
		c.m.Lock()
		namesStruct, hasName = namespaces[nilToEmpty(input.Namespace)]
		if !hasName {
			namesStruct = &pkgNameStruct{
				id:        c.getNextID(),
				parent:    namespacesStruct.id,
				namespace: nilToEmpty(input.Namespace),
				names:     pkgNameMap{},
			}
			c.index[namesStruct.id] = namesStruct
			namespaces[nilToEmpty(input.Namespace)] = namesStruct
		}
		c.m.Unlock()
	}
	names := namesStruct.names

	c.m.RLock()
	versionStruct, hasVersions := names[input.Name]
	c.m.RUnlock()
	if !hasVersions {
		c.m.Lock()
		versionStruct, hasVersions = names[input.Name]
		if !hasVersions {
			versionStruct = &pkgVersionStruct{
				id:       c.getNextID(),
				parent:   namesStruct.id,
				name:     input.Name,
				versions: pkgVersionList{},
			}
			c.index[versionStruct.id] = versionStruct
			names[input.Name] = versionStruct
		}
		c.m.Unlock()
	}

	c.m.RLock()
	duplicate, collectedVersion := duplicatePkgVer(versionStruct.versions, input)
	c.m.RUnlock()
	if !duplicate {
		c.m.Lock()
		duplicate, collectedVersion = duplicatePkgVer(versionStruct.versions, input)
		if !duplicate {
			collectedVersion = &pkgVersionNode{
				id:         c.getNextID(),
				parent:     versionStruct.id,
				version:    nilToEmpty(input.Version),
				subpath:    nilToEmpty(input.Subpath),
				qualifiers: getQualifiersFromInput(input.Qualifiers),
			}
			c.index[collectedVersion.id] = collectedVersion
			// Need to append to version and replace field in versionStruct
			versionStruct.versions = append(versionStruct.versions, collectedVersion)
		}
		c.m.Unlock()
	}

	// build return GraphQL type
	c.m.RLock()
	defer c.m.RUnlock()
	return c.buildPackageResponse(collectedVersion.id, nil)
}

func duplicatePkgVer(versions pkgVersionList, input model.PkgInputSpec) (bool, *pkgVersionNode) {
	for _, v := range versions {
		if noMatchInput(input.Version, v.version) {
			continue
		}
		if noMatchInput(input.Subpath, v.subpath) {
			continue
		}
		if !reflect.DeepEqual(v.qualifiers, getQualifiersFromInput(input.Qualifiers)) {
			continue
		}
		return true, v
	}
	return false, nil
}

// Query Package
func (c *demoClient) Packages(ctx context.Context, filter *model.PkgSpec) ([]*model.Package, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	if filter != nil && filter.ID != nil {
		id, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		p, err := c.buildPackageResponse(uint32(id), filter)
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
		pkgNamespaceStruct, ok := c.packages[*filter.Type]
		if ok {
			pNamespaces := buildPkgNamespace(pkgNamespaceStruct, filter)
			if len(pNamespaces) > 0 {
				out = append(out, &model.Package{
					ID:         nodeID(pkgNamespaceStruct.id),
					Type:       pkgNamespaceStruct.typeKey,
					Namespaces: pNamespaces,
				})
			}
		}
	} else {
		for dbType, pkgNamespaceStruct := range c.packages {
			pNamespaces := buildPkgNamespace(pkgNamespaceStruct, filter)
			if len(pNamespaces) > 0 {
				out = append(out, &model.Package{
					ID:         nodeID(pkgNamespaceStruct.id),
					Type:       dbType,
					Namespaces: pNamespaces,
				})
			}
		}
	}
	return out, nil
}

func buildPkgNamespace(pkgNamespaceStruct *pkgNamespaceStruct, filter *model.PkgSpec) []*model.PackageNamespace {
	pNamespaces := []*model.PackageNamespace{}
	if filter != nil && filter.Namespace != nil {
		pkgNameStruct, ok := pkgNamespaceStruct.namespaces[*filter.Namespace]
		if ok {
			pns := buildPkgName(pkgNameStruct, filter)
			if len(pns) > 0 {
				pNamespaces = append(pNamespaces, &model.PackageNamespace{
					ID:        nodeID(pkgNameStruct.id),
					Namespace: pkgNameStruct.namespace,
					Names:     pns,
				})
			}
		}
	} else {
		for namespace, pkgNameStruct := range pkgNamespaceStruct.namespaces {
			pns := buildPkgName(pkgNameStruct, filter)
			if len(pns) > 0 {
				pNamespaces = append(pNamespaces, &model.PackageNamespace{
					ID:        nodeID(pkgNameStruct.id),
					Namespace: namespace,
					Names:     pns,
				})
			}
		}
	}
	return pNamespaces
}

func buildPkgName(pkgNameStruct *pkgNameStruct, filter *model.PkgSpec) []*model.PackageName {
	pns := []*model.PackageName{}
	if filter != nil && filter.Name != nil {
		pkgVersionStruct, ok := pkgNameStruct.names[*filter.Name]
		if ok {
			pvs := buildPkgVersion(pkgVersionStruct, filter)
			if len(pvs) > 0 {
				pns = append(pns, &model.PackageName{
					ID:       nodeID(pkgVersionStruct.id),
					Name:     pkgVersionStruct.name,
					Versions: pvs,
				})
			}
		}
	} else {
		for name, pkgVersionStruct := range pkgNameStruct.names {
			pvs := buildPkgVersion(pkgVersionStruct, filter)
			if len(pvs) > 0 {
				pns = append(pns, &model.PackageName{
					ID:       nodeID(pkgVersionStruct.id),
					Name:     name,
					Versions: pvs,
				})
			}
		}
	}
	return pns
}

func buildPkgVersion(pkgVersionStruct *pkgVersionStruct, filter *model.PkgSpec) []*model.PackageVersion {
	pvs := []*model.PackageVersion{}
	for _, v := range pkgVersionStruct.versions {
		if filter != nil && noMatch(filter.Version, v.version) {
			continue
		}
		if filter != nil && noMatch(filter.Subpath, v.subpath) {
			continue
		}
		if filter != nil && noMatchQualifiers(filter, v.qualifiers) {
			continue
		}
		pvs = append(pvs, &model.PackageVersion{
			ID:         nodeID(v.id),
			Version:    v.version,
			Subpath:    v.subpath,
			Qualifiers: getCollectedPackageQualifiers(v.qualifiers),
		})
	}
	return pvs
}

// Builds a model.Package to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildPackageResponse(id uint32, filter *model.PkgSpec) (*model.Package, error) {
	if filter != nil && filter.ID != nil {
		filteredID, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		if uint32(filteredID) != id {
			return nil, nil
		}
	}

	node, ok := c.index[id]
	if !ok {
		return nil, fmt.Errorf("%w : ID does not match existing node", errNotFound)
	}

	pvl := []*model.PackageVersion{}
	if versionNode, ok := node.(*pkgVersionNode); ok {
		if filter != nil && noMatch(filter.Version, versionNode.version) {
			return nil, nil
		}
		if filter != nil && noMatch(filter.Subpath, versionNode.subpath) {
			return nil, nil
		}
		if filter != nil && noMatchQualifiers(filter, versionNode.qualifiers) {
			return nil, nil
		}
		pvl = append(pvl, &model.PackageVersion{
			ID:         nodeID(versionNode.id),
			Version:    versionNode.version,
			Subpath:    versionNode.subpath,
			Qualifiers: getCollectedPackageQualifiers(versionNode.qualifiers),
		})
		node, ok = c.index[versionNode.parent]
		if !ok {
			return nil, fmt.Errorf("Internal ID does not match existing node")
		}
	}

	pnl := []*model.PackageName{}
	if versionStruct, ok := node.(*pkgVersionStruct); ok {
		if filter != nil && noMatch(filter.Name, versionStruct.name) {
			return nil, nil
		}
		pnl = append(pnl, &model.PackageName{
			ID:       nodeID(versionStruct.id),
			Name:     versionStruct.name,
			Versions: pvl,
		})
		node, ok = c.index[versionStruct.parent]
		if !ok {
			return nil, fmt.Errorf("Internal ID does not match existing node")
		}
	}

	pnsl := []*model.PackageNamespace{}
	if nameStruct, ok := node.(*pkgNameStruct); ok {
		if filter != nil && noMatch(filter.Namespace, nameStruct.namespace) {
			return nil, nil
		}
		pnsl = append(pnsl, &model.PackageNamespace{
			ID:        nodeID(nameStruct.id),
			Namespace: nameStruct.namespace,
			Names:     pnl,
		})
		node, ok = c.index[nameStruct.parent]
		if !ok {
			return nil, fmt.Errorf("Internal ID does not match existing node")
		}
	}

	namespaceStruct, ok := node.(*pkgNamespaceStruct)
	if !ok {
		return nil, fmt.Errorf("%w: ID does not match expected node type for package namespace", errNotFound)
	}
	p := model.Package{
		ID:         nodeID(namespaceStruct.id),
		Type:       namespaceStruct.typeKey,
		Namespaces: pnsl,
	}
	if filter != nil && noMatch(filter.Type, p.Type) {
		return nil, nil
	}
	return &p, nil
}

func getPackageIDFromInput(c *demoClient, input model.PkgInputSpec, pkgMatchType model.MatchFlags) (uint32, error) {
	pkgNamespace, pkgHasNamespace := c.packages[input.Type]
	if !pkgHasNamespace {
		return 0, gqlerror.Errorf("Package type \"%s\" not found", input.Type)
	}
	pkgName, pkgHasName := pkgNamespace.namespaces[nilToEmpty(input.Namespace)]
	if !pkgHasName {
		return 0, gqlerror.Errorf("Package namespace \"%s\" not found", nilToEmpty(input.Namespace))
	}
	pkgVersion, pkgHasVersion := pkgName.names[input.Name]
	if !pkgHasVersion {
		return 0, gqlerror.Errorf("Package name \"%s\" not found", input.Name)
	}
	var packageID uint32
	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		packageID = pkgVersion.id
	} else {
		found := false
		for _, version := range pkgVersion.versions {
			if noMatchInput(input.Version, version.version) {
				continue
			}
			if noMatchInput(input.Subpath, version.subpath) {
				continue
			}
			if !reflect.DeepEqual(version.qualifiers, getQualifiersFromInput(input.Qualifiers)) {
				continue
			}
			if found {
				return 0, gqlerror.Errorf("More than one package matches input")
			}
			packageID = version.id
			found = true
		}
		if !found {
			return 0, gqlerror.Errorf("No package matches input")
		}
	}
	return packageID, nil
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
	if qualifiersSpec == nil {
		return qualifiersMap
	}
	for _, kv := range qualifiersSpec {
		qualifiersMap[kv.Key] = kv.Value
	}
	return qualifiersMap
}

func getQualifiersFromFilter(qualifiersSpec []*model.PackageQualifierSpec) map[string]string {
	qualifiersMap := map[string]string{}
	if qualifiersSpec == nil {
		return qualifiersMap
	}
	for _, kv := range qualifiersSpec {
		qualifiersMap[kv.Key] = *kv.Value
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

func (c *demoClient) findPackageVersion(filter *model.PkgSpec) ([]*pkgVersionNode, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		id := uint32(id64)
		if node, ok := c.index[id]; ok {
			if c, ok := node.(*pkgVersionNode); ok {
				return []*pkgVersionNode{c}, nil
			}
		}
	}
	out := make([]*pkgVersionNode, 0)
	if filter.Type != nil && filter.Namespace != nil && filter.Name != nil && filter.Version != nil {
		tp, ok := c.packages[*filter.Type]
		if !ok {
			return nil, nil
		}
		ns, ok := tp.namespaces[*filter.Namespace]
		if !ok {
			return nil, nil
		}
		nm, ok := ns.names[*filter.Name]
		if !ok {
			return nil, nil
		}
		for _, v := range nm.versions {
			if *filter.Version != v.version ||
				noMatch(filter.Subpath, v.subpath) ||
				noMatchQualifiers(filter, v.qualifiers) {
				continue
			}
			out = append(out, v)
		}
	}
	return out, nil
}

func (c *demoClient) exactPackageName(filter *model.PkgSpec) (*pkgVersionStruct, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		id := uint32(id64)
		if node, ok := c.index[id]; ok {
			if c, ok := node.(*pkgVersionStruct); ok {
				return c, nil
			}
		}
	}
	if filter.Type != nil && filter.Namespace != nil && filter.Name != nil {
		tp, ok := c.packages[*filter.Type]
		if !ok {
			return nil, nil
		}
		ns, ok := tp.namespaces[*filter.Namespace]
		if !ok {
			return nil, nil
		}
		nm, ok := ns.names[*filter.Name]
		if !ok {
			return nm, nil
		}
	}
	return nil, nil
}
