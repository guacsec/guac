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
	id                uint32
	parent            uint32
	name              string
	versions          pkgVersionList
	srcMapLinks       []uint32
	isDependencyLinks []uint32
	badLinks          []uint32
}
type pkgVersionList []*pkgVersionNode
type pkgVersionNode struct {
	id                uint32
	parent            uint32
	version           string
	subpath           string
	qualifiers        map[string]string
	srcMapLinks       []uint32
	isDependencyLinks []uint32
	occurrences       []uint32
	certifyVulnLinks  []uint32
	hasSBOMs          []uint32
	vexLinks          []uint32
	badLinks          []uint32
	certifyPkgs       []uint32
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
}

func (n *pkgNamespaceStruct) ID() uint32 { return n.id }
func (n *pkgNameStruct) ID() uint32      { return n.id }
func (n *pkgVersionStruct) ID() uint32   { return n.id }
func (n *pkgVersionNode) ID() uint32     { return n.id }

func (n *pkgNamespaceStruct) Neighbors() []uint32 {
	out := make([]uint32, 0, 1+len(n.namespaces))
	for _, v := range n.namespaces {
		out = append(out, v.id)
	}
	return out
}
func (n *pkgNameStruct) Neighbors() []uint32 {
	out := make([]uint32, 0, 1+len(n.names))
	for _, v := range n.names {
		out = append(out, v.id)
	}
	out = append(out, n.parent)
	return out
}
func (n *pkgVersionStruct) Neighbors() []uint32 {
	out := make([]uint32, 0, 1+len(n.versions)+len(n.srcMapLinks)+len(n.isDependencyLinks)+len(n.badLinks))
	for _, v := range n.versions {
		out = append(out, v.id)
	}
	out = append(out, n.srcMapLinks...)
	out = append(out, n.isDependencyLinks...)
	out = append(out, n.badLinks...)
	out = append(out, n.parent)
	return out
}
func (n *pkgVersionNode) Neighbors() []uint32 {
	out := make([]uint32, 0, 1+len(n.srcMapLinks)+len(n.isDependencyLinks)+len(n.occurrences)+len(n.certifyVulnLinks)+len(n.hasSBOMs)+len(n.vexLinks)+len(n.badLinks)+len(n.certifyPkgs))
	out = append(out, n.srcMapLinks...)
	out = append(out, n.isDependencyLinks...)
	out = append(out, n.occurrences...)
	out = append(out, n.certifyVulnLinks...)
	out = append(out, n.hasSBOMs...)
	out = append(out, n.vexLinks...)
	out = append(out, n.badLinks...)
	out = append(out, n.certifyPkgs...)
	out = append(out, n.parent)
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
func (p *pkgVersionNode) getHasSBOM() []uint32 { return p.hasSBOMs }

// certifyBad back edges
func (p *pkgVersionStruct) setCertifyBadLinks(id uint32) { p.badLinks = append(p.badLinks, id) }
func (p *pkgVersionNode) setCertifyBadLinks(id uint32)   { p.badLinks = append(p.badLinks, id) }
func (p *pkgVersionStruct) getCertifyBadLinks() []uint32 { return p.badLinks }
func (p *pkgVersionNode) getCertifyBadLinks() []uint32   { return p.badLinks }

// certifyPkg back edges
func (p *pkgVersionNode) setCertifyPkgs(id uint32) { p.certifyPkgs = append(p.certifyPkgs, id) }

// Ingest Package
func (c *demoClient) IngestPackage(ctx context.Context, input model.PkgInputSpec) (*model.Package, error) {
	namespacesStruct, hasNamespace := c.packages[input.Type]
	if !hasNamespace {
		namespacesStruct = &pkgNamespaceStruct{
			id:         c.getNextID(),
			typeKey:    input.Type,
			namespaces: pkgNamespaceMap{},
		}
		c.index[namespacesStruct.id] = namespacesStruct
	}
	namespaces := namespacesStruct.namespaces

	namesStruct, hasName := namespaces[nilToEmpty(input.Namespace)]
	if !hasName {
		namesStruct = &pkgNameStruct{
			id:        c.getNextID(),
			parent:    namespacesStruct.id,
			namespace: nilToEmpty(input.Namespace),
			names:     pkgNameMap{},
		}
		c.index[namesStruct.id] = namesStruct
	}
	names := namesStruct.names

	versionStruct, hasVersions := names[input.Name]
	if !hasVersions {
		versionStruct = &pkgVersionStruct{
			id:       c.getNextID(),
			parent:   namesStruct.id,
			name:     input.Name,
			versions: pkgVersionList{},
		}
		c.index[versionStruct.id] = versionStruct
	}
	versions := versionStruct.versions

	qualifiersVal := getQualifiersFromInput(input.Qualifiers)

	// Don't insert duplicates
	duplicate := false
	collectedVersion := pkgVersionNode{}
	for _, v := range versions {
		if noMatchInput(input.Version, v.version) {
			continue
		}
		if noMatchInput(input.Subpath, v.subpath) {
			continue
		}
		if !reflect.DeepEqual(v.qualifiers, qualifiersVal) {
			continue
		}
		collectedVersion = *v
		duplicate = true
		break
	}
	if !duplicate {
		collectedVersion = pkgVersionNode{
			id:         c.getNextID(),
			parent:     versionStruct.id,
			version:    nilToEmpty(input.Version),
			subpath:    nilToEmpty(input.Subpath),
			qualifiers: qualifiersVal,
		}
		c.index[collectedVersion.id] = &collectedVersion
		// Need to append to version and replace field in versionStruct
		versionStruct.versions = append(versions, &collectedVersion)
		// All others are refs to maps, so no need to update struct
		names[input.Name] = versionStruct
		namespaces[nilToEmpty(input.Namespace)] = namesStruct
		c.packages[input.Type] = namespacesStruct
	}

	// build return GraphQL type
	return c.buildPackageResponse(collectedVersion.id, nil)
}

// Query Package
func (c *demoClient) Packages(ctx context.Context, filter *model.PkgSpec) ([]*model.Package, error) {
	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		p, err := c.buildPackageResponse(uint32(id), filter)
		if err != nil {
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
		filteredID, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		if uint32(filteredID) != id {
			return nil, nil
		}
	}

	node, ok := c.index[id]
	if !ok {
		return nil, gqlerror.Errorf("ID does not match existing node")
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
		node = c.index[versionNode.parent]
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
		node = c.index[versionStruct.parent]
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
		node = c.index[nameStruct.parent]
	}

	namespaceStruct, ok := node.(*pkgNamespaceStruct)
	if !ok {
		return nil, gqlerror.Errorf("ID does not match expected node type for package namespace")
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

func (c *demoClient) pkgVersionByID(id uint32) (*pkgVersionNode, error) {
	o, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find pkg")
	}
	if a, ok := o.(*pkgVersionNode); ok {
		return a, nil
	}
	return nil, errors.New("not a pkg")
}
