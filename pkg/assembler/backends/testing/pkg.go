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
	"log"
	"reflect"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// TODO: move this into a unit test for this file
func registerAllPackages(client *demoClient) {
	ctx := context.Background()

	v11 := "2.11.1"
	v12 := "2.12.0"
	subpath1 := "saved_model_cli.py"
	subpath2 := "__init__.py"
	opensslNamespace := "openssl.org"
	opensslVersion := "3.0.3"

	inputs := []model.PkgInputSpec{{
		Type: "pypi",
		Name: "tensorflow",
	}, {
		Type:    "pypi",
		Name:    "tensorflow",
		Version: &v11,
	}, {
		Type:    "pypi",
		Name:    "tensorflow",
		Version: &v12,
	}, {
		Type:    "pypi",
		Name:    "tensorflow",
		Version: &v12,
		Subpath: &subpath1,
	}, {
		Type:    "pypi",
		Name:    "tensorflow",
		Version: &v12,
		Subpath: &subpath2,
	}, {
		Type:    "pypi",
		Name:    "tensorflow",
		Version: &v12,
		Subpath: &subpath1,
	}, {
		Type:      "conan",
		Namespace: &opensslNamespace,
		Name:      "openssl",
		Version:   &opensslVersion,
	}}

	for _, input := range inputs {
		_, err := client.IngestPackage(ctx, input)
		if err != nil {
			log.Printf("Error in ingesting: %v\n", err)
		}
	}
}

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
	id               uint32
	parent           uint32
	name             string
	versions         pkgVersionList
	srcMapLink       []uint32
	isDependencyLink []uint32
}
type pkgVersionList []*pkgVersionNode
type pkgVersionNode struct {
	id               uint32
	parent           uint32
	version          string
	subpath          string
	qualifiers       map[string]string
	srcMapLink       []uint32
	isDependencyLink []uint32
}

// Be type safe, don't use any / interface{}
type pkgNameOrVersion interface {
	implementsPkgNameOrVersion()
	setSrcMapLink(id uint32)
	getSrcMapLink() []uint32
	setIsDependencyLink(id uint32)
	getIsDependencyLink() []uint32
}

func (n *pkgNamespaceStruct) getID() uint32 { return n.id }
func (n *pkgNameStruct) getID() uint32      { return n.id }
func (n *pkgVersionStruct) getID() uint32   { return n.id }
func (n *pkgVersionNode) getID() uint32     { return n.id }

func (p *pkgVersionStruct) implementsPkgNameOrVersion() {}
func (p *pkgVersionNode) implementsPkgNameOrVersion()   {}

// hasSourceAt back edges
func (p *pkgVersionStruct) setSrcMapLink(id uint32) { p.srcMapLink = append(p.srcMapLink, id) }
func (p *pkgVersionNode) setSrcMapLink(id uint32)   { p.srcMapLink = append(p.srcMapLink, id) }
func (p *pkgVersionStruct) getSrcMapLink() []uint32 { return p.srcMapLink }
func (p *pkgVersionNode) getSrcMapLink() []uint32   { return p.srcMapLink }

// isDependency back edges
func (p *pkgVersionStruct) setIsDependencyLink(id uint32) {
	p.isDependencyLink = append(p.isDependencyLink, id)
}
func (p *pkgVersionNode) setIsDependencyLink(id uint32) {
	p.isDependencyLink = append(p.isDependencyLink, id)
}
func (p *pkgVersionStruct) getIsDependencyLink() []uint32 { return p.isDependencyLink }
func (p *pkgVersionNode) getIsDependencyLink() []uint32   { return p.isDependencyLink }

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
			id:               c.getNextID(),
			parent:           namesStruct.id,
			name:             input.Name,
			versions:         pkgVersionList{},
			srcMapLink:       []uint32{},
			isDependencyLink: []uint32{},
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
			id:               c.getNextID(),
			parent:           versionStruct.id,
			version:          nilToEmpty(input.Version),
			subpath:          nilToEmpty(input.Subpath),
			qualifiers:       qualifiersVal,
			srcMapLink:       []uint32{},
			isDependencyLink: []uint32{},
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

func getPackageIDFromInput(c *demoClient, input model.PkgInputSpec, pkgMatchType model.MatchFlags) (*uint32, error) {
	pkgNamespace, pkgHasNamespace := c.packages[input.Type]
	if !pkgHasNamespace {
		return nil, gqlerror.Errorf("Package type \"%s\" not found", input.Type)
	}
	pkgName, pkgHasName := pkgNamespace.namespaces[nilToEmpty(input.Namespace)]
	if !pkgHasName {
		return nil, gqlerror.Errorf("Package namespace \"%s\" not found", nilToEmpty(input.Namespace))
	}
	pkgVersion, pkgHasVersion := pkgName.names[input.Name]
	if !pkgHasVersion {
		return nil, gqlerror.Errorf("Package name \"%s\" not found", input.Name)
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
				return nil, gqlerror.Errorf("More than one package matches input")
			}
			packageID = version.id
			found = true
		}
		if !found {
			return nil, gqlerror.Errorf("No package matches input")
		}
	}
	return &packageID, nil
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

// TODO: remove these once the other components don't utilize it
func filterPackageNamespace(pkg *model.Package, pkgSpec *model.PkgSpec) *model.Package {
	var namespaces []*model.PackageNamespace
	for _, ns := range pkg.Namespaces {
		if pkgSpec.Namespace == nil || ns.Namespace == *pkgSpec.Namespace {
			newNs := filterPackageName(ns, pkgSpec)
			if newNs != nil {
				namespaces = append(namespaces, newNs)
			}
		}
	}
	if len(namespaces) == 0 {
		return nil
	}
	return &model.Package{
		Type:       pkg.Type,
		Namespaces: namespaces,
	}
}

// TODO: remove these once the other components don't utilize it
func filterPackageName(ns *model.PackageNamespace, pkgSpec *model.PkgSpec) *model.PackageNamespace {
	var names []*model.PackageName
	for _, n := range ns.Names {
		if pkgSpec.Name == nil || n.Name == *pkgSpec.Name {
			newN := filterPackageVersion(n, pkgSpec)
			if newN != nil {
				names = append(names, newN)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	return &model.PackageNamespace{
		Namespace: ns.Namespace,
		Names:     names,
	}
}

// TODO: remove these once the other components don't utilize it
func filterPackageVersion(n *model.PackageName, pkgSpec *model.PkgSpec) *model.PackageName {
	var versions []*model.PackageVersion
	for _, v := range n.Versions {
		if pkgSpec.Version == nil || v.Version == *pkgSpec.Version {
			newV := filterQualifiersAndSubpath(v, pkgSpec)
			if newV != nil {
				versions = append(versions, newV)
			}
		}
	}
	if len(versions) == 0 {
		return nil
	}
	return &model.PackageName{
		Name:     n.Name,
		Versions: versions,
	}
}

// TODO: remove these once the other components don't utilize it
func filterQualifiersAndSubpath(v *model.PackageVersion, pkgSpec *model.PkgSpec) *model.PackageVersion {
	// First check for subpath matching
	if pkgSpec.Subpath != nil && *pkgSpec.Subpath != v.Subpath {
		return nil
	}

	// Allow matching on nodes with no qualifiers
	if pkgSpec.MatchOnlyEmptyQualifiers != nil {
		if *pkgSpec.MatchOnlyEmptyQualifiers && len(v.Qualifiers) != 0 {
			return nil
		}
	}

	// Because we operate on GraphQL-generated structs directly we cannot
	// use a key-value map, so this is O(n^2). Production resolvers will
	// run queries that match the qualifiers faster.
	for _, specQualifier := range pkgSpec.Qualifiers {
		found := false
		for _, versionQualifier := range v.Qualifiers {
			if specQualifier.Key == versionQualifier.Key {
				if specQualifier.Value == nil || *specQualifier.Value == versionQualifier.Value {
					found = true
					break
				}
			}
		}
		if !found {
			return nil
		}
	}
	return v
}
