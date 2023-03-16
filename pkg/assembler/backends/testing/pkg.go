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
	"fmt"
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
	id         uint32
	parent     uint32
	name       string
	versions   pkgVersionList
	srcMapLink uint32
}
type pkgVersionList []*pkgVersionNode
type pkgVersionNode struct {
	id         uint32
	parent     uint32
	version    string
	subpath    string
	qualifiers map[string]string
	srcMapLink uint32
}

// Be type safe, don't use any / interface{}
type pkgNameOrVersion interface {
	implementsPkgNameOrVersion()
	setSrcMapLink(id uint32)
	getSrcMapLink() uint32
}

func (n *pkgNamespaceStruct) getID() uint32 { return n.id }
func (n *pkgNameStruct) getID() uint32      { return n.id }
func (n *pkgVersionStruct) getID() uint32   { return n.id }
func (n *pkgVersionNode) getID() uint32     { return n.id }

func (p *pkgVersionStruct) implementsPkgNameOrVersion() {}
func (p *pkgVersionNode) implementsPkgNameOrVersion()   {}
func (p *pkgVersionStruct) setSrcMapLink(id uint32)     { p.srcMapLink = id }
func (p *pkgVersionNode) setSrcMapLink(id uint32)       { p.srcMapLink = id }
func (p *pkgVersionStruct) getSrcMapLink() uint32       { return p.srcMapLink }
func (p *pkgVersionNode) getSrcMapLink() uint32         { return p.srcMapLink }

// Ingest Package
func (c *demoClient) IngestPackage(ctx context.Context, input model.PkgInputSpec) (*model.Package, error) {
	namespacesStruct, hasNamespace := packages[input.Type]
	if !hasNamespace {
		namespacesStruct = &pkgNamespaceStruct{
			id:         c.getNextID(),
			typeKey:    input.Type,
			namespaces: pkgNamespaceMap{},
		}
		index[namespacesStruct.id] = namespacesStruct
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
		index[namesStruct.id] = namesStruct
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
		index[versionStruct.id] = versionStruct
	}
	versions := versionStruct.versions

	newVersion := pkgVersionNode{
		id:         c.getNextID(),
		parent:     versionStruct.id,
		version:    nilToEmpty(input.Version),
		subpath:    nilToEmpty(input.Subpath),
		qualifiers: getQualifiersFromInput(input.Qualifiers),
	}
	index[newVersion.id] = &newVersion

	// Don't insert duplicates
	duplicate := false
	for _, v := range versions {
		if v.version == newVersion.version && v.subpath == newVersion.subpath && reflect.DeepEqual(v.qualifiers, newVersion.qualifiers) {
			duplicate = true
			break
		}
	}
	if !duplicate {
		// Need to append to version and replace field in versionStruct
		versionStruct.versions = append(versions, &newVersion)
		// All others are refs to maps, so no need to update struct
		names[input.Name] = versionStruct
		namespaces[nilToEmpty(input.Namespace)] = namesStruct
		packages[input.Type] = namespacesStruct
	}

	// build return GraphQL type
	return buildPackageResponse(newVersion.id, nil)
}

// Query Package
func (c *demoClient) Packages(ctx context.Context, filter *model.PkgSpec) ([]*model.Package, error) {
	if filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		p, err := buildPackageResponse(uint32(id), filter)
		if err != nil {
			return nil, err
		}
		return []*model.Package{p}, nil
	}
	out := []*model.Package{}
	for dbType, namespaces := range packages {
		if filter != nil && noMatch(filter.Type, dbType) {
			continue
		}
		pNamespaces := []*model.PackageNamespace{}
		for namespace, names := range namespaces.namespaces {
			if filter != nil && noMatch(filter.Namespace, namespace) {
				continue
			}
			pns := []*model.PackageName{}
			for name, versions := range names.names {
				if filter != nil && noMatch(filter.Name, name) {
					continue
				}
				pvs := []*model.PackageVersion{}
				for _, v := range versions.versions {
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
						ID:         fmt.Sprintf("%d", v.id),
						Version:    v.version,
						Subpath:    v.subpath,
						Qualifiers: getCollectedPackageQualifiers(v.qualifiers),
					})
				}
				if len(pvs) > 0 {
					pns = append(pns, &model.PackageName{
						ID:       fmt.Sprintf("%d", versions.id),
						Name:     name,
						Versions: pvs,
					})
				}
			}
			if len(pns) > 0 {
				pNamespaces = append(pNamespaces, &model.PackageNamespace{
					ID:        fmt.Sprintf("%d", names.id),
					Namespace: namespace,
					Names:     pns,
				})
			}
		}
		if len(pNamespaces) > 0 {
			out = append(out, &model.Package{
				ID:         fmt.Sprintf("%d", namespaces.id),
				Type:       dbType,
				Namespaces: pNamespaces,
			})
		}
	}
	return out, nil
}

// Builds a model.Package to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func buildPackageResponse(id uint32, filter *model.PkgSpec) (*model.Package, error) {
	if filter != nil && filter.ID != nil {
		filteredID, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		if uint32(filteredID) != id {
			return nil, nil
		}
	}

	node, ok := index[id]
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
			ID:         fmt.Sprintf("%d", versionNode.id),
			Version:    versionNode.version,
			Subpath:    versionNode.subpath,
			Qualifiers: getCollectedPackageQualifiers(versionNode.qualifiers),
		})
		node = index[versionNode.parent]
	}

	pnl := []*model.PackageName{}
	if versionStruct, ok := node.(*pkgVersionStruct); ok {
		if filter != nil && noMatch(filter.Name, versionStruct.name) {
			return nil, nil
		}
		pnl = append(pnl, &model.PackageName{
			ID:       fmt.Sprintf("%d", versionStruct.id),
			Name:     versionStruct.name,
			Versions: pvl,
		})
		node = index[versionStruct.parent]
	}

	pnsl := []*model.PackageNamespace{}
	if nameStruct, ok := node.(*pkgNameStruct); ok {
		if filter != nil && noMatch(filter.Namespace, nameStruct.namespace) {
			return nil, nil
		}
		pnsl = append(pnsl, &model.PackageNamespace{
			ID:        fmt.Sprintf("%d", nameStruct.id),
			Namespace: nameStruct.namespace,
			Names:     pnl,
		})
		node = index[nameStruct.parent]
	}

	namespaceStruct, ok := node.(*pkgNamespaceStruct)
	if !ok {
		return nil, gqlerror.Errorf("ID does not match expected node type")
	}
	p := model.Package{
		ID:         fmt.Sprintf("%d", namespaceStruct.id),
		Type:       namespaceStruct.typeKey,
		Namespaces: pnsl,
	}
	if filter != nil && noMatch(filter.Type, p.Type) {
		return nil, nil
	}
	return &p, nil
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
	if filter.Qualifiers != nil {
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
