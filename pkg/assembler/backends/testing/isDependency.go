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
	"errors"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal data: link between packages and dependent packages (isDependency)
type isDependencyList []*isDependencyLink
type isDependencyLink struct {
	id            uint32
	packageID     uint32
	depPackageID  uint32
	versionRange  string
	justification string
	origin        string
	collector     string
}

func (n *isDependencyLink) getID() uint32 { return n.id }

// Ingest IsDependency
func (c *demoClient) IngestDependency(ctx context.Context, packageArg model.PkgInputSpec, dependentPackageArg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	packageID, err := getPackageIDFromInput(c, packageArg, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion})
	if err != nil {
		return nil, err
	}

	// for IsDependency the dependent package will return the ID at the packageName node. VersionRange will be used to specify the
	// versions are the attestation relates to
	depPackageID, err := getPackageIDFromInput(c, dependentPackageArg, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions})
	if err != nil {
		return nil, err
	}

	packageDependencies := []uint32{}
	pkgVersionNode, ok := c.index[packageID].(*pkgVersionNode)
	if ok {
		packageDependencies = append(packageDependencies, pkgVersionNode.isDependencyLink...)
	}
	depPackageDependencies := []uint32{}
	pkgName, ok := c.index[depPackageID].(*pkgVersionStruct)
	if ok {
		depPackageDependencies = append(depPackageDependencies, pkgName.isDependencyLink...)
	}

	searchIDs := []uint32{}
	if len(packageDependencies) > len(depPackageDependencies) {
		searchIDs = append(searchIDs, depPackageDependencies...)
	} else {
		searchIDs = append(searchIDs, packageDependencies...)
	}

	// Don't insert duplicates
	duplicate := false
	collectedIsDependencyLink := isDependencyLink{}
	for _, id := range searchIDs {
		v, _ := c.dependencyByID(id)
		if packageID == v.packageID && depPackageID == v.depPackageID && dependency.Justification == v.justification &&
			dependency.Origin == v.origin && dependency.Collector == v.collector && dependency.VersionRange == v.versionRange {

			collectedIsDependencyLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		// store the link
		collectedIsDependencyLink = isDependencyLink{
			id:            c.getNextID(),
			packageID:     packageID,
			depPackageID:  depPackageID,
			versionRange:  dependency.VersionRange,
			justification: dependency.Justification,
			origin:        dependency.Origin,
			collector:     dependency.Collector,
		}
		c.index[collectedIsDependencyLink.id] = &collectedIsDependencyLink
		c.isDependencies = append(c.isDependencies, &collectedIsDependencyLink)
		// set the backlinks
		c.index[packageID].(pkgNameOrVersion).setIsDependencyLink(collectedIsDependencyLink.id)
		c.index[depPackageID].(pkgNameOrVersion).setIsDependencyLink(collectedIsDependencyLink.id)
	}

	// build return GraphQL type
	foundIsDependency, err := buildIsDependency(c, &collectedIsDependencyLink, nil, true)
	if err != nil {
		return nil, err
	}

	return foundIsDependency, nil
}

// Query IsDependency
func (c *demoClient) IsDependency(ctx context.Context, filter *model.IsDependencySpec) ([]*model.IsDependency, error) {
	out := []*model.IsDependency{}

	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		node, ok := c.index[uint32(id)]
		if !ok {
			return nil, gqlerror.Errorf("ID does not match existing node")
		}
		if link, ok := node.(*isDependencyLink); ok {
			foundIsDependency, err := buildIsDependency(c, link, filter, true)
			if err != nil {
				return nil, err
			}
			return []*model.IsDependency{foundIsDependency}, nil
		} else {
			return nil, gqlerror.Errorf("ID does not match expected node type for isDependency")
		}
	}

	// TODO if any of the pkg/dependent pkg are specified, ony search those backedges
	for _, link := range c.isDependencies {
		if filter != nil && noMatch(filter.Justification, link.justification) {
			continue
		}
		if filter != nil && noMatch(filter.Origin, link.origin) {
			continue
		}
		if filter != nil && noMatch(filter.Collector, link.collector) {
			continue
		}
		if filter != nil && noMatch(filter.VersionRange, link.versionRange) {
			continue
		}

		foundIsDependency, err := buildIsDependency(c, link, filter, false)
		if err != nil {
			return nil, err
		}
		if foundIsDependency == nil {
			continue
		}
		out = append(out, foundIsDependency)
	}

	return out, nil
}

func buildIsDependency(c *demoClient, link *isDependencyLink, filter *model.IsDependencySpec, ingestOrIDProvided bool) (*model.IsDependency, error) {
	var p *model.Package
	var dep *model.Package
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
	if filter != nil && filter.DependentPackage != nil {
		depPkgFilter := &model.PkgSpec{Type: filter.DependentPackage.Type, Namespace: filter.DependentPackage.Namespace,
			Name: filter.DependentPackage.Name}
		dep, err = c.buildPackageResponse(link.depPackageID, depPkgFilter)
		if err != nil {
			return nil, err
		}
	} else {
		dep, err = c.buildPackageResponse(link.depPackageID, nil)
		if err != nil {
			return nil, err
		}
	}

	// if package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if p == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve package via packageID")
	} else if p == nil && !ingestOrIDProvided {
		return nil, nil
	}
	// if dependent package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if dep == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve dependent package via dependent packageID")
	} else if dep == nil && !ingestOrIDProvided {
		return nil, nil
	}

	foundIsDependency := model.IsDependency{
		ID:               nodeID(link.id),
		Package:          p,
		DependentPackage: dep,
		VersionRange:     link.versionRange,
		Justification:    link.justification,
		Origin:           link.origin,
		Collector:        link.collector,
	}
	return &foundIsDependency, nil
}

func (c *demoClient) dependencyByID(id uint32) (*isDependencyLink, error) {
	node, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find isDependencyLink")
	}
	link, ok := node.(*isDependencyLink)
	if !ok {
		return nil, errors.New("not an isDependencyLink")
	}
	return link, nil
}
