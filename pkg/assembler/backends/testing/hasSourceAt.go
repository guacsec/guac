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
	"reflect"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllHasSourceAt(client *demoClient) error {
	// pkg:pypi/django@1.11.1
	// client.registerPackage("pypi", "", "django", "1.11.1", "")
	selectedType := "pypi"
	selectedNameSpace := ""
	selectedName := "django"
	selectedVersion := "1.11.1"
	selectedSubpath := ""
	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubpath}
	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// "git", "github", "https://github.com/django/django", "tag=1.11.1"
	selectedSourceType := "git"
	selectedSourceNameSpace := "github"
	selectedSourceName := "https://github.com/django/django"
	selectedTag := "1.11.1"
	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	_, err = client.registerHasSourceAt(selectedPackage[0], selectedSource[0], time.Now(), "django located at the following source based on deps.dev", "testing backend", "testing backend")
	if err != nil {
		return err
	}
	// pkg:pypi/kubetest@0.9.5
	// client.registerPackage("pypi", "", "kubetest", "0.9.5", "")

	selectedType = "pypi"
	selectedNameSpace = ""
	selectedName = "kubetest"
	selectedVersion = "0.9.5"
	selectedSubpath = ""
	selectedPkgSpec = &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubpath}
	selectedPackage, err = client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// "git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5"
	// client.registerSource("git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5")

	selectedSourceType = "git"
	selectedSourceNameSpace = "github"
	selectedSourceName = "https://github.com/vapor-ware/kubetest"
	selectedTag = "0.9.5"
	selectedSourceSpec = &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
	selectedSource, err = client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	_, err = client.registerHasSourceAt(selectedPackage[0], selectedSource[0], time.Now(), "kubetest located at the following source based on deps.dev", "testing backend", "testing backend")
	if err != nil {
		return err
	}
	return nil
}

// Internal data: link between sources and packages (HasSourceAt)
type srcMaps []*srcMapLink
type srcMapLink struct {
	id            nodeID
	sourceID      nodeID
	packageID     nodeID
	knownSince    time.Time
	justification string
	origin        string
	collector     string
}

func (n *srcMapLink) getID() nodeID { return n.id }

// Ingest HasSourceAt
func (c *demoClient) IngestHasSourceAt(ctx context.Context, packageArg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	// Note: This assumes that the package and source have already been
	// ingested (and should error otherwise).

	srcNamespace, srcHasNamespace := sources[source.Type]
	if !srcHasNamespace {
		return nil, gqlerror.Errorf("Source type \"%s\" not found", source.Type)
	}
	srcName, srcHasName := srcNamespace.namespaces[source.Namespace]
	if !srcHasName {
		return nil, gqlerror.Errorf("Source namespace \"%s\" not found", source.Namespace)
	}
	found := false
	var sourceID nodeID
	for _, src := range srcName.names {
		if src.name != source.Name {
			continue
		}
		if noMatchInput(source.Tag, src.tag) {
			continue
		}
		if noMatchInput(source.Commit, src.commit) {
			continue
		}
		if found {
			return nil, gqlerror.Errorf("More than one source matches input")
		}
		sourceID = src.id
		found = true
	}
	if !found {
		return nil, gqlerror.Errorf("No source matches input")
	}

	pkgNamespace, pkgHasNamespace := packages[packageArg.Type]
	if !pkgHasNamespace {
		return nil, gqlerror.Errorf("Package type \"%s\" not found", packageArg.Type)
	}
	pkgName, pkgHasName := pkgNamespace.namespaces[nilToEmpty(packageArg.Namespace)]
	if !pkgHasName {
		return nil, gqlerror.Errorf("Package namespace \"%s\" not found", nilToEmpty(packageArg.Namespace))
	}
	pkgVersion, pkgHasVersion := pkgName.names[packageArg.Name]
	if !pkgHasVersion {
		return nil, gqlerror.Errorf("Package name \"%s\" not found", packageArg.Name)
	}
	var packageID nodeID
	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		packageID = pkgVersion.id
	} else {
		found = false
		for _, version := range pkgVersion.versions {
			if noMatchInput(packageArg.Version, version.version) {
				continue
			}
			if noMatchInput(packageArg.Subpath, version.subpath) {
				continue
			}
			if !reflect.DeepEqual(version.qualifiers, getQualifiers(packageArg.Qualifiers)) {
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

	// store the link
	newSrcMapLink := &srcMapLink{
		id:            c.getNextID(),
		sourceID:      sourceID,
		packageID:     packageID,
		knownSince:    hasSourceAt.KnownSince.UTC(),
		justification: hasSourceAt.Justification,
		origin:        hasSourceAt.Origin,
		collector:     hasSourceAt.Collector,
	}
	index[newSrcMapLink.id] = newSrcMapLink
	sourceMaps = append(sourceMaps, newSrcMapLink)
	// set the backlinks
	index[packageID].(pkgNameOrVersion).setSrcMapLink(newSrcMapLink.id)
	index[sourceID].(*srcNameNode).srcMapLink = newSrcMapLink.id

	// build return GraphQL type
	p, err := buildPackageResponse(packageID, nil)
	if err != nil {
		return nil, err
	}
	s, err := buildSourceResponse(sourceID, nil)
	if err != nil {
		return nil, err
	}
	out := model.HasSourceAt{
		Package:       p,
		Source:        s,
		KnownSince:    hasSourceAt.KnownSince.UTC(),
		Justification: hasSourceAt.Justification,
		Origin:        hasSourceAt.Origin,
		Collector:     hasSourceAt.Collector,
	}

	return &out, nil
}

func (c *demoClient) registerHasSourceAt(selectedPackage *model.Package, selectedSource *model.Source, since time.Time, justification, origin, collector string) (*model.HasSourceAt, error) {

	if selectedPackage == nil || selectedSource == nil {
		return nil, fmt.Errorf("package or source is nil")
	}

	for _, h := range c.hasSourceAt {
		if h.Justification == justification && reflect.DeepEqual(h.Package, selectedPackage) && reflect.DeepEqual(h.Source, selectedSource) {
			return h, nil
		}
	}
	newHasSourceAt := &model.HasSourceAt{
		Package:       selectedPackage,
		Source:        selectedSource,
		KnownSince:    since.UTC(),
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	c.hasSourceAt = append(c.hasSourceAt, newHasSourceAt)
	return newHasSourceAt, nil
}

// Query HasSourceAt

func (c *demoClient) HasSourceAt(ctx context.Context, filter *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	out := []*model.HasSourceAt{}

	for _, mapLink := range sourceMaps {
		if noMatch(filter.Justification, mapLink.justification) || noMatch(filter.Origin, mapLink.origin) || noMatch(filter.Collector, mapLink.collector) {
			continue
		}
		// Note: Here we may call the selection resolvers since we
		// build GraphQL structs based on what's on the backend. But
		// this will result in then having to build a cartesian product
		// between packages (of count, say, P) and sources (of count,
		// say, C), for a total of P*C nodes than then need to be
		// compared with the, say, M sourceMaps that we select so far.
		// In general M << {P, C}, so this is wasteful.
		p, err := buildPackageResponse(mapLink.packageID, filter.Package)
		if err != nil {
			return nil, err
		}
		if p == nil {
			continue
		}
		s, err := buildSourceResponse(mapLink.sourceID, filter.Source)
		if err != nil {
			return nil, err
		}
		if s == nil {
			continue
		}
		newHSA := model.HasSourceAt{
			Package:       p,
			Source:        s,
			KnownSince:    mapLink.knownSince,
			Justification: mapLink.justification,
			Origin:        mapLink.origin,
			Collector:     mapLink.collector,
		}
		out = append(out, &newHSA)
	}

	return out, nil
}
