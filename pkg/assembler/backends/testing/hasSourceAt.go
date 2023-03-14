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

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// func registerAllHasSourceAt(client *demoClient) error {
// 	// pkg:pypi/django@1.11.1
// 	// client.registerPackage("pypi", "", "django", "1.11.1", "")
// 	selectedType := "pypi"
// 	selectedNameSpace := ""
// 	selectedName := "django"
// 	selectedVersion := "1.11.1"
// 	selectedSubpath := ""
// 	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubpath}
// 	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
// 	if err != nil {
// 		return err
// 	}

// 	// "git", "github", "https://github.com/django/django", "tag=1.11.1"
// 	selectedSourceType := "git"
// 	selectedSourceNameSpace := "github"
// 	selectedSourceName := "https://github.com/django/django"
// 	selectedTag := "1.11.1"
// 	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
// 	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = client.registerHasSourceAt(selectedPackage[0], selectedSource[0], time.Now(), "django located at the following source based on deps.dev", "testing backend", "testing backend")
// 	if err != nil {
// 		return err
// 	}
// 	// pkg:pypi/kubetest@0.9.5
// 	// client.registerPackage("pypi", "", "kubetest", "0.9.5", "")

// 	selectedType = "pypi"
// 	selectedNameSpace = ""
// 	selectedName = "kubetest"
// 	selectedVersion = "0.9.5"
// 	selectedSubpath = ""
// 	selectedPkgSpec = &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubpath}
// 	selectedPackage, err = client.Packages(context.TODO(), selectedPkgSpec)
// 	if err != nil {
// 		return err
// 	}

// 	// "git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5"
// 	// client.registerSource("git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5")

// 	selectedSourceType = "git"
// 	selectedSourceNameSpace = "github"
// 	selectedSourceName = "https://github.com/vapor-ware/kubetest"
// 	selectedTag = "0.9.5"
// 	selectedSourceSpec = &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
// 	selectedSource, err = client.Sources(context.TODO(), selectedSourceSpec)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = client.registerHasSourceAt(selectedPackage[0], selectedSource[0], time.Now(), "kubetest located at the following source based on deps.dev", "testing backend", "testing backend")
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// // Ingest HasSourceAt

// func (c *demoClient) registerHasSourceAt(selectedPackage *model.Package, selectedSource *model.Source, since time.Time, justification, origin, collector string) (*model.HasSourceAt, error) {

// 	if selectedPackage == nil || selectedSource == nil {
// 		return nil, fmt.Errorf("package or source is nil")
// 	}

// 	for _, h := range c.hasSourceAt {
// 		if h.Justification == justification && reflect.DeepEqual(h.Package, selectedPackage) && reflect.DeepEqual(h.Source, selectedSource) {
// 			return h, nil
// 		}
// 	}
// 	newHasSourceAt := &model.HasSourceAt{
// 		Package:       selectedPackage,
// 		Source:        selectedSource,
// 		KnownSince:    since.UTC(),
// 		Justification: justification,
// 		Origin:        origin,
// 		Collector:     collector,
// 	}
// 	c.hasSourceAt = append(c.hasSourceAt, newHasSourceAt)
// 	return newHasSourceAt, nil
// }

// func (c *demoClient) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {

// 	var selectedPkgSpec *model.PkgSpec
// 	if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
// 		selectedPkgSpec = helper.ConvertPkgInputSpecToPkgSpec(&pkg)

// 	} else {
// 		selectedPkgSpec = &model.PkgSpec{
// 			Type:      &pkg.Type,
// 			Namespace: pkg.Namespace,
// 			Name:      &pkg.Name,
// 		}
// 	}
// 	collectedPkg, err := c.Packages(ctx, selectedPkgSpec)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if len(collectedPkg) != 1 {
// 		return nil, gqlerror.Errorf(
// 			"IngestCertifyBad :: multiple packages found")
// 	}

// 	sourceSpec := helper.ConvertSrcInputSpecToSrcSpec(&source)

// 	sources, err := c.Sources(ctx, sourceSpec)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if len(sources) != 1 {
// 		return nil, gqlerror.Errorf(
// 			"IngestOccurrence :: source argument must match one"+
// 				" single source repository, found %d",
// 			len(sources))
// 	}
// 	return c.registerHasSourceAt(
// 		collectedPkg[0],
// 		sources[0],
// 		hasSourceAt.KnownSince,
// 		hasSourceAt.Justification,
// 		hasSourceAt.Origin,
// 		hasSourceAt.Collector)
// }

// // Query HasSourceAt

// func (c *demoClient) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {

// 	var collectedHasSourceAt []*model.HasSourceAt

// 	for _, h := range c.hasSourceAt {
// 		matchOrSkip := true

// 		if hasSourceAtSpec.Justification != nil && h.Justification != *hasSourceAtSpec.Justification {
// 			matchOrSkip = false
// 		}
// 		if hasSourceAtSpec.Collector != nil && h.Collector != *hasSourceAtSpec.Collector {
// 			matchOrSkip = false
// 		}
// 		if hasSourceAtSpec.Origin != nil && h.Origin != *hasSourceAtSpec.Origin {
// 			matchOrSkip = false
// 		}

// 		if hasSourceAtSpec.Package != nil && h.Package != nil {
// 			if hasSourceAtSpec.Package.Type == nil || h.Package.Type == *hasSourceAtSpec.Package.Type {
// 				newPkg := filterPackageNamespace(h.Package, hasSourceAtSpec.Package)
// 				if newPkg == nil {
// 					matchOrSkip = false
// 				}
// 			}
// 		}

// 		if hasSourceAtSpec.Source != nil && h.Source != nil {
// 			if hasSourceAtSpec.Source.Type == nil || h.Source.Type == *hasSourceAtSpec.Source.Type {
// 				newSource, err := filterSourceNamespace(h.Source, hasSourceAtSpec.Source)
// 				if err != nil {
// 					return nil, err
// 				}
// 				if newSource == nil {
// 					matchOrSkip = false
// 				}
// 			}
// 		}

// 		if matchOrSkip {
// 			collectedHasSourceAt = append(collectedHasSourceAt, h)
// 		}
// 	}
// 	return collectedHasSourceAt, nil
// }

func (c *demoClient) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	// Note: This assumes that the package and source have already been
	// ingested (and should error otherwise).
	//
	// Note: In general, we may be tempted to convert from input to filter
	// and retrieve the singleton list from the selection resolvers, but
	// this returns a GraphQL struct, not the backend struct.
	//
	// Note: Here we assume that if the source input does not contain
	// tag/commit info then we want to match at package name level,
	// otherwise at package version level. If the input contains more info
	// than what we need, we ignore it.
	matchAtPackageNameLevel := source.Tag != nil || source.Commit != nil

	srcNamespace, srcHasNamespace := sources[source.Type]
	if !srcHasNamespace {
		return nil, gqlerror.Errorf("Source type \"%s\" not found", source.Type)
	}
	srcName, srcHasName := srcNamespace[source.Namespace]
	if !srcHasName {
		return nil, gqlerror.Errorf("Source namespace \"%s\" not found", source.Namespace)
	}
	var srcPtr *srcNameNode
	srcPtr = nil
	for _, src := range srcName {
		if src.name != source.Name {
			continue
		}
		if noMatchPtrInput(source.Tag, src.tag) {
			continue
		}
		if noMatchPtrInput(source.Commit, src.commit) {
			continue
		}
		if srcPtr != nil {
			return nil, gqlerror.Errorf("More than one source matches input")
		}
		srcPtr = src
	}
	if srcPtr == nil {
		return nil, gqlerror.Errorf("No source matches input")
	}

	pkgNamespace, pkgHasNamespace := packages[pkg.Type]
	if !pkgHasNamespace {
		return nil, gqlerror.Errorf("Package type \"%s\" not found", pkg.Type)
	}
	pkgName, pkgHasName := pkgNamespace[nilToEmpty(pkg.Namespace)]
	if !pkgHasName {
		return nil, gqlerror.Errorf("Package namespace \"%s\" not found", nilToEmpty(pkg.Namespace))
	}
	pkgVersion, pkgHasVersion := pkgName[pkg.Name]
	if !pkgHasVersion {
		return nil, gqlerror.Errorf("Package name \"%s\" not found", pkg.Name)
	}
	var pkgPtr pkgNameOrVersion
	if !matchAtPackageNameLevel {
		pkgPtr = pkgVersion
	} else {
		pkgPtr = nil
		for _, version := range pkgVersion.versions {
			if noMatchInput(pkg.Version, version.version) {
				continue
			}
			if noMatchInput(pkg.Subpath, version.subpath) {
				continue
			}
			if pkgPtr != nil {
				return nil, gqlerror.Errorf("More than one package matches input")
			}
			pkgPtr = version
		}
	}
	if pkgPtr == nil {
		return nil, gqlerror.Errorf("No package matches input")
	}

	// store the link
	newSrcMapLink := &srcMapLink{
		justification: hasSourceAt.Justification,
		source:        srcPtr,
		pkg:           pkgPtr,
		knownSince:    hasSourceAt.KnownSince.UTC(),
		origin:        hasSourceAt.Origin,
		collector:     hasSourceAt.Collector,
	}
	pkgPtr.setSource(newSrcMapLink)
	srcPtr.pkg = newSrcMapLink
	sourceMaps = append(sourceMaps, newSrcMapLink)

	// build return GraphQL type
	selectedPkg := packageFromInput(pkg)
	src := sourceFromInput(source)
	out := model.HasSourceAt{
		KnownSince:    hasSourceAt.KnownSince.UTC(),
		Package:       selectedPkg,
		Source:        src,
		Justification: hasSourceAt.Justification,
	}

	return &out, nil
}

func (c *demoClient) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	out := []*model.HasSourceAt{}

	for _, mapLink := range sourceMaps {
		if noMatch(hasSourceAtSpec.Justification, mapLink.justification) {
			continue
		}
		// Note: Here we may call the selection resolvers since we
		// build GraphQL structs based on what's on the backend. But
		// this will result in then having to build a cartesian product
		// between packages (of count, say, P) and sources (of count,
		// say, C), for a total of P*C nodes than then need to be
		// compared with the, say, M sourceMaps that we select so far.
		// In general M << {P, C}, so this is wasteful.
		p := packageMatchingFilter(hasSourceAtSpec.Package, mapLink.pkg)
		if p == nil {
			continue
		}
		s := sourceMatchingFilter(hasSourceAtSpec.Source, mapLink.source)
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
