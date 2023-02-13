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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type DemoCredentials struct{}

type demoClient struct {
	packages     []*model.Package
	sources      []*model.Source
	cve          []*model.Cve
	ghsa         []*model.Ghsa
	osv          []*model.Osv
	artifacts    []*model.Artifact
	builders     []*model.Builder
	hashEquals []*model.HashEqual
	isOccurrence []*model.IsOccurrence
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	client := &demoClient{
		packages:  []*model.Package{},
		sources:   []*model.Source{},
		cve:       []*model.Cve{},
		ghsa:      []*model.Ghsa{},
		osv:       []*model.Osv{},
		artifacts: []*model.Artifact{},
		builders:  []*model.Builder{},
	}
	registerAllPackages(client)
	registerAllSources(client)
	registerAllCVE(client)
	registerAllGHSA(client)
	registerAllOSV(client)
	registerAllArtifacts(client)
	registerAllBuilders(client)
	registerAllHashEqual(client)
	err := registerAllIsOccurrence(client)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (c *demoClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	var packages []*model.Package
	for _, p := range c.packages {
		if pkgSpec.Type == nil || p.Type == *pkgSpec.Type {
			newPkg := filterPackageNamespace(p, pkgSpec)
			if newPkg != nil {
				packages = append(packages, newPkg)
			}
		}
	}
	return packages, nil
}

func (c *demoClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	var sources []*model.Source
	for _, s := range c.sources {
		if sourceSpec.Type == nil || s.Type == *sourceSpec.Type {
			newSource, err := filterSourceNamespace(s, sourceSpec)
			if err != nil {
				return nil, err
			}
			if newSource != nil {
				sources = append(sources, newSource)
			}
		}
	}
	return sources, nil
}

func (c *demoClient) Cve(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error) {
	var cve []*model.Cve
	for _, s := range c.cve {
		if cveSpec.Year == nil || s.Year == *cveSpec.Year {
			newCve, err := filterCVEID(s, cveSpec)
			if err != nil {
				return nil, err
			}
			if newCve != nil {
				cve = append(cve, newCve)
			}
		}
	}
	return cve, nil
}

func (c *demoClient) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	var ghsa []*model.Ghsa
	for _, g := range c.ghsa {
		newGHSA, err := filterGHSAID(g, ghsaSpec)
		if err != nil {
			return nil, err
		}
		if newGHSA != nil {
			ghsa = append(ghsa, newGHSA)
		}
	}
	return ghsa, nil
}

func (c *demoClient) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	var osv []*model.Osv
	for _, o := range c.osv {
		newOSV, err := filterOSVID(o, osvSpec)
		if err != nil {
			return nil, err
		}
		if newOSV != nil {
			osv = append(osv, newOSV)
		}
	}
	return osv, nil
}

func (c *demoClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	var artifacts []*model.Artifact

	// enforce lowercase for both the algorithm and digest when querying
	for _, a := range c.artifacts {
		if artifactSpec.Digest == nil && artifactSpec.Algorithm == nil {
			artifacts = append(artifacts, a)
		} else if artifactSpec.Digest != nil && artifactSpec.Algorithm == nil && a.Digest == strings.ToLower(*artifactSpec.Digest) {
			artifacts = append(artifacts, a)
		} else if artifactSpec.Digest == nil && artifactSpec.Algorithm != nil && a.Algorithm == strings.ToLower(*artifactSpec.Algorithm) {
			artifacts = append(artifacts, a)
		} else if artifactSpec.Digest != nil && artifactSpec.Algorithm != nil && a.Algorithm == strings.ToLower(*artifactSpec.Algorithm) && a.Digest == strings.ToLower(*artifactSpec.Digest) {
			artifacts = append(artifacts, a)
		}
	}
	return artifacts, nil
}

func (c *demoClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	var builders []*model.Builder
	for _, b := range c.builders {
		if builderSpec.URI == nil || b.URI == *builderSpec.URI {
			builders = append(builders, b)
		}
	}
	return builders, nil
}

func (c *demoClient) HashEquals(ctx context.Context, hashEqualSpec *model.HashEqualSpec) ([]*model.HashEqual, error) {
	var hashEquals []*model.HashEqual

	justificationMatchOrSkip := false
	collectorMatchOrSkip := false
	originMatchOrSkip := false
	for _, h := range c.hashEquals {
		if hashEqualSpec.Justification == nil || h.Justification == *hashEqualSpec.Justification {
			justificationMatchOrSkip = true
		}
		if hashEqualSpec.Collector == nil || h.Collector == *hashEqualSpec.Collector {
			collectorMatchOrSkip = true
		}
		if hashEqualSpec.Origin == nil || h.Origin == *hashEqualSpec.Origin {
			originMatchOrSkip = true
		}

		if justificationMatchOrSkip && collectorMatchOrSkip && originMatchOrSkip {
			if len(hashEqualSpec.Artifacts) > 0 && filterEqualArtifact(h.Artifacts, hashEqualSpec.Artifacts) {
				hashEquals = append(hashEquals, h)
			} else if len(hashEqualSpec.Artifacts) == 0 {
				hashEquals = append(hashEquals, h)
			}
		}
	}

	return hashEquals, nil

func (c *demoClient) IsOccurrences(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {{
	var isOccurrences []*model.IsOccurrence

	for _, h := range c.isOccurrence {
		if hashEqualSpec.Justification == nil || h.Justification == *hashEqualSpec.Justification {
			if hashEqualSpec.Collector == nil || h.Collector == *hashEqualSpec.Collector {
				if hashEqualSpec.Origin == nil || h.Origin == *hashEqualSpec.Origin {
					if len(hashEqualSpec.Artifacts) > 0 && filterEqualArtifact(h.Artifacts, hashEqualSpec.Artifacts) {
						hashEquals = append(hashEquals, h)
					} else if len(hashEqualSpec.Artifacts) == 0 {
						hashEquals = append(hashEquals, h)
					}
				}
			}
		}
	}
	return isOccurrences, nil
}

func filterEqualArtifact(storedArtifacts []*model.Artifact, queryArtifacts []*model.ArtifactSpec) bool {
	exists := make(map[model.Artifact]bool)
	for _, value := range storedArtifacts {
		exists[*value] = true
	}

	// enforce lowercase for both the algorithm and digest when querying
	for _, value := range queryArtifacts {
		queryArt := model.Artifact{
			Algorithm: strings.ToLower(*value.Algorithm),
			Digest:    strings.ToLower(*value.Digest),
		}
		if _, ok := exists[queryArt]; ok {
			return true
		}
	}
	return false
}

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

func filterSourceNamespace(src *model.Source, sourceSpec *model.SourceSpec) (*model.Source, error) {
	var namespaces []*model.SourceNamespace
	for _, ns := range src.Namespaces {
		if sourceSpec.Namespace == nil || ns.Namespace == *sourceSpec.Namespace {
			newNs, err := filterSourceName(ns, sourceSpec)
			if err != nil {
				return nil, err
			}
			if newNs != nil {
				namespaces = append(namespaces, newNs)
			}
		}
	}
	if len(namespaces) == 0 {
		return nil, nil
	}
	return &model.Source{
		Type:       src.Type,
		Namespaces: namespaces,
	}, nil
}

func filterSourceName(ns *model.SourceNamespace, sourceSpec *model.SourceSpec) (*model.SourceNamespace, error) {

	var names []*model.SourceName
	for _, n := range ns.Names {
		if sourceSpec.Name == nil || n.Name == *sourceSpec.Name {
			n, err := filterSourceQualifier(n, sourceSpec)
			if err != nil {
				return nil, err
			}
			if n != nil {
				names = append(names, n)
			}
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	return &model.SourceNamespace{
		Namespace: ns.Namespace,
		Names:     names,
	}, nil
}

func filterSourceQualifier(n *model.SourceName, sourceSpec *model.SourceSpec) (*model.SourceName, error) {
	if sourceSpec.Qualifier != nil {
		if sourceSpec.Qualifier.Commit != nil && sourceSpec.Qualifier.Tag != nil {
			return nil, gqlerror.Errorf("can only pass in commit or tag")
		}
		if sourceSpec.Qualifier.Commit == nil && sourceSpec.Qualifier.Tag == nil {
			if n.Tag == nil && n.Commit == nil {
				return n, nil
			}
		} else if sourceSpec.Qualifier.Commit != nil && n.Commit != nil {
			if *n.Commit == *sourceSpec.Qualifier.Commit {
				return n, nil
			}
		} else if sourceSpec.Qualifier.Tag != nil && n.Tag != nil {
			if *n.Tag == *sourceSpec.Qualifier.Tag {
				return n, nil
			}
		}
		return nil, nil
	}
	return n, nil
}

func filterCVEID(cve *model.Cve, cveSpec *model.CVESpec) (*model.Cve, error) {
	var cveID []*model.CVEId
	for _, id := range cve.CveID {
		if cveSpec.CveID == nil || id.ID == *cveSpec.CveID {
			cveID = append(cveID, id)
		}
	}
	if len(cveID) == 0 {
		return nil, nil
	}
	return &model.Cve{
		Year:  cve.Year,
		CveID: cveID,
	}, nil
}

func filterGHSAID(ghsa *model.Ghsa, ghsaSpec *model.GHSASpec) (*model.Ghsa, error) {
	var ghsaID []*model.GHSAId
	for _, id := range ghsa.GhsaID {
		if ghsaSpec.GhsaID == nil || id.ID == *ghsaSpec.GhsaID {
			ghsaID = append(ghsaID, id)
		}
	}
	if len(ghsaID) == 0 {
		return nil, nil
	}
	return &model.Ghsa{
		GhsaID: ghsaID,
	}, nil
}

func filterOSVID(ghsa *model.Osv, osvSpec *model.OSVSpec) (*model.Osv, error) {
	var osvID []*model.OSVId
	for _, id := range ghsa.OsvID {
		if osvSpec.OsvID == nil || id.ID == *osvSpec.OsvID {
			osvID = append(osvID, id)
		}
	}
	if len(osvID) == 0 {
		return nil, nil
	}
	return &model.Osv{
		OsvID: osvID,
	}, nil
}
