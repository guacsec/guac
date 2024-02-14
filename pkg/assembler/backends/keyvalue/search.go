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
	"fmt"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"strings"
)

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
		res = append(res, *p)
	}

	sourcesWithSearchText, err := c.searchSources(ctx, searchText)
	if err != nil {
		return nil, fmt.Errorf("error searching sources, %v", err)
	}

	for _, s := range sourcesWithSearchText {
		res = append(res, *s)
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
