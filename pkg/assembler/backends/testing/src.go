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
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// func registerAllSources(client *demoClient) {
// 	// with tag
// 	client.registerSource("git", "github", "github.com/guacsec/guac", "tag=v0.0.1")
// 	// with commit
// 	client.registerSource("git", "github", "github.com/guacsec/guac", "commit=fcba958b73e27cad8b5c8655d46439984d27853b")
// 	// with no tag or commit
// 	client.registerSource("git", "github", "github.com/guacsec/guac", "")
// 	// gitlab namespace
// 	client.registerSource("git", "gitlab", "github.com/guacsec/guacdata", "tag=v0.0.1")
// 	// differnt type
// 	client.registerSource("svn", "gitlab", "github.com/guacsec/guac", "")
// 	// "git", "github", "https://github.com/django/django", "tag=1.11.1"
// 	client.registerSource("git", "github", "https://github.com/django/django", "tag=1.11.1")
// 	// "git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5"
// 	client.registerSource("git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5")
// }

// // Ingest Source

func (c *demoClient) registerSource(srcType, namespace, name, qualifier string) *model.Source {
	for i, s := range c.sources {
		if s.Type == srcType {
			c.sources[i] = registerSourceNamespace(s, namespace, name, qualifier)
			return c.sources[i]
		}
	}

	newSrc := &model.Source{Type: srcType}
	newSrc = registerSourceNamespace(newSrc, namespace, name, qualifier)
	c.sources = append(c.sources, newSrc)

	return newSrc
}

func registerSourceNamespace(s *model.Source, namespace, name, qualifier string) *model.Source {
	for i, ns := range s.Namespaces {
		if ns.Namespace == namespace {
			s.Namespaces[i] = registerSourceName(ns, name, qualifier)
			return s
		}
	}

	newNs := &model.SourceNamespace{Namespace: namespace}
	newNs = registerSourceName(newNs, name, qualifier)
	s.Namespaces = append(s.Namespaces, newNs)
	return s
}

func registerSourceName(ns *model.SourceNamespace, name, qualifier string) *model.SourceNamespace {
	for _, n := range ns.Names {
		if n.Name == name {
			if checkQualifier(n, qualifier) {
				return ns
			}
		}
	}
	newN := &model.SourceName{Name: name}
	newN = sortQualifier(newN, qualifier)
	ns.Names = append(ns.Names, newN)
	return ns
}

func sortQualifier(n *model.SourceName, qualifier string) *model.SourceName {
	if qualifier != "" {
		pair := strings.Split(qualifier, "=")
		if pair[0] == "tag" {
			n.Tag = &pair[1]
		} else {
			n.Commit = &pair[1]
		}
	}
	return n
}

func checkQualifier(n *model.SourceName, qualifier string) bool {
	if qualifier != "" {
		pair := strings.Split(qualifier, "=")
		if pair[0] == "tag" {
			if n.Tag != nil {
				return *n.Tag == pair[1]
			}
		} else {
			if n.Commit != nil {
				return *n.Commit == pair[1]
			}
		}
	}
	return false
}

// // Query Source

// func (c *demoClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
// 	var sources []*model.Source
// 	for _, s := range c.sources {
// 		if sourceSpec.Type == nil || s.Type == *sourceSpec.Type {
// 			newSource, err := filterSourceNamespace(s, sourceSpec)
// 			if err != nil {
// 				return nil, err
// 			}
// 			if newSource != nil {
// 				sources = append(sources, newSource)
// 			}
// 		}
// 	}
// 	return sources, nil
// }

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
			n, err := filterSourceTagCommit(n, sourceSpec)
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

func filterSourceTagCommit(n *model.SourceName, sourceSpec *model.SourceSpec) (*model.SourceName, error) {
	if sourceSpec.Commit != nil && sourceSpec.Tag != nil {
		if *sourceSpec.Commit != "" && *sourceSpec.Tag != "" {
			return nil, gqlerror.Errorf("Passing both commit and tag selectors is an error")
		}
	}

	if !matchInputSpecWithDBField(sourceSpec.Commit, n.Commit) {
		return nil, nil
	}

	if !matchInputSpecWithDBField(sourceSpec.Tag, n.Tag) {
		return nil, nil
	}

	return n, nil
}

// TODO(mihaimaruseac): Probably move to utility
// Matches a field in the database with a spec, considering that null argument
// means anything is ok whereas empty string means matching only with empty
// (null/empty). That is:
// - if spec is nil: match anything
// - if spec is empty: match nil or empty
// - otherwise: match exactly spec
func matchInputSpecWithDBField(spec *string, dbField *string) bool {
	if spec == nil {
		return true
	}

	if *spec == "" {
		return (dbField == nil || *dbField == "")
	}

	return (dbField != nil && *dbField == *spec)
}

// func (c *demoClient) IngestSource(ctx context.Context, source *model.SourceInputSpec) (*model.Source, error) {
// 	sourceType := source.Type
// 	namespace := source.Namespace
// 	name := source.Name

// 	// TODO(mihaimaruseac): Separate in two fields, no need for `tag=`/`commit=`
// 	tagOrCommit := ""
// 	if source.Commit != nil && source.Tag != nil {
// 		if *source.Commit != "" && *source.Tag != "" {
// 			return nil, gqlerror.Errorf("Passing both commit and tag selectors is an error")
// 		} else if *source.Commit != "" {
// 			tagOrCommit = "commit=" + *source.Commit
// 		} else if *source.Tag != "" {
// 			tagOrCommit = "tag=" + *source.Tag
// 		}
// 	} else if source.Commit != nil {
// 		tagOrCommit = "commit=" + *source.Commit
// 	} else if source.Tag != nil {
// 		tagOrCommit = "tag=" + *source.Tag
// 	}

// 	newSrc := c.registerSource(sourceType, namespace, name, tagOrCommit)

// 	return newSrc, nil
// }

// Internal data: Sources
type srcTypeMap map[string]srcNamespaceMap
type srcNamespaceMap map[string]srcNameList
type srcNameList []*srcNameNode
type srcNameNode struct {
	name   string
	tag    *string
	commit *string
	pkg    *srcMapLink
}

// Internal data: link between sources and packages (HasSourceAt)
type srcMaps []*srcMapLink
type srcMapLink struct {
	justification string
	knownSince    time.Time
	origin        string
	collector     string
	source        *srcNameNode
	pkg           pkgNameOrVersion
}

var sources = srcTypeMap{}
var sourceMaps = srcMaps{}

func (c *demoClient) IngestSource(ctx context.Context, source *model.SourceInputSpec) (*model.Source, error) {
	namespaces, hasNamespace := sources[source.Type]
	names := namespaces[source.Namespace]
	newSource := srcNameNode{
		name: source.Name,
	}
	if source.Tag != nil {
		tag := *source.Tag
		newSource.tag = &tag
	}
	if source.Commit != nil {
		commit := *source.Commit
		newSource.commit = &commit
	}

	// Don't insert duplicates
	duplicate := false
	for _, src := range names {
		if src.name != source.Name {
			continue
		}
		if noMatchPtrInput(source.Tag, src.tag) {
			continue
		}
		if noMatchPtrInput(source.Commit, src.commit) {
			continue
		}
		duplicate = true
		break
	}
	if !duplicate {
		names = append(names, &newSource)
		if !hasNamespace {
			sources[source.Type] = srcNamespaceMap{}
		}
		sources[source.Type][source.Namespace] = names
	}

	// build return GraphQL type
	out := sourceFromInput(*source)
	return out, nil
}

func (c *demoClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	out := []*model.Source{}
	for dbType, namespaces := range sources {
		if noMatch(sourceSpec.Type, dbType) {
			continue
		}
		sNamespaces := []*model.SourceNamespace{}
		for namespace, names := range namespaces {
			if noMatch(sourceSpec.Namespace, namespace) {
				continue
			}
			sns := []*model.SourceName{}
			for _, s := range names {
				if noMatch(sourceSpec.Name, s.name) {
					continue
				}
				if noMatchPtr(sourceSpec.Tag, s.tag) {
					continue
				}
				if noMatchPtr(sourceSpec.Commit, s.commit) {
					continue
				}
				newSrc := model.SourceName{
					Name:   s.name,
					Tag:    s.tag,
					Commit: s.commit,
				}
				sns = append(sns, &newSrc)
			}
			sn := model.SourceNamespace{
				Namespace: namespace,
				Names:     sns,
			}
			sNamespaces = append(sNamespaces, &sn)
		}
		s := model.Source{
			Type:       dbType,
			Namespaces: sNamespaces,
		}
		out = append(out, &s)
	}
	return out, nil
}

func sourceFromInput(input model.SourceInputSpec) *model.Source {
	sn := model.SourceName{
		Name:   input.Name,
		Tag:    input.Tag,
		Commit: input.Commit,
	}
	sns := model.SourceNamespace{
		Namespace: input.Namespace,
		Names:     []*model.SourceName{&sn},
	}
	return &model.Source{
		Type:       input.Type,
		Namespaces: []*model.SourceNamespace{&sns},
	}
}

func sourceMatchingFilter(filter *model.SourceSpec, source *srcNameNode) *model.Source {
	var out *model.Source
	out = nil

	for dbType, namespaces := range sources {
		if filter != nil && noMatch(filter.Type, dbType) {
			continue
		}
		foundNamespace := false
		sNamespaces := []*model.SourceNamespace{}
		for namespace, names := range namespaces {
			if filter != nil && noMatch(filter.Namespace, namespace) {
				continue
			}
			foundName := false
			sns := []*model.SourceName{}
			for _, s := range names {
				if filter != nil && noMatch(filter.Name, s.name) {
					continue
				}
				if filter != nil && noMatchPtr(filter.Tag, s.tag) {
					continue
				}
				if filter != nil && noMatchPtr(filter.Commit, s.commit) {
					continue
				}
				if source != s {
					continue
				}
				newSrc := model.SourceName{
					Name:   s.name,
					Tag:    s.tag,
					Commit: s.commit,
				}
				sns = append(sns, &newSrc)
				foundName = true
			}
			if foundName {
				sn := model.SourceNamespace{
					Namespace: namespace,
					Names:     sns,
				}
				sNamespaces = append(sNamespaces, &sn)
				foundNamespace = true
			}
		}
		if foundNamespace {
			out = &model.Source{
				Type:       dbType,
				Namespaces: sNamespaces,
			}
		}
	}

	return out
}
