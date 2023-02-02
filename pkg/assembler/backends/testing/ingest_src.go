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

package backend

import (
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllSources(client *demoClient) {
	// with tag
	client.registerSource("git", "github", "github.com/guacsec/guac", "tag=v0.0.1")
	// with commit
	client.registerSource("git", "github", "github.com/guacsec/guac", "commit=fcba958b73e27cad8b5c8655d46439984d27853b")
	// with no tag or commit
	client.registerSource("git", "github", "github.com/guacsec/guac", "")
	// gitlab namespace
	client.registerSource("git", "gitlab", "github.com/guacsec/guacdata", "tag=v0.0.1")
	// differnt type
	client.registerSource("svn", "gitlab", "github.com/guacsec/guac", "")
}

func (c *demoClient) registerSource(srcType, namespace, name, qualifier string) {
	for i, s := range c.sources {
		if s.Type == srcType {
			c.sources[i] = registerSourceNamespace(s, namespace, name, qualifier)
			return
		}
	}

	newSrc := &model.Source{Type: srcType}
	newSrc = registerSourceNamespace(newSrc, namespace, name, qualifier)
	c.sources = append(c.sources, newSrc)
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
			if n.Tag == &pair[1] {
				return true
			}
		} else {
			if n.Commit == &pair[1] {
				return true
			}
		}
	}
	return false
}
