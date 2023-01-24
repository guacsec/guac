//
// Copyright 2022 The GUAC Authors.
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

package root_package

import (
	"context"
	"errors"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
)

// PackageComponent represents the top level package node and its dependencies
type PackageComponent struct {
	Package     assembler.PackageNode
	DepPackages []*PackageComponent
}

type packageQuery struct {
	client graphdb.Client
}

// NewPackageQuery initializes the packageQuery to query from the graph database
func NewPackageQuery(client graphdb.Client) certifier.QueryComponents {
	return &packageQuery{
		client: client,
	}
}

// GetComponents runs as a goroutine to query for root level and dependent packages to scan and passes them
// to the compChan as they are found. The interface will be type "*Component"
func (q *packageQuery) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	// Get top level package MATCH (p:Package) WHERE NOT (p)<-[:DependsOn]-() return p
	// Get all packages that the top level package depends on MATCH (p:Package) WHERE NOT (p)<-[:DependsOn]-() WITH p MATCH (p)-[:DependsOn]->(p2:Package) return p2
	// MATCH (p:Package) WHERE p.purl = "pkg:oci/vul-image-latest?repository_url=ppatel1989" WITH p MATCH (p)-[:DependsOn]->(p2:Package) return p2

	roots, err := graphdb.ReadQuery(q.client, "MATCH (p:Package) WHERE NOT (p)<-[:DependsOn]-() return p", nil)
	if err != nil {
		return err
	}
	for _, result := range roots {
		foundNode, ok := result.(dbtype.Node)
		if !ok {
			return errors.New("failed to cast to node type")
		}
		rootPackage := assembler.PackageNode{}
		rootPackage.Purl, ok = foundNode.Props["purl"].(string)
		if !ok {
			return errors.New("failed to cast purl property to string type")
		}
		deps, err := getCompHelper(ctx, q.client, rootPackage.Purl)
		if err != nil {
			return err
		}
		rootComponent := &PackageComponent{
			Package:     rootPackage,
			DepPackages: deps,
		}
		compChan <- rootComponent
	}
	return nil
}

func getCompHelper(ctx context.Context, client graphdb.Client, parentPurl string) ([]*PackageComponent, error) {
	dependencies, err := graphdb.ReadQuery(client, "MATCH (p:Package) WHERE p.purl = $rootPurl WITH p MATCH (p)-[:DependsOn]->(p2:Package) return p2",
		map[string]any{"rootPurl": parentPurl})
	if err != nil {
		return nil, err
	}
	depPackages := []*PackageComponent{}
	for _, dep := range dependencies {
		foundDep, ok := dep.(dbtype.Node)
		if !ok {
			return nil, errors.New("failed to cast to node type")
		}
		foundDepPack := assembler.PackageNode{}
		foundDepPack.Purl, ok = foundDep.Props["purl"].(string)
		if !ok {
			return nil, errors.New("failed to cast purl property to string type")
		}
		deps, err := getCompHelper(ctx, client, foundDepPack.Purl)
		if err != nil {
			return nil, err
		}
		depPackages = append(depPackages, &PackageComponent{
			Package:     foundDepPack,
			DepPackages: deps,
		})
	}
	return depPackages, nil
}
