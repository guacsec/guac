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
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier"
)

// PackageNode represents package node along with the its corresponding artifact digest
type PackageNode struct {
	// Purl is the package url of the package
	Purl string
	// Algorithm is the hash algorithm used
	Algorithm string
	// Digest represents the hash of the package occurrence
	Digest string
}

type packageQuery struct {
	client            graphql.Client
	daysSinceLastScan int
}

var getPackages func(ctx context.Context, client graphql.Client, filter *generated.PkgSpec) (*generated.PackagesResponse, error)
var getNeighbors func(ctx context.Context, client graphql.Client, node string) (*generated.NeighborsResponse, error)

// NewPackageQuery initializes the packageQuery to query from the graph database
func NewPackageQuery(client graphql.Client, daysSinceLastScan int) certifier.QueryComponents {
	getPackages = generated.Packages
	getNeighbors = generated.Neighbors
	return &packageQuery{
		client:            client,
		daysSinceLastScan: daysSinceLastScan,
	}
}

// GetComponents get all the packages that do not have a certify vulnerability attached or last scanned is more than daysSinceLastScan
func (p *packageQuery) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	if compChan == nil {
		return fmt.Errorf("compChan cannot be nil")
	}

	// nodeChan to receive components
	nodeChan := make(chan *PackageNode, 10000)
	// errChan to receive error from collectors
	errChan := make(chan error, 1)

	response, err := getPackages(ctx, p.client, nil)
	if err != nil {
		return fmt.Errorf("failed sources query: %w", err)
	}

	go func() {
		errChan <- p.getPackageNodes(ctx, response, nodeChan)
	}()

	packNodes := []*PackageNode{}
	componentsCaptured := false
	timeout := time.After(5 * time.Second)
	for !componentsCaptured {
		select {
		case <-timeout:
			if len(packNodes) > 0 {
				compChan <- packNodes
				packNodes = []*PackageNode{}
			}
			timeout = time.After(5 * time.Second)
		case d := <-nodeChan:
			if len(packNodes) < 1000 {
				packNodes = append(packNodes, d)
			} else {
				compChan <- packNodes
				packNodes = []*PackageNode{}
				timeout = time.After(5 * time.Second)
			}
		case err := <-errChan:
			if err != nil {
				return err
			}
			componentsCaptured = true
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	for len(nodeChan) > 0 {
		d := <-nodeChan
		if len(packNodes) < 1000 {
			packNodes = append(packNodes, d)
		} else {
			compChan <- packNodes
			packNodes = []*PackageNode{}
		}
	}

	if len(packNodes) > 0 {
		compChan <- packNodes
	}

	return nil
}

func (p *packageQuery) getPackageNodes(ctx context.Context, response *generated.PackagesResponse, nodeChan chan<- *PackageNode) error {
	packages := response.GetPackages()
	for _, pkgType := range packages {
		for _, namespace := range pkgType.Namespaces {
			for _, name := range namespace.Names {
				for _, version := range name.Versions {
					response, err := getNeighbors(ctx, p.client, version.Id)
					if err != nil {
						return fmt.Errorf("failed neighbors query: %w", err)
					}
					vulnList := []*generated.NeighborsNeighborsCertifyVuln{}
					occurrenceList := []*generated.NeighborsNeighborsIsOccurrence{}
					certifyVulnFound := false
					for _, neighbor := range response.Neighbors {
						if certifyVuln, ok := neighbor.(*generated.NeighborsNeighborsCertifyVuln); ok {
							vulnList = append(vulnList, certifyVuln)
						} else if occurrence, ok := neighbor.(*generated.NeighborsNeighborsIsOccurrence); ok {
							occurrenceList = append(occurrenceList, occurrence)
						}
					}
					// collect all certifyVulnerability and then check timestamp else if not checking timestamp,
					// if a certifyVulnerability is found break out
					for _, vulns := range vulnList {
						if p.daysSinceLastScan != 0 {
							now := time.Now()
							difference := vulns.Metadata.TimeScanned.Sub(now)
							if math.Abs(difference.Hours()) < float64(p.daysSinceLastScan*24) {
								certifyVulnFound = true
							}
						} else {
							certifyVulnFound = true
							break
						}
					}
					if !certifyVulnFound {
						qualifiersMap := map[string]string{}
						keys := []string{}
						for _, kv := range version.Qualifiers {
							qualifiersMap[kv.Key] = kv.Value
							keys = append(keys, kv.Key)
						}
						sort.Strings(keys)
						qualifiers := []string{}
						for _, k := range keys {
							qualifiers = append(qualifiers, k, qualifiersMap[k])
						}
						purl := helpers.PkgToPurl(pkgType.Type, namespace.Namespace, name.Name, version.Version, version.Subpath, qualifiers)
						if len(occurrenceList) == 0 {
							packNode := PackageNode{
								Purl:      purl,
								Algorithm: "",
								Digest:    "",
							}
							nodeChan <- &packNode
						} else {
							for _, occurrence := range occurrenceList {
								packNode := PackageNode{
									Purl:      purl,
									Algorithm: occurrence.Artifact.Algorithm,
									Digest:    occurrence.Artifact.Digest,
								}
								nodeChan <- &packNode
							}
						}
					}
				}
			}
		}
	}
	return nil
}
