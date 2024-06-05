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
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/certifier"
)

const guacType string = "guac"

// PackageNode represents package node along with the its corresponding artifact digest
type PackageNode struct {
	// Purl is the package url of the package
	Purl string
}

type packageQuery struct {
	client            graphql.Client
	daysSinceLastScan int
}

var getPackages func(ctx context.Context, client graphql.Client, filter generated.PkgSpec, after *string, first *int) (*generated.PackagesListResponse, error)
var getNeighbors func(ctx context.Context, client graphql.Client, node string, usingOnly []generated.Edge) (*generated.NeighborsResponse, error)

// NewPackageQuery initializes the packageQuery to query from the graph database
func NewPackageQuery(client graphql.Client, daysSinceLastScan int) certifier.QueryComponents {
	getPackages = generated.PackagesList
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

	tickInterval := 5 * time.Second

	// nodeChan to receive components
	nodeChan := make(chan *PackageNode, 1)
	// errChan to receive error from collectors
	errChan := make(chan error, 1)

	defer close(nodeChan)
	defer close(errChan)

	go func() {
		errChan <- p.getPackageNodes(ctx, nodeChan)
	}()

	packNodes := []*PackageNode{}
	componentsCaptured := false
	ticker := time.NewTicker(tickInterval)
	for !componentsCaptured {
		select {
		case <-ticker.C:
			if len(packNodes) > 0 {
				compChan <- packNodes
				packNodes = []*PackageNode{}
			}
			ticker.Reset(tickInterval)
		case d := <-nodeChan:
			if len(packNodes) < 999 {
				packNodes = append(packNodes, d)
			} else {
				packNodes = append(packNodes, d)
				compChan <- packNodes
				packNodes = []*PackageNode{}
				ticker.Reset(tickInterval)
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
		if len(packNodes) < 999 {
			packNodes = append(packNodes, d)
		} else {
			packNodes = append(packNodes, d)
			compChan <- packNodes
			packNodes = []*PackageNode{}
		}
	}

	if len(packNodes) > 0 {
		compChan <- packNodes
	}

	return nil
}

func (p *packageQuery) getPackageNodes(ctx context.Context, nodeChan chan<- *PackageNode) error {
	var afterCursor *string
	first := 60000
	for {
		pkgConn, err := getPackages(ctx, p.client, generated.PkgSpec{}, afterCursor, &first)
		if err != nil {
			return fmt.Errorf("failed to query packages with error: %w", err)
		}
		if pkgConn == nil || pkgConn.PackagesList == nil {
			continue
		}
		pkgEdges := pkgConn.PackagesList.Edges

		for _, pkgNode := range pkgEdges {
			if pkgNode.Node.Type == guacType {
				continue
			}
			for _, namespace := range pkgNode.Node.Namespaces {
				for _, name := range namespace.Names {
					for _, version := range name.Versions {
						response, err := getNeighbors(ctx, p.client, version.Id, []generated.Edge{generated.EdgePackageCertifyVuln})
						if err != nil {
							return fmt.Errorf("failed neighbors query: %w", err)
						}
						vulnList := []*generated.NeighborsNeighborsCertifyVuln{}
						certifyVulnFound := false
						for _, neighbor := range response.Neighbors {
							if certifyVuln, ok := neighbor.(*generated.NeighborsNeighborsCertifyVuln); ok {
								vulnList = append(vulnList, certifyVuln)
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
							packNode := PackageNode{
								Purl: version.Purl,
							}
							nodeChan <- &packNode
						}
					}
				}
			}
		}
		if !pkgConn.PackagesList.PageInfo.HasNextPage {
			break
		}
		afterCursor = pkgConn.PackagesList.PageInfo.EndCursor
	}
	return nil
}
