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
	client graphql.Client
	// set the batch size for the package pagination query
	batchSize int
	// add artificial latency to throttle the pagination query
	addedLatency *time.Duration
}

var getPackages func(ctx context.Context, client graphql.Client, filter generated.PkgSpec, after *string, first *int) (*generated.PackagesListResponse, error)

// NewPackageQuery initializes the packageQuery to query from the graph database
func NewPackageQuery(client graphql.Client, batchSize int, addedLatency *time.Duration) certifier.QueryComponents {
	getPackages = generated.PackagesList
	return &packageQuery{
		client:       client,
		batchSize:    batchSize,
		addedLatency: addedLatency,
	}
}

// GetComponents get all the packages
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

	first := p.batchSize
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
						packNode := PackageNode{
							Purl: version.Purl,
						}
						nodeChan <- &packNode
					}
				}
			}
		}
		if !pkgConn.PackagesList.PageInfo.HasNextPage {
			break
		}
		afterCursor = pkgConn.PackagesList.PageInfo.EndCursor
		// add artificial latency to throttle the pagination query
		if p.addedLatency != nil {
			time.Sleep(*p.addedLatency)
		}
	}
	return nil
}
