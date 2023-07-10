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

package inmem

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type DemoCredentials struct{}

// node is the common interface of all backend nodes.
type node interface {
	// ID provides global IDs for all nodes that can be referenced from
	// other places in GUAC.
	//
	// Since we always ingest data and never remove,
	// we can keep this global and increment it as needed.
	//
	// For fast retrieval, we also keep a map from ID from nodes that have
	// it.
	//
	// IDs are stored as string in graphql even though we ask for integers
	// See https://github.com/99designs/gqlgen/issues/2561
	ID() uint32

	// Neighbors allows retrieving neighbors of a node using the backlinks.
	//
	// This is useful for path related queries where the type of the node
	// is not as relevant as its connections.
	//
	// The allowedEdges argument allows filtering the set of neighbors to
	// only include certain GUAC verbs.
	Neighbors(allowedEdges edgeMap) []uint32

	// BuildModelNode builds a GraphQL return type for a backend node,
	BuildModelNode(c *demoClient) (model.Node, error)
}

type indexType map[uint32]node

var errNotFound = errors.New("Not found")

// Scorecard scores are in range of 1-10, so a single step at 100 should be
// plenty big
var epsilon = math.Nextafter(100, 100.1) - 100

// atomic add to ensure ID is not duplicated
func (c *demoClient) getNextID() uint32 {
	return atomic.AddUint32(&c.id, 1)
}

type demoClient struct {
	id uint32
	m  sync.RWMutex

	artifacts            artMap
	builders             builderMap
	certifyBads          badList
	certifyGoods         goodList
	pkgEquals            pkgEqualList
	cves                 cveMap
	equalVulnerabilities equalVulnerabilityList
	ghsas                ghsaMap
	hasMetadatas         hasMetadataList
	pointOfContacts      pointOfContactList
	hasSBOMs             hasSBOMList
	hasSLSAs             hasSLSAList
	hasSources           hasSrcList
	hashEquals           hashEqualList
	index                indexType
	isDependencies       isDependencyList
	occurrences          isOccurrenceList
	osvs                 osvMap
	packages             pkgTypeMap
	scorecards           scorecardList
	sources              srcTypeMap
	vexs                 vexList
	vulnerabilities      vulnerabilityList

	// Ensures that only one noKnownVuln node is created
	noKnownVulnNode noKnownVuln
}

// This node is a singleton!
type noKnownVuln struct {
	id               uint32
	certifyVulnLinks []uint32
}

func (n *noKnownVuln) ID() uint32 { return n.id }

func (n *noKnownVuln) Neighbors(allowedEdges edgeMap) []uint32 {
	if allowedEdges[model.EdgeNoVulnCertifyVuln] {
		return n.certifyVulnLinks
	}
	return []uint32{}
}

func (n *noKnownVuln) BuildModelNode(c *demoClient) (model.Node, error) {
	return &model.NoVuln{ID: nodeID(n.id)}, nil
}

func (n *noKnownVuln) setVulnerabilityLinks(id uint32) {
	n.certifyVulnLinks = append(n.certifyVulnLinks, id)
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	client := &demoClient{
		artifacts:            artMap{},
		builders:             builderMap{},
		certifyBads:          badList{},
		certifyGoods:         goodList{},
		pkgEquals:            pkgEqualList{},
		cves:                 cveMap{},
		equalVulnerabilities: equalVulnerabilityList{},
		ghsas:                ghsaMap{},
		hasSBOMs:             hasSBOMList{},
		hasSLSAs:             hasSLSAList{},
		hasSources:           hasSrcList{},
		hashEquals:           hashEqualList{},
		index:                indexType{},
		isDependencies:       isDependencyList{},
		occurrences:          isOccurrenceList{},
		osvs:                 osvMap{},
		packages:             pkgTypeMap{},
		scorecards:           scorecardList{},
		sources:              srcTypeMap{},
		vexs:                 vexList{},
		vulnerabilities:      vulnerabilityList{},
		noKnownVulnNode:      noKnownVuln{},
	}

	// Build the special noKnownVuln node and link it everywhere
	client.noKnownVulnNode.id = client.getNextID()
	client.index[client.noKnownVulnNode.id] = &client.noKnownVulnNode

	return client, nil
}

func nodeID(id uint32) string {
	return fmt.Sprintf("%d", id)
}

func noMatch(filter *string, value string) bool {
	if filter != nil {
		return value != *filter
	}
	return false
}

func noMatchInput(filter *string, value string) bool {
	if filter != nil {
		return value != *filter
	}
	return value != ""
}

func nilToEmpty(input *string) string {
	if input == nil {
		return ""
	}
	return *input
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a != nil && b != nil {
		return a.Equal(*b)
	}
	return false
}

func toLower(filter *string) *string {
	if filter != nil {
		lower := strings.ToLower(*filter)
		return &lower
	}
	return nil
}

func noMatchFloat(filter *float64, value float64) bool {
	if filter != nil {
		return math.Abs(*filter-value) > epsilon
	}
	return false
}

func floatEqual(x float64, y float64) bool {
	return math.Abs(x-y) < epsilon
}

func byID[E node](id uint32, c *demoClient) (E, error) {
	var nl E
	o, ok := c.index[id]
	if !ok {
		return nl, fmt.Errorf("%w : id not in index", errNotFound)
	}
	s, ok := o.(E)
	if !ok {
		return nl, fmt.Errorf("%w : node not a %T", errNotFound, nl)
	}
	return s, nil
}

func lock(m *sync.RWMutex, readOnly bool) {
	if readOnly {
		m.RLock()
	} else {
		m.Lock()
	}
}

func unlock(m *sync.RWMutex, readOnly bool) {
	if readOnly {
		m.RUnlock()
	} else {
		m.Unlock()
	}
}

func (c *demoClient) buildNoVulnResponse() (*model.NoVuln, error) {
	if c.noKnownVulnNode.id == 0 {
		return nil, fmt.Errorf("noKnownVulnNode has not been initialized")
	}
	return &model.NoVuln{
		ID: nodeID(c.noKnownVulnNode.id),
	}, nil
}
