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
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func init() {
	backends.Register("inmem", getBackend)
}

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

var errNotFound = errors.New("not found")

// Scorecard scores are in range of 1-10, so a single step at 100 should be
// plenty big
var epsilon = math.Nextafter(100, 100.1) - 100

// atomic add to ensure ID is not duplicated
func (c *demoClient) getNextID() uint32 {
	return atomic.AddUint32(&c.id, 1)
}

type demoClient struct {
	id    uint32
	m     sync.RWMutex
	index indexType

	artifacts       artMap
	builders        builderMap
	licenses        licMap
	packages        pkgTypeMap
	sources         srcTypeMap
	vulnerabilities vulnTypeMap

	certifyBads            badList
	certifyGoods           goodList
	certifyLegals          certifyLegalList
	certifyVulnerabilities certifyVulnerabilityList
	hasMetadatas           hasMetadataList
	hasSBOMs               hasSBOMList
	hasSLSAs               hasSLSAList
	hasSources             hasSrcList
	hashEquals             hashEqualList
	isDependencies         isDependencyList
	occurrences            isOccurrenceList
	pkgEquals              pkgEqualList
	pointOfContacts        pointOfContactList
	scorecards             scorecardList
	vexs                   vexList
	vulnerabilityEquals    vulnerabilityEqualList
	vulnerabilityMetadatas vulnerabilityMetadataList
}

func getBackend(_ context.Context, _ backends.BackendArgs) (backends.Backend, error) {
	client := &demoClient{
		artifacts:       artMap{},
		builders:        builderMap{},
		index:           indexType{},
		licenses:        licMap{},
		packages:        pkgTypeMap{},
		sources:         srcTypeMap{},
		vulnerabilities: vulnTypeMap{},
	}

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

func parseIDs(ids []string) ([]uint32, error) {
	keys := make([]uint32, 0, len(ids))
	for _, id := range ids {
		if key, err := parseID(id); err != nil {
			return nil, err
		} else {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func parseID(id string) (uint32, error) {
	id64, err := strconv.ParseUint(id, 10, 32)
	return uint32(id64), err
}

func sortAndRemoveDups(ids []uint32) []uint32 {
	numIDs := len(ids)
	if numIDs > 1 {
		slices.Sort(ids)
		nextIndex := 1
		for index := 1; index < numIDs; index++ {
			currentVal := ids[index]
			if ids[index-1] != currentVal {
				ids[nextIndex] = currentVal
				nextIndex++
			}
		}
		ids = ids[:nextIndex]
	}
	return ids
}

func (c *demoClient) getPackageVersionAndArtifacts(pkgOrArt []uint32) (pkgs []uint32, arts []uint32, err error) {
	for _, id := range pkgOrArt {
		switch entry := c.index[id].(type) {
		case *pkgVersionNode:
			pkgs = append(pkgs, entry.id)
		case *artStruct:
			arts = append(arts, entry.id)
		default:
			return nil, nil, fmt.Errorf("unexpected type in package or artifact list: %s", reflect.TypeOf(entry))
		}
	}

	return
}

// IDs should be sorted
func (c *demoClient) isIDPresent(id string, linkIDs []uint32) bool {
	linkID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return false
	}
	_, found := slices.BinarySearch[[]uint32](linkIDs, uint32(linkID))
	return found
}
