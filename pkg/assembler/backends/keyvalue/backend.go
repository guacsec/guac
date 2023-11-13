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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/guacsec/guac/pkg/assembler/kv/redis"
)

func init() {
	backends.Register("keyvalue", getBackend)
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
	ID() string

	// Neighbors allows retrieving neighbors of a node using the backlinks.
	//
	// This is useful for path related queries where the type of the node
	// is not as relevant as its connections.
	//
	// The allowedEdges argument allows filtering the set of neighbors to
	// only include certain GUAC verbs.
	Neighbors(allowedEdges edgeMap) []string

	// BuildModelNode builds a GraphQL return type for a backend node,
	BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error)
}

type indexType map[string]node

var errNotFound = errors.New("not found")

// Scorecard scores are in range of 1-10, so a single step at 100 should be
// plenty big
var epsilon = math.Nextafter(100, 100.1) - 100

const (
	indexCol = "index"
	artCol   = "artifacts"
	occCol   = "isOccurrences"
)

// atomic add to ensure ID is not duplicated
func (c *demoClient) getNextID() string {
	atomic.AddUint32(&c.id, 1)
	return fmt.Sprintf("%d", c.id)
}

type demoClient struct {
	id    uint32
	m     sync.RWMutex
	kv    kv.Store
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
	return &demoClient{
		kv: &redis.Store{},
		//kv:              &memmap.Store{},
		artifacts:       artMap{},
		builders:        builderMap{},
		index:           indexType{},
		licenses:        licMap{},
		packages:        pkgTypeMap{},
		sources:         srcTypeMap{},
		vulnerabilities: vulnTypeMap{},
	}, nil
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

func byID[E node](id string, c *demoClient) (E, error) {
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

func byIDkv[E node](ctx context.Context, id string, coll string, c *demoClient) (E, error) {
	var nl E
	k, err := c.kv.Get(ctx, indexCol, id)
	if err != nil {
		return nl, err
	}
	strval, err := c.kv.Get(ctx, coll, k)
	if err != nil {
		return nl, err
	}
	err = json.Unmarshal(([]byte)(strval), &nl)
	return nl, err
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
