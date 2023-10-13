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
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/guacsec/guac/pkg/assembler/kv/memmap"
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

	Key() string
}

//type indexType map[string]node

var errNotFound = errors.New("not found")
var errTypeNotMatch = errors.New("Stored type does not match")

// Scorecard scores are in range of 1-10, so a single step at 100 should be
// plenty big
var epsilon = math.Nextafter(100, 100.1) - 100

const (
	// Collection names must not have ":" in them
	indexCol    = "index"
	artCol      = "artifacts"
	occCol      = "isOccurrences"
	pkgTypeCol  = "pkgTypes"
	pkgNSCol    = "pkgNamespaces"
	pkgNameCol  = "pkgNames"
	pkgVerCol   = "pkgVersions"
	isDepCol    = "isDependencies"
	hasMDCol    = "hasMetadatas"
	hasSBOMCol  = "hasSBOMs"
	srcTypeCol  = "srcTypes"
	srcNSCol    = "srcNamespaces"
	srcNameCol  = "srcNames"
	cgCol       = "certifyGoods"
	cbCol       = "certifyBads"
	builderCol  = "builders"
	licenseCol  = "licenses"
	clCol       = "certifyLegals"
	cscCol      = "certifyScorecards"
	slsaCol     = "hasSLSAs"
	hsaCol      = "hasSourceAts"
	hashEqCol   = "hashEquals"
	pkgEqCol    = "pkgEquals"
	pocCol      = "pointOfContacts"
	vulnTypeCol = "vulnTypes"
	vulnIDCol   = "vulnIDs"
	vulnEqCol   = "vulnEquals"
	vulnMDCol   = "vulnMetadatas"
	cVEXCol     = "certifyVEXs"
	cVulnCol    = "certifyVulns"
)

func typeColMap(col string) node {
	switch col {
	case artCol:
		return &artStruct{}
	case occCol:
		return &isOccurrenceStruct{}
	case pkgTypeCol:
		return &pkgType{}
	case pkgNSCol:
		return &pkgNamespace{}
	case pkgNameCol:
		return &pkgName{}
	case pkgVerCol:
		return &pkgVersion{}
	case isDepCol:
		return &isDependencyLink{}
	case hasMDCol:
		return &hasMetadataLink{}
	case hasSBOMCol:
		return &hasSBOMStruct{}
	case srcTypeCol:
		return &srcType{}
	case srcNSCol:
		return &srcNamespace{}
	case srcNameCol:
		return &srcNameNode{}
	case cgCol:
		return &goodLink{}
	case cbCol:
		return &badLink{}
	case builderCol:
		return &builderStruct{}
	case licenseCol:
		return &licStruct{}
	case clCol:
		return &certifyLegalStruct{}
	case cscCol:
		return &scorecardLink{}
	case slsaCol:
		return &hasSLSAStruct{}
	case hsaCol:
		return &srcMapLink{}
	case hashEqCol:
		return &hashEqualStruct{}
	case pkgEqCol:
		return &pkgEqualStruct{}
	case pocCol:
		return &pointOfContactLink{}
	case vulnTypeCol:
		return &vulnTypeStruct{}
	case vulnIDCol:
		return &vulnIDNode{}
	case vulnEqCol:
		return &vulnerabilityEqualLink{}
	case vulnMDCol:
		return &vulnerabilityMetadataLink{}
	case cVEXCol:
		return &vexLink{}
	case cVulnCol:
		return &certifyVulnerabilityLink{}
	}
	//?
	return &artStruct{}
}

// atomic add to ensure ID is not duplicated
func (c *demoClient) getNextID() string {
	atomic.AddUint32(&c.id, 1)
	return fmt.Sprintf("%d", c.id)
}

type demoClient struct {
	id uint32
	m  sync.RWMutex
	kv kv.Store
}

func getBackend(ctx context.Context, opts backends.BackendArgs) (backends.Backend, error) {

	store, ok := opts.(kv.Store)
	if !ok {
		store = memmap.GetStore()
	}
	//kv, err := tikv.GetStore(ctx)
	// kv, err := memmap.GetStore()
	// if err != nil {
	// 	return nil, err
	// }
	return &demoClient{
		//kv: &redis.Store{},
		kv: store,
		//kv:              kv,
	}, nil
}

func noMatch(filter *string, value string) bool {
	if filter != nil {
		return value != *filter
	}
	return false
}

// func noMatchInput(filter *string, value string) bool {
// 	if filter != nil {
// 		return value != *filter
// 	}
// 	return value != ""
// }

func nilToEmpty(input *string) string {
	if input == nil {
		return ""
	}
	return *input
}

// func timePtrEqual(a, b *time.Time) bool {
// 	if a == nil && b == nil {
// 		return true
// 	}
// 	if a != nil && b != nil {
// 		return a.Equal(*b)
// 	}
// 	return false
// }

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

// func floatEqual(x float64, y float64) bool {
// 	return math.Abs(x-y) < epsilon
// }

// delete this
// func byID[E node](id string, c *demoClient) (E, error) {
// 	var nl E
// 	o, ok := c.index[id]
// 	if !ok {
// 		return nl, fmt.Errorf("%w : id not in index", errNotFound)
// 	}
// 	s, ok := o.(E)
// 	if !ok {
// 		return nl, fmt.Errorf("%w : node not a %T", errNotFound, nl)
// 	}
// 	return s, nil
// }

func byIDkv[E node](ctx context.Context, id string, c *demoClient) (E, error) {
	var nl E
	var k string
	if err := c.kv.Get(ctx, indexCol, id, &k); err != nil {
		return nl, fmt.Errorf("%w : id not found in index %q", err, id)
	}
	sub := strings.SplitN(k, ":", 2)
	if len(sub) != 2 {
		return nl, fmt.Errorf("Bad value was stored in index map: %v", k)
	}
	return byKeykv[E](ctx, sub[0], sub[1], c)
}

func byKeykv[E node](ctx context.Context, coll string, k string, c *demoClient) (E, error) {
	var nl E
	if err := validateType(nl, coll); err != nil {
		return nl, err
	}
	err := c.kv.Get(ctx, coll, k, &nl)
	return nl, err
}

func setkv(ctx context.Context, coll string, n node, c *demoClient) error {
	// validate type?
	return c.kv.Set(ctx, coll, n.Key(), n)
}

func (c *demoClient) addToIndex(ctx context.Context, coll string, n node) error {
	if err := validateType(n, coll); err != nil {
		return err
	}
	val := strings.Join([]string{coll, n.Key()}, ":")
	return c.kv.Set(ctx, indexCol, n.ID(), val)
}

func validateType[E node](n E, c string) error {
	if reflect.TypeOf(typeColMap(c)) == reflect.TypeOf(n) {
		return nil
	}
	return fmt.Errorf("%w : found: %q want: %q", errTypeNotMatch,
		reflect.TypeOf(typeColMap(c)), reflect.TypeOf(n))
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

func timeKey(t time.Time) string {
	return fmt.Sprint(t.Unix())
}
