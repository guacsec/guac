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
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type DemoCredentials struct{}

// node is the common interface of all backend nodes.
type node interface {
	// getID provides global IDs for all nodes that can be referenced from
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
	getID() uint32

	// neighbors allows retrieving neighbors of a node using the backlinks.
	//
	// This is useful for path related queries where the type of the node
	// is not as relevant as its connections.
	neighbors() []uint32

	// buildModelNode builds a GraphQL return type for a backend node,
	buildModelNode(c *demoClient) (model.Node, error)
}

type indexType map[uint32]node

// atomic add to ensure ID is not duplicated
func (c *demoClient) getNextID() uint32 {
	return atomic.AddUint32(&c.id, 1)
}

type demoClient struct {
	hasSBOM              []*model.HasSbom
	certifyPkg           []*model.CertifyPkg
	certifyVuln          []*model.CertifyVuln
	certifyScorecard     []*model.CertifyScorecard
	certifyBad           []*model.CertifyBad
	isVulnerability      []*model.IsVulnerability
	certifyVEXStatement  []*model.CertifyVEXStatement
	id                   uint32
	index                indexType
	packages             pkgTypeMap
	sources              srcTypeMap
	osvs                 osvMap
	ghsas                ghsaMap
	cves                 cveMap
	hasSources           hasSrcList
	isDependencies       isDependencyList
	scorecards           scorecardList
	artifacts            artMap
	hashEquals           hashEqualList
	occurrences          isOccurrenceList
	vulnerabilities      vulnerabilityList
	equalVulnerabilities equalVulnerabilityList
	builders             builderMap
	hasSLSAs             hasSLSAList
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	client := &demoClient{
		hasSBOM:              []*model.HasSbom{},
		certifyPkg:           []*model.CertifyPkg{},
		certifyVuln:          []*model.CertifyVuln{},
		certifyScorecard:     []*model.CertifyScorecard{},
		certifyBad:           []*model.CertifyBad{},
		isVulnerability:      []*model.IsVulnerability{},
		certifyVEXStatement:  []*model.CertifyVEXStatement{},
		index:                indexType{},
		packages:             pkgTypeMap{},
		sources:              srcTypeMap{},
		osvs:                 osvMap{},
		ghsas:                ghsaMap{},
		cves:                 cveMap{},
		hasSources:           hasSrcList{},
		isDependencies:       isDependencyList{},
		scorecards:           scorecardList{},
		artifacts:            artMap{},
		hashEquals:           hashEqualList{},
		occurrences:          isOccurrenceList{},
		vulnerabilities:      vulnerabilityList{},
		equalVulnerabilities: equalVulnerabilityList{},
		builders:             builderMap{},
		hasSLSAs:             hasSLSAList{},
	}
	registerAllPackages(client)
	registerAllSources(client)
	registerAllCVE(client)
	registerAllGHSA(client)
	registerAllOSV(client)

	return client, nil
}

func GetEmptyBackend(args backends.BackendArgs) (backends.Backend, error) {
	client := &demoClient{
		hasSBOM:              []*model.HasSbom{},
		certifyPkg:           []*model.CertifyPkg{},
		certifyVuln:          []*model.CertifyVuln{},
		certifyScorecard:     []*model.CertifyScorecard{},
		certifyBad:           []*model.CertifyBad{},
		isVulnerability:      []*model.IsVulnerability{},
		certifyVEXStatement:  []*model.CertifyVEXStatement{},
		index:                indexType{},
		packages:             pkgTypeMap{},
		sources:              srcTypeMap{},
		osvs:                 osvMap{},
		ghsas:                ghsaMap{},
		cves:                 cveMap{},
		hasSources:           hasSrcList{},
		isDependencies:       isDependencyList{},
		scorecards:           scorecardList{},
		artifacts:            artMap{},
		hashEquals:           hashEqualList{},
		occurrences:          isOccurrenceList{},
		vulnerabilities:      vulnerabilityList{},
		equalVulnerabilities: equalVulnerabilityList{},
		builders:             builderMap{},
		hasSLSAs:             hasSLSAList{},
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

func toLower(filter *string) *string {
	if filter != nil {
		lower := strings.ToLower(*filter)
		return &lower
	}
	return nil
}
